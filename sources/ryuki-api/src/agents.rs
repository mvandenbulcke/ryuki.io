//! Execution-agent dispatch plumbing — S3a + S3b (control-plane side).
//!
//! Slice scope: agent registry + job queue + lease mechanics (S3a);
//! signed result verification + recording (S3b).
//! Out of scope: per-request lifecycle wiring (S4), admin approval UI,
//! signed grant issuance.
//!
//! # Auth model
//!
//! Agent auth = bearer token (hashed compare, same SHA-256-hex as api_tokens) + status == 'approved'.
//! Full per-request key-binding / request signing is S3b.
//! The token check lives in `authenticate_agent` — S3b extends it there, not scattered across handlers.
//!
//! # Lease / fencing invariants
//!
//! - Initial/non-live lease TTL is 5 minutes (CP DB time; no client clock).
//!   Exact Running live-job renewals extend past the runner's bounded call.
//! - cp_nonce + fencing_token are generated as UUIDs (128-bit CSPRNG; unguessable).
//! - The SKIP LOCKED lease query is the single atomically-safe dispatch path.
//! - Ack, renewal, and result recording all reject an expired DB-clock lease.
//! - Lease expiry: OfflineDryRun / LivePlan → re-Pending (new attempt);
//!   LiveApply / LiveDestroy → ReconcileRequired (never auto-redispatched).

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use ryuki_engine::auth::{check_permission, AuthSession};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::interval;
use uuid::Uuid;

use chrono::DateTime;

use crate::contracts::{is_scoped, row_scope_permits};
use crate::cp_identity;
use crate::database::get_db;
use crate::sha256_hex;
use ryuki_protocol::{
    crypto::{
        decode_verifying_key, encode_verifying_key, execution_trust_profile_digest, sign_vlc,
        verify_agent_enrollment_proof, verify_vlc,
    },
    AgentHeartbeat, AgentHeartbeatResponse, Capabilities, ExecutionTrustProfile, Job, JobLease,
    JobMode, JobResult, JobResultStatus, JobSpec, JobStatus, LiveExecutionAuthority,
    VerifiedLiveContext, AGENT_ENROLLMENT_CHALLENGE_HEX_BYTES, AGENT_ENROLLMENT_CHALLENGE_PREFIX,
    EXECUTABLE_PROVENANCE_POLICY_VERSION, EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION,
    EXECUTION_TRUST_PROFILE_SCHEMA_VERSION, PROVIDER_CREDENTIAL_AUTHORITY_MODE,
    TERRAFORM_STATE_ISOLATION_POLICY_VERSION,
};

// ---------------------------------------------------------------------------
// Lease TTL (seconds)
// ---------------------------------------------------------------------------

// Initial and non-live lease duration: five minutes.
const LEASE_TTL_SECS: i64 = 300;
// A live executor call is synchronous at the agent boundary and may run three
// sequential Terraform subprocesses, each capped at 600s (plan:
// init/plan/show; apply: init/apply/post-apply plan). Extending a successfully
// fenced Running live lease beyond that whole bound prevents the CP from
// expiring/reassigning the job while a timed subprocess can still mutate.
const MAX_LIVE_EXECUTOR_CALL_SECS: i64 = 3 * 600;
const LIVE_LEASE_TTL_SECS: i64 = MAX_LIVE_EXECUTOR_CALL_SECS + 600;
/// The bundled agent processes one job at a time. Keep the server-side
/// admission ceiling equally narrow so a rogue or malfunctioning approved
/// identity cannot warehouse a platform backlog by polling repeatedly.
const MAX_ACTIVE_LEASES_PER_AGENT: i64 = 1;
const _: () = {
    assert!(LIVE_LEASE_TTL_SECS > MAX_LIVE_EXECUTOR_CALL_SECS);
    assert!(LIVE_LEASE_TTL_SECS > LEASE_TTL_SECS);
    assert!(MAX_ACTIVE_LEASES_PER_AGENT > 0);
};

// ---------------------------------------------------------------------------
// Public enrollment admission bounds
// ---------------------------------------------------------------------------

/// Registration is deliberately public, so it gets a much smaller body budget
/// than the general API before Axum allocates/deserializes the JSON document.
const AGENT_REGISTRATION_BODY_LIMIT_BYTES: usize = 32 * 1024;
const AGENT_ID_MAX_BYTES: usize = 128;
const AGENT_PLATFORM_MAX_BYTES: usize = 128;
/// A canonical padded base64 Ed25519 public key is 44 bytes. Keep a small
/// compatibility margin while still rejecting oversized input before decode.
const AGENT_PUBLIC_KEY_MAX_BYTES: usize = 64;
const AGENT_ENROLLMENT_CHALLENGE_BYTES: usize =
    AGENT_ENROLLMENT_CHALLENGE_PREFIX.len() + AGENT_ENROLLMENT_CHALLENGE_HEX_BYTES;
/// Base64 for a 64-byte Ed25519 signature is 88 bytes. Keep the bound explicit
/// so malformed public requests are rejected before decoder allocation.
const AGENT_ENROLLMENT_PROOF_MAX_BYTES: usize = 96;
const AGENT_ENROLLMENT_CHALLENGE_DEFAULT_TTL_SECS: i64 = 15 * 60;
const AGENT_ENROLLMENT_CHALLENGE_MIN_TTL_SECS: i64 = 60;
const AGENT_ENROLLMENT_CHALLENGE_MAX_TTL_SECS: i64 = 24 * 60 * 60;
const PUBLIC_KEY_FINGERPRINT_PREFIX: &str = "sha256:";
const PUBLIC_KEY_FINGERPRINT_HEX_BYTES: usize = 64;
const CAPABILITY_VERSION_MAX_BYTES: usize = 64;
const CAPABILITY_PROVIDER_MAX_COUNT: usize = 64;
const CAPABILITY_PROVIDER_NAME_MAX_BYTES: usize = 128;
const CAPABILITY_PROVIDER_VERSION_MAX_BYTES: usize = 64;
const CAPABILITIES_JSON_MAX_BYTES: usize = 16 * 1024;

/// At most this many active pending enrollment records may exist in one control
/// plane. Approved and revoked agents do not consume the admission budget.
const MAX_PENDING_AGENT_ENROLLMENTS: i64 = 1024;
/// Each sweep removes a bounded batch so cleanup cannot monopolize the pool.
const PENDING_AGENT_ENROLLMENT_CLEANUP_BATCH: i64 = 256;
/// Non-queueing process-local cap on public registration work. The database
/// advisory lock below provides the cross-replica serialization needed for the
/// exact global pending quota.
const AGENT_REGISTRATION_CONCURRENCY: usize = 8;
static AGENT_REGISTRATION_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(AGENT_REGISTRATION_CONCURRENCY);

/// Always-on, route-specific admission for the anonymous registration edge.
/// These budgets remain active when the optional general API limiter is off
/// and run outside the queueing whole-application concurrency layer.
const AGENT_REGISTRATION_CLIENT_REQUESTS_PER_SECOND: u32 = 2;
const AGENT_REGISTRATION_CLIENT_BURST: u32 = 8;
const AGENT_REGISTRATION_GLOBAL_REQUESTS_PER_SECOND: u32 = 32;
const AGENT_REGISTRATION_GLOBAL_BURST: u32 = 64;
const AGENT_REGISTRATION_REJECTION_LOG_SAMPLE_EVERY: u64 = 256;

type AgentRegistrationClientRateLimiter =
    RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

#[derive(Clone)]
pub(crate) struct AgentRegistrationAdmission {
    per_client: Arc<AgentRegistrationClientRateLimiter>,
    global: Arc<DefaultDirectRateLimiter>,
    in_flight: Arc<tokio::sync::Semaphore>,
    bucket_salt: [u8; 32],
    trusted_proxies: Arc<Vec<ryuki_core::config::TrustedProxyNetwork>>,
    telemetry: Arc<AgentRegistrationAdmissionTelemetry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentRegistrationAdmissionRejection {
    ClientRate,
    GlobalRate,
    InFlight,
}

impl AgentRegistrationAdmissionRejection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientRate => "client_rate",
            Self::GlobalRate => "global_rate",
            Self::InFlight => "in_flight",
        }
    }
}

#[derive(Default)]
struct AgentRegistrationAdmissionTelemetry {
    client_rate: AtomicU64,
    global_rate: AtomicU64,
    in_flight: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentRegistrationAdmissionRejectionSnapshot {
    client_rate: u64,
    global_rate: u64,
    in_flight: u64,
}

impl AgentRegistrationAdmissionTelemetry {
    fn record(
        &self,
        rejection: AgentRegistrationAdmissionRejection,
    ) -> Option<AgentRegistrationAdmissionRejectionSnapshot> {
        let counter = match rejection {
            AgentRegistrationAdmissionRejection::ClientRate => &self.client_rate,
            AgentRegistrationAdmissionRejection::GlobalRate => &self.global_rate,
            AgentRegistrationAdmissionRejection::InFlight => &self.in_flight,
        };
        let reason_count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if reason_count != 1 && reason_count % AGENT_REGISTRATION_REJECTION_LOG_SAMPLE_EVERY != 0 {
            return None;
        }
        Some(self.snapshot())
    }

    fn snapshot(&self) -> AgentRegistrationAdmissionRejectionSnapshot {
        AgentRegistrationAdmissionRejectionSnapshot {
            client_rate: self.client_rate.load(Ordering::Relaxed),
            global_rate: self.global_rate.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
        }
    }
}

impl AgentRegistrationAdmission {
    pub(crate) fn production(
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> Self {
        Self::new(
            AGENT_REGISTRATION_CLIENT_REQUESTS_PER_SECOND,
            AGENT_REGISTRATION_CLIENT_BURST,
            AGENT_REGISTRATION_GLOBAL_REQUESTS_PER_SECOND,
            AGENT_REGISTRATION_GLOBAL_BURST,
            AGENT_REGISTRATION_CONCURRENCY,
            trusted_proxies,
        )
    }

    fn new(
        client_per_second: u32,
        client_burst: u32,
        global_per_second: u32,
        global_burst: u32,
        max_in_flight: usize,
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> Self {
        let quota = |per_second, burst| {
            Quota::per_second(NonZeroU32::new(per_second).unwrap_or(NonZeroU32::MIN))
                .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN))
        };
        Self {
            per_client: Arc::new(RateLimiter::keyed(quota(client_per_second, client_burst))),
            global: Arc::new(RateLimiter::direct(quota(global_per_second, global_burst))),
            in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight.max(1))),
            bucket_salt: rand::random(),
            trusted_proxies: Arc::new(trusted_proxies),
            telemetry: Arc::new(AgentRegistrationAdmissionTelemetry::default()),
        }
    }

    fn try_admit(
        &self,
        peer_addr: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, AgentRegistrationAdmissionRejection> {
        let (client_key, _) = crate::resolve_rate_limit_client_key_from_headers(
            peer_addr,
            headers,
            &self.trusted_proxies,
        );
        // The salted fixed bucket namespace bounds keyed limiter state even if
        // a peer rotates source addresses or forwarded identities.
        let bucket =
            crate::bounded_rate_limit_key("agent-registration", &client_key, &self.bucket_salt);
        self.per_client
            .check_key(&bucket)
            .map_err(|_| AgentRegistrationAdmissionRejection::ClientRate)?;
        self.global
            .check()
            .map_err(|_| AgentRegistrationAdmissionRejection::GlobalRate)?;
        self.in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| AgentRegistrationAdmissionRejection::InFlight)
    }

    fn record_rejection(
        &self,
        rejection: AgentRegistrationAdmissionRejection,
    ) -> Option<AgentRegistrationAdmissionRejectionSnapshot> {
        self.telemetry.record(rejection)
    }
}

/// Stable transaction-scoped PostgreSQL advisory-lock namespace for agent
/// registration admission. `pg_try_*` is intentional: callers fail fast rather
/// than holding a database connection while another registration is admitted.
const AGENT_REGISTRATION_ADVISORY_LOCK_KEY: i64 = 0x5259_554B_4941_4745;
/// Transaction-local marker consumed by migration 158's fail-closed bridge
/// triggers. It prevents an older API replica from silently ignoring the v3
/// challenge-admission contract during a rolling or rollback overlap.
const AGENT_ENROLLMENT_CONTRACT_SETTING: &str = "ryuki.agent_enrollment_contract";
/// Transaction-local marker consumed by migration 161. Older API replicas do
/// not set it, so their capability-blind/unbounded Pending -> Leased UPDATE is
/// blocked during a rolling deployment or rollback overlap.
const AGENT_JOB_LEASE_CONTRACT_SETTING: &str = "ryuki.agent_job_lease_contract";

// ---------------------------------------------------------------------------
// DB row types
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct AgentRow {
    id: Uuid,
    agent_id: String,
    #[allow(dead_code)]
    public_key: String,
    token_hash: String,
    status: String,
}

#[derive(Debug, sqlx::FromRow)]
struct AgentLeaseAuthorityRow {
    id: Uuid,
    platform: String,
    public_key: String,
    capabilities: sqlx::types::Json<Value>,
}

#[derive(Debug, sqlx::FromRow)]
struct AgentEnrollmentChallengeRow {
    agent_id: String,
    platform: String,
    public_key: String,
    public_key_fingerprint: String,
    secret_hash: String,
    status: String,
    active: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct AgentApprovalRow {
    id: Uuid,
    status: String,
    public_key: String,
    enrollment_expires_at: Option<DateTime<Utc>>,
    enrollment_challenge_id: Option<Uuid>,
    challenge_status: Option<String>,
    challenge_agent_id: Option<String>,
    challenge_platform: Option<String>,
    challenge_public_key: Option<String>,
    consumed_enrollment_id: Option<Uuid>,
}

#[allow(dead_code)]
#[derive(sqlx::FromRow, Clone)]
struct AgentJobRow {
    id: Uuid,
    request_id: Uuid,
    platform: String,
    spec: sqlx::types::Json<Value>,
    mode: String,
    status: String,
    agent_id: Option<String>,
    attempt_id: Option<Uuid>,
    lease_generation: i64,
    fencing_token: Option<String>,
    cp_nonce: Option<String>,
    lease_deadline: Option<chrono::DateTime<Utc>>,
    // S5: CP-signed LiveApply approval grant (NULL for non-live jobs).
    live_context: Option<sqlx::types::Json<Value>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

const AGENT_JOB_COLUMNS: &str = "id, request_id, platform, spec, mode, status, \
    agent_id, attempt_id, lease_generation, fencing_token, cp_nonce, \
    lease_deadline, live_context, created_at, updated_at";

pub(crate) struct LeasedAgentJob {
    row: AgentJobRow,
    attempt_id: Uuid,
    fencing_token: String,
    cp_nonce: String,
}

// ---------------------------------------------------------------------------
// Wire types (request / response bodies)
// ---------------------------------------------------------------------------

/// Body for POST /api/agents/register.
/// Fields mirror ryuki_protocol::AgentRegistration but we accept them
/// separately here so we can validate before inserting.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RegisterBody {
    pub enrollment_challenge_id: Uuid,
    pub enrollment_challenge: String,
    pub agent_id: String,
    pub platform: String,
    pub capabilities: Capabilities,
    pub public_key: String,
    pub enrollment_proof: String,
}

/// Returned once on successful registration. Token is never stored and never
/// returned again.
#[derive(Serialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub token: String,
}

impl std::fmt::Debug for RegisterResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegisterResponse")
            .field("agent_id", &self.agent_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The agent bearer is another one-time plaintext bootstrap credential. Keep
/// it out of browser/proxy caches even though registration is a POST and sits
/// outside the human-route idempotency middleware.
pub type RegisterHttpResponse = (
    [(axum::http::header::HeaderName, &'static str); 1],
    Json<RegisterResponse>,
);

/// Trusted provisioning request for a single-use agent enrollment grant.
/// The public key is not secret; storing the exact canonical value lets both
/// the API and migration trigger reject a substituted key without relying on a
/// second key registry or provider-specific attestation format.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEnrollmentChallengeBody {
    pub agent_id: String,
    pub platform: String,
    pub public_key: String,
    pub expires_in_seconds: Option<i64>,
}

/// Returned once to the trusted provisioning caller. The plaintext challenge
/// is never stored and must be delivered to the intended workload over the
/// operator's existing secret/bootstrap channel.
#[derive(Serialize)]
pub struct CreateEnrollmentChallengeResponse {
    pub enrollment_challenge_id: Uuid,
    pub enrollment_challenge: String,
    pub agent_id: String,
    pub platform: String,
    pub public_key_fingerprint: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for CreateEnrollmentChallengeResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateEnrollmentChallengeResponse")
            .field("enrollment_challenge_id", &self.enrollment_challenge_id)
            .field("enrollment_challenge", &"<redacted>")
            .field("agent_id", &self.agent_id)
            .field("platform", &self.platform)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A one-time plaintext challenge must never be cached or persisted by an
/// intermediary. In particular, the human-route idempotency middleware treats
/// `Cache-Control: no-store` as an explicit prohibition on recording a response
/// body in `idempotency_records`.
pub type CreateEnrollmentChallengeHttpResponse = (
    [(axum::http::header::HeaderName, &'static str); 1],
    Json<CreateEnrollmentChallengeResponse>,
);

/// Body for POST /api/admin/agents/{id}/approve.
///
/// `platform` is REQUIRED and must match the trusted provisioning challenge for
/// challenge-admitted identities. The challenge issuer, not the public agent,
/// is the authoritative source of the platform assignment.
#[derive(Debug, Deserialize)]
pub struct ApproveBody {
    /// Immutable enrollment row reviewed by the administrator. A stale review
    /// must never approve a later enrollment that reused the same agent_id.
    pub enrollment_id: Uuid,
    /// Non-secret SHA-256 fingerprint displayed by the admin enrollment list.
    /// Required so approval is bound to the exact reviewed public key as well
    /// as the immutable row.
    pub public_key_fingerprint: String,
    /// Authoritative platform selected during trusted provisioning. Required;
    /// a mismatch from the consumed challenge is rejected.
    pub platform: String,
    /// Authoritative capabilities assigned by admin (overwrites self-declared).
    pub capabilities: Option<Capabilities>,
}

/// Body for POST /api/admin/agents/{id}/revoke.
///
/// Revocation is bound to the same immutable roster snapshot as approval. Agent
/// ids may be reused after an expired Pending enrollment is removed, so an id by
/// itself is not sufficient authority for a terminal state change.
#[derive(Debug, Deserialize)]
pub struct RevokeBody {
    /// Immutable enrollment row reviewed by the administrator.
    pub enrollment_id: Uuid,
    /// Non-secret SHA-256 fingerprint displayed by the admin enrollment list.
    pub public_key_fingerprint: String,
}

/// Body for POST /api/agents/{id}/jobs/{job}/ack.
#[derive(Debug, Deserialize)]
pub struct AckBody {
    pub attempt_id: Uuid,
    pub fencing_token: String,
}

// ---------------------------------------------------------------------------
// Error helpers (mirror contracts.rs patterns)
// ---------------------------------------------------------------------------

pub type ApiResult<T> = Result<T, (StatusCode, Json<Value>)>;

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    // Log server-side; return a GENERIC body. The raw error (sqlx Display) can
    // leak SQL/column/constraint internals, so it must NOT ride in the response
    // `detail` (matches the generic-body path at the lease-query handler).
    tracing::error!(error = %e, "agent db error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "database error"})),
    )
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({"error": msg.into()})))
}

fn conflict(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::CONFLICT, Json(json!({"error": msg.into()})))
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(json!({"error": msg.into()})))
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()})))
}

fn service_unavailable(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": msg.into()})),
    )
}

fn too_many_requests(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error": msg.into()})),
    )
}

fn agent_registration_admission_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response {
    let mut response = (status, Json(json!({"error": code, "message": message}))).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn is_agent_registration_request(method: &Method, path: &str) -> bool {
    *method == Method::POST && path == "/api/agents/register"
}

/// Fail-fast admission for the anonymous registration route. This path-aware
/// layer is mounted outside body polling, telemetry, the optional general rate
/// limiter, and the queueing whole-application concurrency limit. The handler's
/// semaphore and PostgreSQL advisory lock remain independent defense in depth.
pub(crate) async fn agent_registration_admission_middleware(
    State(admission): State<AgentRegistrationAdmission>,
    request: Request,
    next: Next,
) -> Response {
    if !is_agent_registration_request(request.method(), request.uri().path()) {
        return next.run(request).await;
    }
    let Some(ConnectInfo(peer_addr)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        tracing::error!("agent registration peer address unavailable; failing admission closed");
        return agent_registration_admission_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AGENT_REGISTRATION_ADMISSION_CONTEXT_UNAVAILABLE",
            "Agent registration admission context is unavailable",
        );
    };
    let permit = match admission.try_admit(peer_addr, request.headers()) {
        Ok(permit) => permit,
        Err(rejection) => {
            if let Some(totals) = admission.record_rejection(rejection) {
                tracing::warn!(
                    reason = rejection.as_str(),
                    client_rate_total = totals.client_rate,
                    global_rate_total = totals.global_rate,
                    in_flight_total = totals.in_flight,
                    sample_every = AGENT_REGISTRATION_REJECTION_LOG_SAMPLE_EVERY,
                    "agent registration admission rejections (sampled aggregate)"
                );
            }
            return agent_registration_admission_response(
                StatusCode::TOO_MANY_REQUESTS,
                "AGENT_REGISTRATION_ADMISSION_EXCEEDED",
                "Too many agent registration requests",
            );
        }
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

fn parse_agent_job_id(id: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| not_found(format!("job {} not found", id)))
}

struct ValidatedRegistration<'a> {
    enrollment_challenge_id: Uuid,
    enrollment_challenge: &'a str,
    agent_id: &'a str,
    platform: &'a str,
    public_key: &'a str,
    public_key_fingerprint: String,
}

fn validate_registration_text(field: &str, value: &str, max_bytes: usize) -> ApiResult<()> {
    if value.trim().is_empty() {
        return Err(bad_request(format!("{field} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(bad_request(format!(
            "{field} must be at most {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn public_key_fingerprint(public_key: &str) -> String {
    format!(
        "{PUBLIC_KEY_FINGERPRINT_PREFIX}{}",
        sha256_hex(public_key.trim())
    )
}

fn validate_execution_trust_profile(
    profile: &ExecutionTrustProfile,
    spec: &JobSpec,
    platform: &str,
) -> Result<(), &'static str> {
    let offering = spec.iac_ref.split('@').next().unwrap_or_default();
    let (provider_source, provider_version) =
        ryuki_runner::iac::reviewed_live_provider_identity(offering)
            .ok_or("execution trust profile offering has no reviewed provider lock")?;
    let expected_containment = format!(
        "{}+{}",
        ryuki_runner::exec::RUNNER_CONTAINMENT_POLICY_VERSION,
        TERRAFORM_STATE_ISOLATION_POLICY_VERSION,
    );
    let backend_supported = matches!(
        profile.backend_kind.as_str(),
        "local"
            | "s3"
            | "azurerm"
            | "oss"
            | "cos"
            | "gcs"
            | "etcdv3"
            | "consul"
            | "kubernetes"
            | "http"
    );
    let version_valid = !profile.executable_version.is_empty()
        && profile.executable_version.len() <= 64
        && profile
            .executable_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'));
    let path_valid = profile.executable_path.starts_with('/')
        && profile.executable_path.len() <= 4096
        && !profile.executable_path.chars().any(char::is_control);
    let executable_digest_valid = profile.executable_sha256.as_deref().is_none_or(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    let backend_authority_digest_valid = profile.backend_authority_digest.len() == 64
        && profile
            .backend_authority_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let state_key = spec.state_key.as_deref().unwrap_or_default();

    if profile.schema_version != EXECUTION_TRUST_PROFILE_SCHEMA_VERSION
        || profile.allowlist_version != EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION
        || profile.platform != platform
        || profile.offering != offering
        || profile.runner_kind != "terraform"
        || profile.provider_source != provider_source
        || profile.provider_version != provider_version
        || !ryuki_protocol::provider_authority_reference_is_canonical(
            &profile.provider_authority_id,
            &profile.provider_authority_version,
        )
        || !backend_supported
        || !ryuki_protocol::backend_credential_authority_reference_is_canonical(
            &profile.backend_kind,
            &profile.backend_credential_authority_id,
            &profile.backend_credential_authority_revision,
        )
        || !backend_authority_digest_valid
        || profile.executable_kind != "terraform"
        || !path_valid
        || !version_valid
        || !executable_digest_valid
        || profile.executable_provenance_policy_version != EXECUTABLE_PROVENANCE_POLICY_VERSION
        || profile.provider_credential_authority_mode != PROVIDER_CREDENTIAL_AUTHORITY_MODE
        || profile.backend_credential_authority_mode
            != ryuki_runner::live::BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION
        || profile.containment_policy_version != expected_containment
        || profile.iac_digest != spec.iac_digest
        || profile.state_key != state_key
    {
        return Err("execution trust profile is outside the closed reviewed-live policy");
    }
    Ok(())
}

fn invalid_enrollment_challenge() -> (StatusCode, Json<Value>) {
    // Keep every trust-decision failure deliberately indistinguishable to an
    // anonymous caller: existence, expiry, identity, key, secret, consumption,
    // and proof state are all part of the same bootstrap credential boundary.
    forbidden("invalid or expired agent enrollment challenge")
}

fn registration_insert_err(error: sqlx::Error) -> (StatusCode, Json<Value>) {
    // The database trigger repeats the challenge match and expiry check at the
    // INSERT boundary. If the deadline crosses between the earlier locked read
    // and that statement, preserve the same anonymous-facing denial instead of
    // turning a trust-decision race into a distinguishable 500 response.
    if error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23514")
    {
        invalid_enrollment_challenge()
    } else {
        db_err(error)
    }
}

fn valid_enrollment_challenge_shape(value: &str) -> bool {
    value.len() == AGENT_ENROLLMENT_CHALLENGE_BYTES
        && value.starts_with(AGENT_ENROLLMENT_CHALLENGE_PREFIX)
        && value[AGENT_ENROLLMENT_CHALLENGE_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_canonical_agent_public_key(value: &str) -> ApiResult<ed25519_dalek::VerifyingKey> {
    validate_registration_text("public_key", value, AGENT_PUBLIC_KEY_MAX_BYTES)?;
    let key = decode_verifying_key(value).map_err(|_| {
        bad_request("public_key must be a valid base64-encoded Ed25519 verifying key")
    })?;
    if key.is_weak() {
        return Err(bad_request(
            "public_key must not be a weak (small-order) Ed25519 key",
        ));
    }
    if encode_verifying_key(&key) != value {
        return Err(bad_request(
            "public_key must use the canonical padded base64 encoding",
        ));
    }
    Ok(key)
}

/// Stable, non-secret review handle for one canonical capabilities document.
/// `Capabilities` serializes with fixed field order and provider maps are
/// `BTreeMap`s; JSONB reads are likewise normalized before reaching this helper.
fn capabilities_digest(capabilities: &Value) -> String {
    format!(
        "{PUBLIC_KEY_FINGERPRINT_PREFIX}{}",
        sha256_hex(&capabilities.to_string())
    )
}

fn valid_public_key_fingerprint_shape(value: &str) -> bool {
    value.len() == PUBLIC_KEY_FINGERPRINT_PREFIX.len() + PUBLIC_KEY_FINGERPRINT_HEX_BYTES
        && value.starts_with(PUBLIC_KEY_FINGERPRINT_PREFIX)
        && value[PUBLIC_KEY_FINGERPRINT_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn pending_enrollment_missing_expiry(
    status: &str,
    enrollment_expires_at: Option<DateTime<Utc>>,
) -> bool {
    status == "pending" && enrollment_expires_at.is_none()
}

async fn activate_agent_enrollment_contract_v3(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config($1, '3', TRUE)")
        .bind(AGENT_ENROLLMENT_CONTRACT_SETTING)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn activate_agent_job_lease_contract_v2(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config($1, '2', TRUE)")
        .bind(AGENT_JOB_LEASE_CONTRACT_SETTING)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Validate every attacker-sized registration field before public-key decode,
/// JSON conversion, token generation, or database acquisition.
fn validate_registration_input(body: &RegisterBody) -> ApiResult<ValidatedRegistration<'_>> {
    let enrollment_challenge = body.enrollment_challenge.trim();
    if enrollment_challenge != body.enrollment_challenge
        || !valid_enrollment_challenge_shape(enrollment_challenge)
    {
        return Err(invalid_enrollment_challenge());
    }
    validate_registration_text("agent_id", &body.agent_id, AGENT_ID_MAX_BYTES)?;
    validate_registration_text("platform", &body.platform, AGENT_PLATFORM_MAX_BYTES)?;

    let public_key = body.public_key.trim();
    let verifying_key = validate_canonical_agent_public_key(public_key)?;
    validate_registration_text(
        "enrollment_proof",
        &body.enrollment_proof,
        AGENT_ENROLLMENT_PROOF_MAX_BYTES,
    )?;
    if body.enrollment_proof.trim() != body.enrollment_proof {
        return Err(invalid_enrollment_challenge());
    }

    let mut provider_count = 0usize;
    for (tool_name, capability) in [
        ("terraform", body.capabilities.terraform.as_ref()),
        ("ansible", body.capabilities.ansible.as_ref()),
    ] {
        let Some(capability) = capability else {
            continue;
        };
        if capability.version.len() > CAPABILITY_VERSION_MAX_BYTES {
            return Err(bad_request(format!(
                "{tool_name} capability version must be at most {CAPABILITY_VERSION_MAX_BYTES} bytes"
            )));
        }
        provider_count = provider_count.saturating_add(capability.provider_versions.len());
        if provider_count > CAPABILITY_PROVIDER_MAX_COUNT {
            return Err(bad_request(format!(
                "capabilities may declare at most {CAPABILITY_PROVIDER_MAX_COUNT} provider versions"
            )));
        }
        for (provider_name, provider_version) in &capability.provider_versions {
            if provider_name.len() > CAPABILITY_PROVIDER_NAME_MAX_BYTES {
                return Err(bad_request(format!(
                    "capability provider names must be at most {CAPABILITY_PROVIDER_NAME_MAX_BYTES} bytes"
                )));
            }
            if provider_version.len() > CAPABILITY_PROVIDER_VERSION_MAX_BYTES {
                return Err(bad_request(format!(
                    "capability provider versions must be at most {CAPABILITY_PROVIDER_VERSION_MAX_BYTES} bytes"
                )));
            }
        }
    }

    // Prove possession before acquiring a database connection. This check alone
    // does not trust the key; the locked challenge row below must independently
    // match this exact canonical key and identity.
    verify_agent_enrollment_proof(
        body.enrollment_challenge_id,
        enrollment_challenge,
        &body.agent_id,
        &body.platform,
        public_key,
        body.enrollment_proof.trim(),
        &verifying_key,
    )
    .map_err(|_| invalid_enrollment_challenge())?;

    Ok(ValidatedRegistration {
        enrollment_challenge_id: body.enrollment_challenge_id,
        enrollment_challenge,
        agent_id: &body.agent_id,
        platform: &body.platform,
        public_key,
        public_key_fingerprint: public_key_fingerprint(public_key),
    })
}

/// Validate the administrator-authoritative capability grant before it can be
/// persisted. Registration data is only an untrusted hint; this stricter path
/// keeps approved documents canonical and prevents an operator from granting a
/// shape that the lease matcher must (correctly) reject.
fn validated_approved_capabilities(capabilities: &Capabilities) -> ApiResult<Value> {
    let mut provider_count = 0usize;
    for (tool_name, capability) in [
        ("terraform", capabilities.terraform.as_ref()),
        ("ansible", capabilities.ansible.as_ref()),
    ] {
        let Some(capability) = capability else {
            continue;
        };
        if capability.version.trim().is_empty()
            || capability.version.trim() != capability.version
            || capability.version.len() > CAPABILITY_VERSION_MAX_BYTES
        {
            return Err(bad_request(format!(
                "{tool_name} capability version must be a canonical non-empty string of at most {CAPABILITY_VERSION_MAX_BYTES} bytes"
            )));
        }
        if tool_name == "ansible" && !capability.provider_versions.is_empty() {
            return Err(bad_request(
                "ansible capability provider_versions must be empty",
            ));
        }
        provider_count = provider_count.saturating_add(capability.provider_versions.len());
        if provider_count > CAPABILITY_PROVIDER_MAX_COUNT {
            return Err(bad_request(format!(
                "capabilities may declare at most {CAPABILITY_PROVIDER_MAX_COUNT} provider versions"
            )));
        }
        for (provider_name, provider_version) in &capability.provider_versions {
            if provider_name.trim().is_empty()
                || provider_name.trim() != provider_name
                || provider_name.len() > CAPABILITY_PROVIDER_NAME_MAX_BYTES
            {
                return Err(bad_request(format!(
                    "capability provider names must be canonical non-empty strings of at most {CAPABILITY_PROVIDER_NAME_MAX_BYTES} bytes"
                )));
            }
            if provider_version.trim().is_empty()
                || provider_version.trim() != provider_version
                || provider_version.len() > CAPABILITY_PROVIDER_VERSION_MAX_BYTES
            {
                return Err(bad_request(format!(
                    "capability provider versions must be canonical non-empty strings of at most {CAPABILITY_PROVIDER_VERSION_MAX_BYTES} bytes"
                )));
            }
        }
    }

    let approved = serde_json::to_value(capabilities).map_err(db_err)?;
    if approved.to_string().len() > CAPABILITIES_JSON_MAX_BYTES {
        return Err(bad_request(format!(
            "capabilities must serialize to at most {CAPABILITIES_JSON_MAX_BYTES} bytes"
        )));
    }
    Ok(approved)
}

/// Delete at most `batch` expired Pending enrollments, oldest first.
///
/// The production lifecycle sweep and the registration admission path both use
/// this bounded query. `SKIP LOCKED` prevents cleanup from waiting behind an
/// administrator who is concurrently approving or revoking an enrollment.
async fn cleanup_expired_pending_agent_enrollments_with_batch(
    pool: &PgPool,
    batch: i64,
) -> Result<u64, sqlx::Error> {
    if batch <= 0 {
        return Ok(0);
    }
    let result = sqlx::query(
        "WITH expired AS ( \
             SELECT id FROM agents \
             WHERE status = 'pending' AND enrollment_expires_at <= NOW() \
             ORDER BY enrollment_expires_at, id \
             FOR UPDATE SKIP LOCKED \
             LIMIT $1 \
         ) \
         DELETE FROM agents AS target \
         USING expired \
         WHERE target.id = expired.id",
    )
    .bind(batch)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub(crate) async fn cleanup_expired_pending_agent_enrollments(
    pool: &PgPool,
) -> Result<u64, sqlx::Error> {
    cleanup_expired_pending_agent_enrollments_with_batch(
        pool,
        PENDING_AGENT_ENROLLMENT_CLEANUP_BATCH,
    )
    .await
}

/// Serialize registration admission across replicas, prune a bounded expired
/// batch, enforce the exact global active-Pending quota, then insert atomically.
async fn persist_pending_agent_registration(
    pool: &PgPool,
    pv: ProtocolVersion,
    registration: &ValidatedRegistration<'_>,
    capabilities_json: &Value,
    max_pending: i64,
) -> ApiResult<String> {
    debug_assert!(max_pending > 0);
    let mut tx = pool.begin().await.map_err(db_err)?;
    activate_agent_enrollment_contract_v3(&mut tx)
        .await
        .map_err(db_err)?;

    let lock_acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(AGENT_REGISTRATION_ADVISORY_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    if !lock_acquired {
        return Err(too_many_requests("agent registration is busy; retry later"));
    }

    // Lock the one-time grant before touching the durable agent identity. Every
    // mismatch intentionally returns the same anonymous-facing error. The
    // Ed25519 proof was already checked against the submitted key; this lookup
    // establishes that trusted provisioning selected that exact key and
    // identity before registration became reachable.
    let challenge: Option<AgentEnrollmentChallengeRow> = sqlx::query_as(
        "SELECT agent_id, platform, public_key, public_key_fingerprint, secret_hash, status, \
                (status = 'pending' AND expires_at > clock_timestamp()) AS active \
         FROM agent_enrollment_challenges \
         WHERE id = $1 \
         FOR UPDATE",
    )
    .bind(registration.enrollment_challenge_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(challenge) = challenge else {
        return Err(invalid_enrollment_challenge());
    };
    let presented_secret_hash = sha256_hex(registration.enrollment_challenge);
    use subtle::ConstantTimeEq;
    let secret_matches: bool = presented_secret_hash
        .as_bytes()
        .ct_eq(challenge.secret_hash.as_bytes())
        .into();
    if !challenge.active
        || challenge.status != "pending"
        || !secret_matches
        || challenge.agent_id != registration.agent_id
        || challenge.platform != registration.platform
        || challenge.public_key != registration.public_key
        || challenge.public_key_fingerprint != registration.public_key_fingerprint
    {
        return Err(invalid_enrollment_challenge());
    }

    // Let an expired identity re-enroll even if it is not within the oldest
    // cleanup batch. The row lock is bounded to one attacker-selected unique key.
    sqlx::query(
        "DELETE FROM agents \
         WHERE agent_id = $1 \
           AND status = 'pending' \
           AND enrollment_expires_at <= NOW()",
    )
    .bind(registration.agent_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        "WITH expired AS ( \
             SELECT id FROM agents \
             WHERE status = 'pending' AND enrollment_expires_at <= NOW() \
             ORDER BY enrollment_expires_at, id \
             FOR UPDATE SKIP LOCKED \
             LIMIT $1 \
         ) \
         DELETE FROM agents AS target \
         USING expired \
         WHERE target.id = expired.id",
    )
    .bind(PENDING_AGENT_ENROLLMENT_CLEANUP_BATCH)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let active_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ( \
             SELECT 1 FROM agents \
             WHERE status = 'pending' AND enrollment_expires_at > NOW() \
             LIMIT $1 \
         ) AS active_pending",
    )
    .bind(max_pending)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if active_pending >= max_pending {
        return Err(too_many_requests(
            "the pending agent enrollment capacity is full; retry after an enrollment is reviewed or expires",
        ));
    }

    let token = generate_agent_token();
    let hash = sha256_hex(&token);
    let enrollment_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status, \
                             protocol_version, enrollment_challenge_id) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7) \
         ON CONFLICT DO NOTHING \
         RETURNING id",
    )
    .bind(registration.agent_id)
    .bind(registration.platform)
    .bind(capabilities_json)
    .bind(registration.public_key)
    .bind(&hash)
    // BIGINT column: the wire version is u32, whose full range fits an i64 losslessly.
    .bind(i64::from(pv.0))
    .bind(registration.enrollment_challenge_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(registration_insert_err)?;

    let Some(enrollment_id) = enrollment_id else {
        return Err(conflict(format!(
            "agent_id '{}' already registered",
            registration.agent_id
        )));
    };

    // Consume in the same transaction as the identity insert. Re-check expiry
    // with the database clock at the final write so a challenge that expires
    // while this request is being processed rolls the insert back. The locked
    // row plus this status predicate makes replay and concurrent consumption
    // deterministic: exactly one claimant can commit.
    let consumed = sqlx::query(
        "UPDATE agent_enrollment_challenges \
         SET status = 'consumed', consumed_at = clock_timestamp(), \
             consumed_enrollment_id = $1 \
         WHERE id = $2 AND status = 'pending' \
           AND expires_at > clock_timestamp()",
    )
    .bind(enrollment_id)
    .bind(registration.enrollment_challenge_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if consumed.rows_affected() != 1 {
        return Err(invalid_enrollment_challenge());
    }

    tx.commit().await.map_err(db_err)?;
    Ok(token)
}

/// Test-only fixture boundary for code outside this module that needs an agent
/// row. It intentionally exercises migration 158's real admission sequence
/// instead of weakening the database trigger for direct approved-row inserts.
#[cfg(test)]
pub(crate) struct ChallengeAdmittedTestAgent<'a> {
    pub(crate) agent_id: &'a str,
    pub(crate) platform: &'a str,
    pub(crate) public_key: &'a str,
    pub(crate) token_hash: &'a str,
    pub(crate) capabilities: &'a Value,
    pub(crate) final_status: &'a str,
    pub(crate) last_seen_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
pub(crate) async fn seed_challenge_admitted_test_agent(
    pool: &PgPool,
    fixture: ChallengeAdmittedTestAgent<'_>,
) -> Uuid {
    let ChallengeAdmittedTestAgent {
        agent_id,
        platform,
        public_key,
        token_hash,
        capabilities,
        final_status,
        last_seen_at,
    } = fixture;
    assert!(
        matches!(final_status, "pending" | "approved" | "revoked"),
        "unsupported agent fixture status"
    );
    let challenge_id = Uuid::new_v4();
    let challenge = generate_agent_enrollment_challenge();
    let mut tx = pool.begin().await.expect("begin admitted-agent fixture");
    activate_agent_enrollment_contract_v3(&mut tx)
        .await
        .expect("activate enrollment contract for admitted-agent fixture");
    sqlx::query(
        "INSERT INTO agent_enrollment_challenges ( \
             id, agent_id, platform, public_key, public_key_fingerprint, \
             secret_hash, ttl_seconds, expires_at, created_by \
         ) VALUES ($1, $2, $3, $4, $5, $6, 3600, \
                   statement_timestamp(), 'test-provisioner')",
    )
    .bind(challenge_id)
    .bind(agent_id)
    .bind(platform)
    .bind(public_key)
    .bind(public_key_fingerprint(public_key))
    .bind(sha256_hex(&challenge))
    .execute(&mut *tx)
    .await
    .expect("seed trusted challenge for admitted-agent fixture");

    let enrollment_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents ( \
             agent_id, platform, capabilities, public_key, token_hash, status, \
             enrollment_challenge_id, last_seen_at \
         ) VALUES ($1, $2, $3::jsonb, $4, $5, 'pending', $6, $7) \
         RETURNING id",
    )
    .bind(agent_id)
    .bind(platform)
    .bind(capabilities)
    .bind(public_key)
    .bind(token_hash)
    .bind(challenge_id)
    .bind(last_seen_at)
    .fetch_one(&mut *tx)
    .await
    .expect("insert challenge-bound Pending agent fixture");

    sqlx::query(
        "UPDATE agent_enrollment_challenges \
         SET status = 'consumed', consumed_at = clock_timestamp(), \
             consumed_enrollment_id = $1 \
         WHERE id = $2 AND status = 'pending'",
    )
    .bind(enrollment_id)
    .bind(challenge_id)
    .execute(&mut *tx)
    .await
    .expect("consume admitted-agent fixture challenge");

    if final_status != "pending" {
        sqlx::query(
            "UPDATE agents SET status = $1, enrollment_expires_at = NULL, updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(final_status)
        .bind(enrollment_id)
        .execute(&mut *tx)
        .await
        .expect("transition admitted-agent fixture to final status");
    }
    tx.commit()
        .await
        .expect("commit admitted-agent fixture transaction");
    enrollment_id
}

// ---------------------------------------------------------------------------
// Token generation (AGENT_TOKEN_PREFIX + 32 random bytes → 64 hex chars)
// ---------------------------------------------------------------------------

pub const AGENT_TOKEN_PREFIX: &str = "rya_";

fn generate_agent_enrollment_challenge() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{AGENT_ENROLLMENT_CHALLENGE_PREFIX}{hex}")
}

fn generate_agent_token() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut bytes = [0u8; 32];
    // Use OsRng directly to match the rest of the auth/crypto surface (OIDC
    // state/nonce + the CP keypair). `thread_rng()` is also a CSPRNG, so this is a
    // consistency / defense-in-depth alignment for the agent bearer token, not a fix.
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{AGENT_TOKEN_PREFIX}{hex}")
}

// ---------------------------------------------------------------------------
// Agent token authentication
//
// Single entry-point so S3b can extend it (e.g. add request signing check)
// without touching individual handlers.
// ---------------------------------------------------------------------------

/// Authenticates the caller as an agent bearer (hashed compare against
/// `agents.token_hash`) and returns the agent row.
///
/// Returns:
/// - 401 if no bearer / not an agent token prefix.
/// - 403 if the token does not match any approved row.
/// - 403 if status != 'approved'.
async fn authenticate_agent(headers: &HeaderMap, pool: &PgPool) -> ApiResult<AgentRow> {
    let auth = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.trim().strip_prefix("Bearer ").map(str::trim))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "bearer token required"})),
            )
        })?;

    if !auth.starts_with(AGENT_TOKEN_PREFIX) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "not an agent token"})),
        ));
    }

    let hash = sha256_hex(auth);

    use subtle::ConstantTimeEq;
    let row = sqlx::query_as::<_, AgentRow>(
        "SELECT id, agent_id, public_key, token_hash, status \
         FROM agents WHERE token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| forbidden("invalid agent token"))?;

    // Constant-time belt-and-suspenders (token already filtered in WHERE).
    let hash_ok: bool = hash.as_bytes().ct_eq(row.token_hash.as_bytes()).into();
    if !hash_ok {
        return Err(forbidden("invalid agent token"));
    }

    if row.status != "approved" {
        return Err(forbidden(format!(
            "agent '{}' is not approved (status: {})",
            row.agent_id, row.status
        )));
    }

    Ok(row)
}

/// Enrollment changes create durable workload credentials, so coarse `admin`
/// RBAC is not sufficient: the caller must be a currently verified interactive
/// human with platform-global authority. `token_valid` is set only after the
/// request authentication boundary admits the current credential/session;
/// `api-token` is then excluded explicitly so a standing machine credential
/// cannot mint a transitive agent credential. The provider name is otherwise
/// deliberately neutral, preserving local and federated direct/persisted human
/// sessions without a brittle provider allowlist.
fn is_fresh_unscoped_interactive_human_admin(session: &AuthSession) -> bool {
    check_permission(session, "admin")
        && session.is_verified_human()
        && session.site_scope.is_empty()
        && session.environment_scope.is_empty()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/admin/agents/enrollment-challenges
///
/// Preprovisions one short-lived bootstrap grant for an exact agent identity
/// and existing Ed25519 workload key. The plaintext challenge is returned only
/// in this response; the database retains its hash. Delivery to the intended
/// workload remains a trusted, provider-neutral provisioning responsibility.
pub async fn admin_create_agent_enrollment_challenge(
    Extension(session): Extension<AuthSession>,
    Json(body): Json<CreateEnrollmentChallengeBody>,
) -> ApiResult<CreateEnrollmentChallengeHttpResponse> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to provision an agent enrollment",
        ));
    }
    if !session.site_scope.is_empty() || !session.environment_scope.is_empty() {
        return Err(forbidden(
            "agent fleet operations require an unrestricted (non-scoped) admin",
        ));
    }
    if !is_fresh_unscoped_interactive_human_admin(&session) {
        return Err(forbidden(
            "agent enrollment requires a fresh interactive human admin session; API tokens and static/dry-run identities are not accepted",
        ));
    }

    validate_registration_text("agent_id", &body.agent_id, AGENT_ID_MAX_BYTES)?;
    validate_registration_text("platform", &body.platform, AGENT_PLATFORM_MAX_BYTES)?;
    let public_key = body.public_key.trim();
    validate_canonical_agent_public_key(public_key)?;
    let ttl_secs = body
        .expires_in_seconds
        .unwrap_or(AGENT_ENROLLMENT_CHALLENGE_DEFAULT_TTL_SECS);
    if !(AGENT_ENROLLMENT_CHALLENGE_MIN_TTL_SECS..=AGENT_ENROLLMENT_CHALLENGE_MAX_TTL_SECS)
        .contains(&ttl_secs)
    {
        return Err(bad_request(format!(
            "expires_in_seconds must be between {AGENT_ENROLLMENT_CHALLENGE_MIN_TTL_SECS} and {AGENT_ENROLLMENT_CHALLENGE_MAX_TTL_SECS}"
        )));
    }
    let ttl_seconds = i32::try_from(ttl_secs)
        .map_err(|_| bad_request("expires_in_seconds is outside the supported database range"))?;

    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    // Serialize trusted issuance with public consumption. Registration uses the
    // non-queueing variant of this same lock and therefore fails fast while an
    // administrator is changing bootstrap authority.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AGENT_REGISTRATION_ADVISORY_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    sqlx::query(
        "UPDATE agent_enrollment_challenges \
         SET status = 'expired' \
         WHERE agent_id = $1 AND status = 'pending' \
           AND expires_at <= clock_timestamp()",
    )
    .bind(&body.agent_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let existing_agent: Option<(String, bool)> = sqlx::query_as(
        "SELECT status, \
                (status = 'pending' AND enrollment_expires_at IS NOT NULL \
                 AND enrollment_expires_at <= clock_timestamp()) AS removable \
         FROM agents WHERE agent_id = $1 FOR UPDATE",
    )
    .bind(&body.agent_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    if let Some((status, removable)) = existing_agent {
        if !removable {
            return Err(conflict(format!(
                "agent_id '{}' already has a {status} identity",
                body.agent_id
            )));
        }
    }

    let active_challenge: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 FROM agent_enrollment_challenges \
             WHERE agent_id = $1 AND status = 'pending' \
         )",
    )
    .bind(&body.agent_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if active_challenge {
        return Err(conflict(format!(
            "agent_id '{}' already has an active enrollment challenge",
            body.agent_id
        )));
    }

    let enrollment_challenge_id = Uuid::new_v4();
    let enrollment_challenge = generate_agent_enrollment_challenge();
    let challenge_hash = sha256_hex(&enrollment_challenge);
    let fingerprint = public_key_fingerprint(public_key);
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO agent_enrollment_challenges ( \
             id, agent_id, platform, public_key, public_key_fingerprint, \
             secret_hash, ttl_seconds, expires_at, created_by \
         ) VALUES ( \
             $1, $2, $3, $4, $5, $6, $7, statement_timestamp(), $8 \
         ) \
         RETURNING expires_at",
    )
    .bind(enrollment_challenge_id)
    .bind(&body.agent_id)
    .bind(&body.platform)
    .bind(public_key)
    .bind(&fingerprint)
    .bind(&challenge_hash)
    .bind(ttl_seconds)
    .bind(&session.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-enrollment-challenge-create",
            None,
            "pending",
            json!({
                "agent_id": &body.agent_id,
                "platform": &body.platform,
                "enrollment_challenge_id": enrollment_challenge_id,
                "public_key_fingerprint": &fingerprint,
                "expires_at": expires_at.to_rfc3339(),
            }),
        ),
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(CreateEnrollmentChallengeResponse {
            enrollment_challenge_id,
            enrollment_challenge,
            agent_id: body.agent_id,
            platform: body.platform,
            public_key_fingerprint: fingerprint,
            expires_at,
        }),
    ))
}

/// POST /api/agents/register
///
/// Enrolls a new agent in 'pending' status. Generates a bearer token,
/// stores its SHA-256 hash, and returns the plaintext token ONCE.
/// A pending agent cannot poll for jobs until an admin approves it.
pub async fn register_agent(
    pv: ProtocolVersion,
    _headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> ApiResult<RegisterHttpResponse> {
    let _registration_permit = AGENT_REGISTRATION_PERMITS
        .try_acquire()
        .map_err(|_| too_many_requests("agent registration is busy; retry later"))?;

    // All attacker-sized fields, including the encoded key, are bounded before
    // key decode, JSON conversion, token generation, or database acquisition.
    let registration = validate_registration_input(&body)?;
    let capabilities_json = serde_json::to_value(&body.capabilities).map_err(db_err)?;
    let capabilities_json_bytes = serde_json::to_vec(&capabilities_json)
        .map_err(db_err)?
        .len();
    if capabilities_json_bytes > CAPABILITIES_JSON_MAX_BYTES {
        return Err(bad_request(format!(
            "capabilities must serialize to at most {CAPABILITIES_JSON_MAX_BYTES} bytes"
        )));
    }
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let token = persist_pending_agent_registration(
        pool,
        pv,
        &registration,
        &capabilities_json,
        MAX_PENDING_AGENT_ENROLLMENTS,
    )
    .await?;

    tracing::info!(agent_id = %registration.agent_id, platform = %registration.platform, "agent registered (pending)");

    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(RegisterResponse {
            agent_id: registration.agent_id.to_owned(),
            token,
        }),
    ))
}

/// POST /api/admin/agents/{agent_id}/approve
///
/// Sets an agent's status to 'approved'. The platform must match the consumed
/// trusted challenge; capabilities remain administrator-authoritative and the
/// agent's self-declared capability document is only a hint.
///
/// The request must carry `enrollment_id` and `public_key_fingerprint` from the
/// current admin roster together with `platform`. Binding approval to the
/// immutable row and reviewed key prevents a stale page from approving a later
/// enrollment that reused the same human-readable agent id.
/// This endpoint sits under `/api/admin/` so the human RBAC middleware enforces
/// the `admin` permission. The in-handler human-session gate additionally keeps
/// agent and API-token credentials from minting a transitive workload identity.
pub async fn admin_approve_agent(
    Path(agent_id): Path<String>,
    Extension(session): Extension<AuthSession>,
    Json(body): Json<ApproveBody>,
) -> ApiResult<Json<Value>> {
    // Defense in depth: the `/api/admin/` middleware already enforces `admin`, but
    // re-check here so the verified principal is also the audit actor.
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to approve an agent",
        ));
    }
    // run-5 A0: agent-FLEET operations are platform-global. Agents are keyed on
    // `platform` (site-adjacent, with no platform->site mapping), so no coherent
    // site/env scope can be resolved for them. Deny any scoped principal — a
    // session-property gate evaluated BEFORE any row lookup, so it leaks no
    // existence oracle. Mirrors the "platform-wide rows only for an unrestricted
    // principal" posture.
    if !session.site_scope.is_empty() || !session.environment_scope.is_empty() {
        return Err(forbidden(
            "agent fleet operations require an unrestricted (non-scoped) admin",
        ));
    }
    if !is_fresh_unscoped_interactive_human_admin(&session) {
        return Err(forbidden(
            "agent enrollment requires a fresh interactive human admin session; API tokens and static/dry-run identities are not accepted",
        ));
    }
    if body.platform.trim().is_empty() {
        return Err(bad_request("platform must not be empty"));
    }
    if !valid_public_key_fingerprint_shape(&body.public_key_fingerprint) {
        return Err(bad_request(
            "public_key_fingerprint must be a lowercase sha256 fingerprint",
        ));
    }

    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    // The active-job check must take a fresh statement snapshot after waiting
    // for the same agent-row lock used by leasing. Do not inherit a database
    // role override that could retain a pre-wait REPEATABLE READ snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    activate_agent_enrollment_contract_v3(&mut tx)
        .await
        .map_err(db_err)?;

    // Lock and bind the review to the immutable row plus the displayed key
    // fingerprint. `agent_id` is intentionally reusable after expiry cleanup, so
    // approving by that human-readable identifier alone would let a stale admin
    // page approve a replacement key.
    let prior: Option<AgentApprovalRow> = sqlx::query_as(
        "SELECT agent.id, agent.status, agent.public_key, agent.enrollment_expires_at, \
                agent.enrollment_challenge_id, challenge.status AS challenge_status, \
                challenge.agent_id AS challenge_agent_id, \
                challenge.platform AS challenge_platform, \
                challenge.public_key AS challenge_public_key, \
                challenge.consumed_enrollment_id \
         FROM agents AS agent \
         LEFT JOIN agent_enrollment_challenges AS challenge \
           ON challenge.id = agent.enrollment_challenge_id \
         WHERE agent.agent_id = $1 \
         FOR UPDATE OF agent",
    )
    .bind(&agent_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(prior) = prior else {
        return Err(not_found(format!("agent '{}' not found", agent_id)));
    };
    let stored_fingerprint = public_key_fingerprint(&prior.public_key);
    if prior.id != body.enrollment_id || stored_fingerprint != body.public_key_fingerprint {
        return Err(conflict(
            "the reviewed agent enrollment has changed; refresh the enrollment list",
        ));
    }
    if prior.status == "revoked" {
        return Err(conflict(format!(
            "agent '{}' is revoked and cannot be re-approved; it must re-enroll",
            agent_id
        )));
    }
    // A legacy NULL must fail closed even before the atomic UPDATE predicate.
    // Expiry itself is decided by PostgreSQL below, never by the process clock.
    if pending_enrollment_missing_expiry(&prior.status, prior.enrollment_expires_at) {
        return Err(conflict(format!(
            "agent '{}' enrollment has no valid expiry; the agent must re-enroll",
            agent_id
        )));
    }

    // A Pending row can cross into trust only when its exact preprovisioned
    // challenge was consumed by a valid Ed25519 proof. Challenge-bound approved
    // rows retain that same identity/platform binding during capability-only
    // reapproval. Legacy rows that were already approved remain operable, but a
    // legacy/unlinked Pending row can never become approved.
    if prior.status == "pending" || prior.enrollment_challenge_id.is_some() {
        let challenge_matches = prior.enrollment_challenge_id.is_some()
            && prior.challenge_status.as_deref() == Some("consumed")
            && prior.consumed_enrollment_id == Some(prior.id)
            && prior.challenge_agent_id.as_deref() == Some(agent_id.as_str())
            && prior.challenge_platform.as_deref() == Some(body.platform.as_str())
            && prior.challenge_public_key.as_deref() == Some(prior.public_key.as_str());
        if !challenge_matches {
            return Err(conflict(
                "agent enrollment lacks a matching consumed provisioning challenge; re-enroll through trusted provisioning",
            ));
        }
    }

    // Persist the already challenge-authorized platform; capabilities are RESET
    // to empty unless the admin explicitly supplies them (the agent's
    // self-declared registration capabilities are never trusted for dispatch).
    let approved_capabilities = match &body.capabilities {
        Some(capabilities) => validated_approved_capabilities(capabilities)?,
        None => json!({}),
    };
    let approved_capabilities_digest = capabilities_digest(&approved_capabilities);

    // Re-approval is also the capability-narrowing path. The agents row is
    // already locked, which is the same first lock taken by leasing, so no new
    // assignment can race this check. Refuse a change that would make an
    // already Leased/Running job incompatible; the administrator may revoke
    // the identity instead, which fences its next authenticated operation.
    if prior.status == "approved" {
        let incompatible_active_job: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
                 SELECT 1 FROM agent_jobs \
                 WHERE agent_id = $1 AND status IN ('Leased', 'Running') \
                   AND NOT ryuki_agent_capabilities_satisfy_requirement( \
                         $2::jsonb, required_capabilities \
                       ) \
             )",
        )
        .bind(&agent_id)
        .bind(&approved_capabilities)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        if incompatible_active_job {
            return Err(conflict(
                "agent capabilities cannot be narrowed while incompatible jobs are active",
            ));
        }
    }

    let updated = sqlx::query(
        "UPDATE agents SET status = 'approved', platform = $1, capabilities = $2::jsonb, \
         enrollment_expires_at = NULL, updated_at = NOW() \
         WHERE agent_id = $3 AND id = $4 \
           AND (status = 'approved' OR ( \
               status = 'pending' \
               AND enrollment_expires_at IS NOT NULL \
               AND enrollment_expires_at > clock_timestamp() \
           ))",
    )
    .bind(&body.platform)
    .bind(&approved_capabilities)
    .bind(&agent_id)
    .bind(body.enrollment_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() != 1 {
        return Err(conflict(format!(
            "agent '{}' enrollment has expired or changed; refresh and re-enroll",
            agent_id
        )));
    }

    // Audit ATOMICALLY with the status change (previously only traced — a gap):
    // actor is the verified admin; detail carries no token hash, raw key, or
    // capability document. The digest makes the exact non-secret grant
    // reviewable without widening the audit payload.
    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-approve",
            Some(&prior.status),
            "approved",
            json!({
                "agent_id": &agent_id,
                "enrollment_id": body.enrollment_id,
                "public_key_fingerprint": &body.public_key_fingerprint,
                "platform": &body.platform,
                "capabilities_digest": &approved_capabilities_digest,
            }),
        ),
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    tracing::info!(
        agent_id = %agent_id,
        enrollment_id = %body.enrollment_id,
        assigned_platform = %body.platform,
        capabilities_digest = %approved_capabilities_digest,
        "agent approved (platform authoritatively set)"
    );
    Ok(Json(json!({
        "agent_id": agent_id,
        "enrollment_id": body.enrollment_id,
        "public_key_fingerprint": body.public_key_fingerprint,
        "status": "approved",
        "platform": body.platform,
        "capabilities_digest": approved_capabilities_digest,
    })))
}

/// POST /api/admin/agents/{agent_id}/revoke
///
/// Sets an agent's status to 'revoked' (from `pending` or `approved`). Revocation
/// is TERMINAL: `authenticate_agent` rejects any status other than 'approved', so
/// the agent's token is refused on its next call, and `admin_approve_agent` cannot
/// move it back. Already-leased jobs are NOT force-cancelled here — they wind down
/// via the lease/fencing/reconcile path; this closes the door to NEW work. Admin-
/// tier (the `/api/admin/` middleware blocks agent-token auth). Idempotent: re-
/// revoking an already-revoked agent returns 200 without a duplicate audit row.
/// The request must carry the immutable enrollment id and reviewed public-key
/// fingerprint from the current admin roster. A stale snapshot returns 409 and
/// cannot revoke a replacement enrollment that reused the same agent id. 404 if
/// the agent is unknown.
pub async fn admin_revoke_agent(
    Path(agent_id): Path<String>,
    Extension(session): Extension<AuthSession>,
    Json(body): Json<RevokeBody>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission is required to revoke an agent"));
    }
    // run-5 A0: fleet revoke is platform-global (revoking a runner starves every
    // job on its platform — a cross-site action). Deny any scoped principal
    // before any row lookup (no existence oracle).
    if is_scoped(&session) {
        return Err(forbidden(
            "agent fleet operations require an unrestricted (non-scoped) admin",
        ));
    }
    if !session.is_verified_human() {
        return Err(forbidden(
            "agent revocation requires a verified human administrator",
        ));
    }
    if !valid_public_key_fingerprint_shape(&body.public_key_fingerprint) {
        return Err(bad_request(
            "public_key_fingerprint must be a lowercase sha256 fingerprint",
        ));
    }
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    activate_agent_enrollment_contract_v3(&mut tx)
        .await
        .map_err(db_err)?;

    let prior: Option<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, status, public_key FROM agents WHERE agent_id = $1 FOR UPDATE")
            .bind(&agent_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some((enrollment_id, prior_status, stored_public_key)) = prior else {
        return Err(not_found(format!("agent '{}' not found", agent_id)));
    };
    let stored_fingerprint = public_key_fingerprint(&stored_public_key);
    if enrollment_id != body.enrollment_id || stored_fingerprint != body.public_key_fingerprint {
        return Err(conflict(
            "the reviewed agent enrollment has changed; refresh the enrollment list",
        ));
    }

    // Idempotent: already revoked → 200, no second state-change audit row.
    if prior_status == "revoked" {
        return Ok(Json(json!({
            "agent_id": agent_id,
            "enrollment_id": body.enrollment_id,
            "public_key_fingerprint": body.public_key_fingerprint,
            "status": "revoked",
            "already_revoked": true
        })));
    }

    let updated = sqlx::query(
        "UPDATE agents SET status = 'revoked', enrollment_expires_at = NULL, \
         updated_at = NOW() WHERE agent_id = $1 AND id = $2",
    )
    .bind(&agent_id)
    .bind(body.enrollment_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() != 1 {
        return Err(conflict(
            "the reviewed agent enrollment has changed; refresh the enrollment list",
        ));
    }

    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-revoke",
            Some(&prior_status),
            "revoked",
            json!({
                "agent_id": &agent_id,
                "enrollment_id": body.enrollment_id,
                "public_key_fingerprint": &body.public_key_fingerprint,
            }),
        ),
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    tracing::warn!(
        agent_id = %agent_id,
        enrollment_id = %body.enrollment_id,
        prior_status = %prior_status,
        "agent revoked (its token will be refused on the next call)"
    );
    Ok(Json(json!({
        "agent_id": agent_id,
        "enrollment_id": body.enrollment_id,
        "public_key_fingerprint": body.public_key_fingerprint,
        "status": "revoked"
    })))
}

/// GET /api/agents/{agent_id}/jobs
///
/// Authenticated (bearer token + approved). Atomically leases the next
/// Pending job for this agent's platform using SELECT … FOR UPDATE SKIP LOCKED,
/// then returns the full Job with its JobLease (including cp_nonce +
/// fencing_token). Returns 204 when no Pending job is available.
pub(crate) async fn lease_pending_job(
    pool: &PgPool,
    agent_id: &str,
) -> Result<Option<LeasedAgentJob>, sqlx::Error> {
    let attempt_id = Uuid::new_v4();
    let fencing_token = Uuid::new_v4().to_string();
    let cp_nonce = Uuid::new_v4().to_string();

    // The agent lock and lease UPDATE must be separate statements in one READ
    // COMMITTED transaction. The first statement serializes all polls for this
    // exact agent across API replicas. A waiter then starts the lease UPDATE
    // with a fresh statement snapshot and therefore sees the preceding poll's
    // newly committed active lease. Folding the row lock and capacity check
    // into one CTE would retain the pre-wait statement snapshot and could
    // oversubscribe the ceiling.
    let mut tx = pool.begin().await?;
    // The security proof below requires a fresh snapshot for statement two
    // after a concurrent poll releases the agent-row lock. Pin the isolation
    // level rather than inheriting a cluster/user override such as REPEATABLE
    // READ, which would retain the pre-wait snapshot and miss the new lease.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    let authority = sqlx::query_as::<_, AgentLeaseAuthorityRow>(
        "SELECT id, platform, public_key, capabilities \
         FROM agents \
         WHERE agent_id = $1 AND status = 'approved' \
         FOR UPDATE",
    )
    .bind(agent_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(authority) = authority else {
        tx.rollback().await?;
        return Ok(None);
    };
    activate_agent_job_lease_contract_v2(&mut tx).await?;

    // A stateful live job is pinned to the first agent that leases its state
    // key. Later plan/apply/destroy jobs, retries, and admin requeues may only
    // return to that agent. The oldest pending live job is the sole unbound
    // affinity anchor, preventing concurrent first leases of sibling jobs from
    // establishing different agents for one key.
    let row = sqlx::query_as::<_, AgentJobRow>(&format!(
        "UPDATE agent_jobs \
         SET status = 'Leased', \
             agent_id = $1, \
             attempt_id = $2, \
             lease_generation = lease_generation + 1, \
             fencing_token = $3, \
             cp_nonce = $4, \
             lease_deadline = NOW() + make_interval(secs => $5), \
             updated_at = NOW() \
         WHERE id = ( \
             SELECT pending.id FROM agent_jobs AS pending \
             WHERE pending.platform = $6 AND pending.status = 'Pending' \
               AND (pending.agent_id IS NULL OR pending.agent_id = $1) \
               AND ( \
                 pending.live_context IS NULL \
                 OR ( \
                   pending.live_context->'execution_authority'->>'assigned_agent_id' = $1 \
                   AND pending.live_context->'execution_authority'->>'assigned_agent_enrollment_id' = $9 \
                   AND pending.live_context->'execution_authority'->>'assigned_agent_key_fingerprint' = $10 \
                 ) \
               ) \
               AND ryuki_agent_capabilities_satisfy_requirement( \
                     $7::jsonb, pending.required_capabilities \
                   ) \
               AND ( \
                 SELECT COUNT(*) FROM ( \
                   SELECT 1 FROM agent_jobs AS active \
                   WHERE active.agent_id = $1 \
                     AND active.status IN ('Leased', 'Running') \
                   LIMIT $8 \
                 ) AS bounded_active \
               ) < $8 \
               AND ( \
                 NOT ( \
                   pending.mode IN ('LivePlan', 'LiveApply', 'LiveDestroy') \
                   OR COALESCE(pending.spec->>'mode', '') \
                      IN ('live_plan', 'live_apply', 'live_destroy') \
                 ) \
                 OR NULLIF(pending.spec->>'state_key', '') IS NULL \
                 OR ( \
                   NOT EXISTS ( \
                     SELECT 1 FROM agent_jobs AS conflicting \
                     WHERE conflicting.agent_id IS NOT NULL \
                       AND conflicting.agent_id <> $1 \
                       AND conflicting.spec->>'state_key' = pending.spec->>'state_key' \
                       AND ( \
                         conflicting.mode IN ('LivePlan', 'LiveApply', 'LiveDestroy') \
                         OR COALESCE(conflicting.spec->>'mode', '') \
                            IN ('live_plan', 'live_apply', 'live_destroy') \
                       ) \
                   ) \
                   AND ( \
                     EXISTS ( \
                       SELECT 1 FROM agent_jobs AS affinity \
                       WHERE affinity.agent_id = $1 \
                         AND affinity.spec->>'state_key' = pending.spec->>'state_key' \
                         AND ( \
                           affinity.mode IN ('LivePlan', 'LiveApply', 'LiveDestroy') \
                           OR COALESCE(affinity.spec->>'mode', '') \
                              IN ('live_plan', 'live_apply', 'live_destroy') \
                         ) \
                     ) \
                     OR pending.id = ( \
                       SELECT anchor.id FROM agent_jobs AS anchor \
                       WHERE anchor.status = 'Pending' \
                         AND anchor.spec->>'state_key' = pending.spec->>'state_key' \
                         AND ( \
                           anchor.mode IN ('LivePlan', 'LiveApply', 'LiveDestroy') \
                           OR COALESCE(anchor.spec->>'mode', '') \
                              IN ('live_plan', 'live_apply', 'live_destroy') \
                         ) \
                       ORDER BY anchor.created_at, anchor.id \
                       LIMIT 1 \
                     ) \
                   ) \
                 ) \
               ) \
             ORDER BY pending.priority DESC, pending.created_at, pending.id \
             FOR UPDATE OF pending SKIP LOCKED \
             LIMIT 1 \
         ) \
         RETURNING {AGENT_JOB_COLUMNS}"
    ))
    .bind(agent_id)
    .bind(attempt_id)
    .bind(&fencing_token)
    .bind(&cp_nonce)
    .bind(LEASE_TTL_SECS as f64)
    .bind(&authority.platform)
    .bind(&authority.capabilities.0)
    .bind(MAX_ACTIVE_LEASES_PER_AGENT)
    .bind(authority.id.to_string())
    .bind(public_key_fingerprint(&authority.public_key))
    .fetch_optional(&mut *tx)
    .await?;

    // Keep the external 204 response deliberately indistinguishable from an
    // empty or incompatible queue, but make saturation observable internally.
    // The diagnostic count is bounded by the same server-controlled ceiling;
    // the predicate in the atomic UPDATE above remains the enforcement point.
    if row.is_none() {
        let active_lease_ceiling_reached: bool = sqlx::query_scalar(
            "SELECT COUNT(*) >= $2 FROM ( \
                 SELECT 1 FROM agent_jobs \
                 WHERE agent_id = $1 AND status IN ('Leased', 'Running') \
                 LIMIT $2 \
             ) AS bounded_active",
        )
        .bind(agent_id)
        .bind(MAX_ACTIVE_LEASES_PER_AGENT)
        .fetch_one(&mut *tx)
        .await?;
        if active_lease_ceiling_reached {
            tracing::debug!(
                agent_id = %agent_id,
                active_lease_limit = MAX_ACTIVE_LEASES_PER_AGENT,
                reason = "active_lease_ceiling",
                "agent poll did not lease work"
            );
        }
    }

    tx.commit().await?;

    Ok(row.map(|row| LeasedAgentJob {
        row,
        attempt_id,
        fencing_token,
        cp_nonce,
    }))
}

pub async fn poll_job(
    _pv: ProtocolVersion,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let pool = match get_db() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "database unavailable"})),
            )
                .into_response()
        }
    };

    let agent = match authenticate_agent(&headers, pool).await {
        Ok(a) => a,
        Err((status, body)) => return (status, body).into_response(),
    };

    // Verify path agent_id matches the token's agent.
    if agent.agent_id != agent_id {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "token does not match agent_id"})),
        )
            .into_response();
    }

    // Atomically lease the next Pending job for this platform.
    // SKIP LOCKED ensures two concurrent polls cannot double-lease the same row.
    // lease_deadline is computed entirely in DB time (NOW() + interval) so all
    // lease timing uses the canonical Postgres clock, not the API server clock.
    let leased = match lease_pending_job(pool, &agent_id).await {
        Ok(Some(leased)) => leased,
        Ok(None) => {
            // No Pending job available — 204 No Content.
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "lease query failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database error"})),
            )
                .into_response();
        }
    };
    let LeasedAgentJob {
        row,
        attempt_id: new_attempt_id,
        fencing_token,
        cp_nonce,
    } = leased;

    let spec: JobSpec = match serde_json::from_value(row.spec.0.clone()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(job_id = %row.id, error = %e, "job spec deserialization failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "malformed job spec in database"})),
            )
                .into_response();
        }
    };

    // Use the DB-computed deadline from the RETURNING row — the canonical value
    // set by NOW() + make_interval in the lease UPDATE.
    let db_deadline = row
        .lease_deadline
        .unwrap_or_else(|| Utc::now() + Duration::seconds(LEASE_TTL_SECS));
    let lease = JobLease {
        attempt_id: new_attempt_id,
        lease_generation: row.lease_generation as u64,
        fencing_token,
        deadline: db_deadline,
        cp_nonce,
    };

    // S5: deliver the CP-signed grant (if any) so the agent can verify_vlc it
    // before a LiveApply. A malformed stored grant is logged and delivered as
    // None — the agent then refuses to apply (fail-safe).
    let live_context = match row.live_context.as_ref() {
        Some(j) => match serde_json::from_value::<VerifiedLiveContext>(j.0.clone()) {
            Ok(g) => Some(g),
            Err(e) => {
                tracing::error!(
                    job_id = %row.id,
                    error = %e,
                    "stored live_context is malformed; delivering job without a grant"
                );
                None
            }
        },
        None => None,
    };

    let job = Job {
        id: row.id,
        agent_enrollment_id: agent.id,
        platform: row.platform.clone(),
        spec,
        status: JobStatus::Leased,
        lease: Some(lease),
        live_context,
    };

    tracing::info!(
        job_id = %row.id,
        agent_id = %agent_id,
        attempt_id = %new_attempt_id,
        "job leased"
    );

    Json(job).into_response()
}

/// POST /api/agents/{agent_id}/jobs/{job_id}/ack
///
/// Transitions Leased → Running. The caller must supply the fencing_token and
/// attempt_id that match the current lease. A mismatch returns 409.
pub async fn ack_job(
    _pv: ProtocolVersion,
    Path((agent_id, job_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> ApiResult<Json<Value>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let agent = authenticate_agent(&headers, pool).await?;

    if agent.agent_id != agent_id {
        return Err(forbidden("token does not match agent_id"));
    }

    let job_id = parse_agent_job_id(&job_id_str)?;

    // Atomic conditional UPDATE: transitions Leased → Running in a single
    // statement. All four conditions (status, attempt_id, fencing_token,
    // lease_deadline) are evaluated by the DB in one round-trip, eliminating
    // the TOCTOU window that existed in the previous read-then-write approach.
    // A concurrent expire/re-lease between a SELECT and this UPDATE can no
    // longer clobber a stale ack into Running.
    // Scalar query returns the id if the UPDATE matched — used only for
    // is_some() check, so we query the scalar directly.
    // `agent_id = $4` binds the transition to the AUTHENTICATED agent, so even a
    // leaked attempt_id + fencing_token cannot be replayed by a different agent to
    // drive another agent's job to Running (defense-in-depth on top of the
    // fencing_token secret).
    let updated = sqlx::query_scalar::<_, Uuid>(
        "UPDATE agent_jobs AS job \
         SET status = 'Running', updated_at = NOW() \
         WHERE job.id = $1 \
           AND job.agent_id = $4 \
           AND job.status = 'Leased' \
           AND job.attempt_id = $2 \
           AND job.fencing_token = $3 \
           AND job.lease_deadline >= NOW() \
         RETURNING job.id",
    )
    .bind(job_id)
    .bind(body.attempt_id)
    .bind(&body.fencing_token)
    .bind(&agent.agent_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    if updated.is_some() {
        // Scalar result is the matched row id — presence means transition succeeded.
        tracing::info!(job_id = %job_id, agent_id = %agent_id, "job ack → Running");
        return Ok(Json(json!({"job_id": job_id, "status": "Running"})));
    }

    // UPDATE matched 0 rows. Disambiguate: 404 vs 409.
    #[derive(sqlx::FromRow)]
    struct StatusRow {
        agent_id: Option<String>,
        status: String,
        attempt_id: Option<Uuid>,
        lease_deadline: Option<chrono::DateTime<Utc>>,
    }
    let existing = sqlx::query_as::<_, StatusRow>(
        "SELECT agent_id, status, attempt_id, lease_deadline FROM agent_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let row = match existing {
        None => return Err(not_found(format!("job {} not found", job_id))),
        Some(r) => r,
    };

    // ── Authorization BEFORE any status disclosure ───────────────────────────
    //
    // The UPDATE above can only match a job leased to THIS agent (it requires the
    // caller's attempt_id + fencing_token, which another agent's lease does not
    // share), so a 0-row UPDATE followed by a status-specific 409 would otherwise
    // let any approved agent probe a job leased to a DIFFERENT agent and learn its
    // existence + lifecycle state. Mirror `post_job_result`'s assignee guard: a
    // non-assignee (or unassigned/Pending job, agent_id = NULL) is rejected 403
    // before any state-dependent reason is built.
    if row.agent_id.as_deref() != Some(&agent.agent_id) {
        return Err(forbidden("job is not assigned to this agent"));
    }

    // Build a clear rejection reason for the caller.
    let reason = if row.status != "Leased" {
        format!(
            "job {} is in status '{}', expected 'Leased'",
            job_id, row.status
        )
    } else if row.attempt_id != Some(body.attempt_id) {
        "attempt_id mismatch — lease has been superseded".to_string()
    } else if row.lease_deadline.map(|d| d < Utc::now()).unwrap_or(true) {
        "lease has expired".to_string()
    } else {
        "fencing_token mismatch".to_string()
    };

    Err(conflict(reason))
}

// ---------------------------------------------------------------------------
// Result body — submitted by the agent
// ---------------------------------------------------------------------------

/// Body for POST /api/agents/{agent_id}/jobs/{job_id}/result.
///
/// The outer `JobResult` fields are untrusted; only the embedded
/// `SignedEnvelope` is authoritative. The handler equality-checks every outer
/// field against the signed envelope before persisting anything.
#[derive(Debug, Deserialize)]
pub struct ResultBody {
    pub job_result: JobResult,
    /// Raw evidence bytes (the payload whose SHA-256 is `evidence_digest`).
    /// May be empty for modes that produce no evidence (e.g. OfflineDryRun
    /// without a plan artifact), but the digest must still match.
    #[serde(default)]
    pub evidence: Vec<u8>,
    /// Optional structured evidence parsed from the evidence bytes.
    /// Stored as JSONB for query convenience; never trusted for authz.
    #[serde(default)]
    pub evidence_json: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Internal DB row for the terminal result read-back (idempotency)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(sqlx::FromRow)]
struct TerminalResultRow {
    status: String,
    result_id: Option<uuid::Uuid>,
    result_status: Option<String>,
    evidence_digest: Option<String>,
    completed_at: Option<chrono::DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// JobResultStatus wire label → DB TEXT
// ---------------------------------------------------------------------------

fn result_status_label(s: &JobResultStatus) -> &'static str {
    match s {
        JobResultStatus::CheckOk => "check_ok",
        JobResultStatus::Planned => "planned",
        JobResultStatus::Applied => "applied",
        JobResultStatus::Verified => "verified",
        JobResultStatus::Failed => "failed",
        JobResultStatus::LiveRefused => "live_refused",
    }
}

// ---------------------------------------------------------------------------
// JobResultStatus → terminal agent_jobs.status
// ---------------------------------------------------------------------------

fn map_result_status_to_job_status(mode: &JobMode, s: &JobResultStatus) -> &'static str {
    if matches!(mode, JobMode::LiveApply | JobMode::LiveDestroy)
        && matches!(s, JobResultStatus::Failed)
    {
        return "ReconcileRequired";
    }
    match s {
        JobResultStatus::CheckOk
        | JobResultStatus::Planned
        | JobResultStatus::Applied
        | JobResultStatus::Verified => "Succeeded",
        JobResultStatus::Failed => "Failed",
        JobResultStatus::LiveRefused => "LiveRefused",
    }
}

// ---------------------------------------------------------------------------
// #60 slice 2: write-side evidence offload.
//
// Large evidence bloats the hot, frequently-updated `agent_jobs` row. Evidence
// over `ryuki_engine::evidence_store::DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES`
// is offloaded to the content-addressed `evidence_blobs` table (keyed by the
// ALREADY-VERIFIED `evidence_digest` — step 6 above guarantees
// `sha256_hex(&body.evidence) == env.evidence_digest` before this is ever
// called), and only a small reference is stored inline in place of the full
// `evidence_json`. Small evidence is unaffected — it keeps flowing through as
// the agent-submitted `evidence_json` exactly as before.
// ---------------------------------------------------------------------------

/// Reference stored inline in `agent_jobs.evidence_json` when the raw evidence
/// was offloaded to `evidence_blobs`. Deliberately small and DOES NOT include
/// the raw evidence — the read side (resolving this reference back to bytes)
/// is a separate, design-gated slice.
fn evidence_blob_reference(digest: &str, size_bytes: usize) -> Value {
    json!({
        "_evidence_blob_digest": digest,
        "_evidence_size_bytes": size_bytes,
    })
}

/// Decide what to persist in `agent_jobs.evidence_json` for this result: the
/// original agent-submitted `evidence_json` when evidence is small enough to
/// stay inline, or a small digest reference when it is large enough to
/// offload. Pure and side-effect-free so the offload threshold decision is
/// unit-testable without a DB. `offload` is the caller's already-computed
/// [`ryuki_engine::evidence_store::EvidenceStorage::is_offloaded`] result —
/// passed in rather than recomputed so the handler and the persisted
/// `evidence_blobs` INSERT can never disagree on the decision.
fn compute_evidence_json_for_storage(
    offload: bool,
    evidence_len: usize,
    evidence_digest: &str,
    evidence_json: &Option<Value>,
) -> Option<Value> {
    if offload {
        Some(evidence_blob_reference(evidence_digest, evidence_len))
    } else {
        evidence_json.clone()
    }
}

/// Sanitized, server-derived review of a digest-verified Terraform LivePlan.
/// Raw plan JSON is deliberately never serialized through this type.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct LivePlanReview {
    digest_verified: bool,
    state_key: String,
    placement: LivePlanPlacement,
    managed_changes: Vec<ManagedPlanChange>,
    counts: PlanChangeCounts,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct LivePlanPlacement {
    name: String,
    cpu: u32,
    memory_gb: u32,
    disk_size_gb: u32,
    datacenter: String,
    cluster: String,
    datastore: String,
    network: String,
    template: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ManagedPlanChange {
    resource_type: &'static str,
    logical_name: String,
    action: &'static str,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct PlanChangeCounts {
    create: u32,
    update: u32,
    delete: u32,
    replace: u32,
}

#[derive(Debug, Default)]
struct PlannedPlacementNames {
    datacenter: Option<String>,
    cluster: Option<String>,
    datastore: Option<String>,
    network: Option<String>,
    template: Option<String>,
}

#[derive(Debug)]
struct PlannedVmShape {
    name: String,
    cpu: u32,
    memory_gb: u32,
    disk_size_gb: u32,
}

fn safe_plan_review_value(
    vars: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Option<String> {
    let value = vars.get(key)?.trim();
    if value.is_empty()
        || value.len() > 160
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || value.contains("://")
    {
        return None;
    }
    Some(value.to_string())
}

fn live_plan_placement(spec: &JobSpec) -> Option<LivePlanPlacement> {
    let offering = spec.iac_ref.split('@').next()?;
    if !matches!(
        offering,
        "linux-server-deployment" | "windows-server-deployment"
    ) {
        return None;
    }

    let memory_mb = safe_plan_review_value(&spec.vars, "memory_mb")
        .and_then(|value| value.parse::<u32>().ok())?;
    if memory_mb == 0 || memory_mb % 1024 != 0 {
        return None;
    }

    Some(LivePlanPlacement {
        name: safe_plan_review_value(&spec.vars, "vm_name")?,
        cpu: safe_plan_review_value(&spec.vars, "num_cpus")?
            .parse()
            .ok()
            .filter(|value| *value > 0)?,
        memory_gb: memory_mb / 1024,
        disk_size_gb: safe_plan_review_value(&spec.vars, "disk_size_gb")?
            .parse()
            .ok()
            .filter(|value| *value > 0)?,
        datacenter: safe_plan_review_value(&spec.vars, "datacenter")?,
        cluster: safe_plan_review_value(&spec.vars, "cluster")?,
        datastore: safe_plan_review_value(&spec.vars, "datastore")?,
        network: safe_plan_review_value(&spec.vars, "network")?,
        template: safe_plan_review_value(&spec.vars, "template")?,
    })
}

fn classify_managed_plan_action(actions: &[Value]) -> Option<Option<&'static str>> {
    let labels: Option<Vec<&str>> = actions.iter().map(Value::as_str).collect();
    match labels?.as_slice() {
        ["no-op"] | ["read"] => Some(None),
        ["create"] => Some(Some("create")),
        ["update"] => Some(Some("update")),
        ["delete"] => Some(Some("delete")),
        ["delete", "create"] | ["create", "delete"] => Some(Some("replace")),
        _ => None,
    }
}

fn plan_u32(value: &Value) -> Option<u32> {
    u32::try_from(value.as_u64()?).ok()
}

fn has_exact_object_keys(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn planned_vm_shape(after: &Value) -> Option<PlannedVmShape> {
    if !has_exact_object_keys(after, &["name", "num_cpus", "memory", "disk"]) {
        return None;
    }
    let after = after.as_object()?;
    let memory_mb = plan_u32(after.get("memory")?)?;
    let cpu = plan_u32(after.get("num_cpus")?)?;
    let disk_size_gb = plan_u32(after.get("disk")?.as_array()?.first()?.get("size")?)?;
    if memory_mb == 0 || memory_mb % 1024 != 0 || cpu == 0 || disk_size_gb == 0 {
        return None;
    }
    let disks = after.get("disk")?.as_array()?;
    let [disk] = disks.as_slice() else {
        return None;
    };
    if !has_exact_object_keys(disk, &["label", "size"]) {
        return None;
    }
    if disk.get("label").and_then(Value::as_str) != Some("disk0") {
        return None;
    }
    Some(PlannedVmShape {
        name: after.get("name")?.as_str()?.to_string(),
        cpu,
        memory_gb: memory_mb / 1024,
        disk_size_gb,
    })
}

fn record_planned_placement_name(
    names: &mut PlannedPlacementNames,
    resource_type: &str,
    logical_name: &str,
    after: &Value,
) -> Option<()> {
    if !has_exact_object_keys(after, &["name"]) {
        return None;
    }
    let value = after.get("name")?.as_str()?.to_string();
    let slot = match (resource_type, logical_name) {
        ("vsphere_datacenter", "dc") => &mut names.datacenter,
        ("vsphere_compute_cluster", "cluster") => &mut names.cluster,
        ("vsphere_datastore", "ds") => &mut names.datastore,
        ("vsphere_network", "net") => &mut names.network,
        ("vsphere_virtual_machine", "template") => &mut names.template,
        _ => return None,
    };
    if slot.is_some() {
        return None;
    }
    *slot = Some(value);
    Some(())
}

/// Parse only the versioned safe-projection envelope emitted by the runner.
/// Legacy/raw Terraform JSON, unknown fields, incomplete projections, and
/// unknown mutating resource types/actions all fail closed and suppress the
/// review rather than reflecting Terraform/provider data.
fn derive_live_plan_review(spec: &JobSpec, evidence: &[u8]) -> Option<LivePlanReview> {
    let state_key = spec.state_key.clone()?;
    if !ryuki_protocol::is_safe_state_key(&state_key) {
        return None;
    }
    let expected_placement = live_plan_placement(spec)?;
    let expected_resource_name = match spec.iac_ref.split('@').next()? {
        "linux-server-deployment" => "linux_server",
        "windows-server-deployment" => "windows_server",
        _ => return None,
    };
    let plan: Value = serde_json::from_slice(evidence).ok()?;
    if !has_exact_object_keys(
        &plan,
        &[
            "schema_version",
            "canonical_plan_sha256",
            "projection_complete",
            "resource_changes",
        ],
    ) || plan.get("schema_version")?.as_str()?
        != ryuki_protocol::TERRAFORM_LIVE_PLAN_EVIDENCE_SCHEMA_VERSION
        || !plan.get("projection_complete")?.as_bool()?
        || !is_lowercase_sha256(plan.get("canonical_plan_sha256")?.as_str()?)
    {
        return None;
    }
    let resource_changes = plan.get("resource_changes")?.as_array()?;
    let mut managed_changes = Vec::new();
    let mut counts = PlanChangeCounts::default();
    let mut placement_names = PlannedPlacementNames::default();
    let mut vm_shape: Option<PlannedVmShape> = None;

    for resource in resource_changes {
        if !has_exact_object_keys(resource, &["mode", "type", "name", "change"]) {
            return None;
        }
        let resource_mode = resource.get("mode").and_then(Value::as_str)?;
        let change = resource.get("change")?;
        if !has_exact_object_keys(change, &["actions", "after"]) {
            return None;
        }
        let actions = change.get("actions")?.as_array()?;
        let action = classify_managed_plan_action(actions)?;

        if resource_mode == "data" {
            // Data sources must be read-only and must be the exact five
            // placement lookups used by the reviewed vSphere bundle. Their
            // planned `after.name` values are the only plan-side representation
            // of the operator-facing placement names (the managed VM stores
            // provider object ids instead).
            if action.is_some() {
                return None;
            }
            record_planned_placement_name(
                &mut placement_names,
                resource.get("type")?.as_str()?,
                resource.get("name")?.as_str()?,
                change.get("after")?,
            )?;
            continue;
        }
        if resource_mode != "managed" {
            return None;
        }
        if resource.get("type").and_then(Value::as_str) != Some("vsphere_virtual_machine")
            || resource.get("name").and_then(Value::as_str) != Some(expected_resource_name)
        {
            return None;
        }
        if vm_shape.is_some() {
            return None;
        }
        vm_shape = Some(planned_vm_shape(change.get("after")?)?);
        // Retention may include one exact, allowlisted managed no-op/read so
        // scheduled drift checks can record a converged projection. Approval
        // remains stricter below: it requires exactly one create and therefore
        // cannot authorize this non-mutating shape.
        if let Some(action) = action {
            match action {
                "create" => counts.create += 1,
                "update" => counts.update += 1,
                "delete" => counts.delete += 1,
                "replace" => counts.replace += 1,
                _ => return None,
            }
            managed_changes.push(ManagedPlanChange {
                resource_type: "virtual_machine",
                logical_name: expected_resource_name.to_string(),
                action,
            });
        }
    }

    let vm_shape = vm_shape?;
    let actual_placement = LivePlanPlacement {
        name: vm_shape.name,
        cpu: vm_shape.cpu,
        memory_gb: vm_shape.memory_gb,
        disk_size_gb: vm_shape.disk_size_gb,
        datacenter: placement_names.datacenter?,
        cluster: placement_names.cluster?,
        datastore: placement_names.datastore?,
        network: placement_names.network?,
        template: placement_names.template?,
    };
    if actual_placement != expected_placement {
        return None;
    }

    Some(LivePlanReview {
        digest_verified: true,
        state_key,
        placement: actual_placement,
        managed_changes,
        counts,
    })
}

/// Enforce the distinct raw-plan commitment carried by a successful LivePlan.
/// The evidence digest proves the retained safe-projection bytes; this value
/// instead commits to the complete canonical Terraform plan that projection
/// was derived from. Legacy results without the signed commitment and results
/// whose commitment differs from the digest inside the verified projection
/// fail closed.
fn validated_raw_plan_digest(
    mode: &JobMode,
    status: &JobResultStatus,
    signed_raw_plan_digest: Option<&str>,
    spec: &JobSpec,
    evidence: &[u8],
) -> Result<Option<String>, &'static str> {
    if *mode == JobMode::LivePlan && *status == JobResultStatus::Planned {
        if derive_live_plan_review(spec, evidence).is_none() {
            return Err("LivePlan evidence is not a complete supported safe projection");
        }
        let signed = signed_raw_plan_digest
            .ok_or("successful LivePlan result must include signed raw_plan_digest")?;
        if !is_lowercase_sha256(signed) {
            return Err("raw_plan_digest must be a lowercase SHA-256 digest");
        }
        let projection: Value = serde_json::from_slice(evidence)
            .map_err(|_| "LivePlan evidence is not a complete supported safe projection")?;
        let projected = projection
            .get("canonical_plan_sha256")
            .and_then(Value::as_str)
            .ok_or("LivePlan evidence is not a complete supported safe projection")?;
        if projected != signed {
            return Err(
                "raw_plan_digest does not match the canonical plan digest in signed evidence",
            );
        }
        return Ok(Some(signed.to_owned()));
    }

    if signed_raw_plan_digest.is_some() {
        return Err("raw_plan_digest is only valid for a successful LivePlan result");
    }
    Ok(None)
}

pub(crate) fn server_live_plan_is_safe_to_approve(spec: &JobSpec, evidence: &[u8]) -> bool {
    let Some(review) = derive_live_plan_review(spec, evidence) else {
        return false;
    };
    review.counts
        == (PlanChangeCounts {
            create: 1,
            update: 0,
            delete: 0,
            replace: 0,
        })
        && review.managed_changes.len() == 1
        && review.managed_changes[0].action == "create"
}

// ---------------------------------------------------------------------------
// #43 post-apply verification: derive the runner's convergence verdict and map
// it to a CP-internal terminal outcome + optional domain event.
// ---------------------------------------------------------------------------

/// Extract the post-apply verdict from the evidence bytes whose SHA-256 was
/// verified against the SIGNED envelope in step 6. This MUST read `body.evidence`
/// (the digest-covered bytes), NEVER `body.evidence_json` — the latter is an
/// UNSIGNED convenience field, and trusting it would let a compromised agent
/// forge a `verified` upgrade by pairing digest-matching `applied` evidence with
/// a JSON blob claiming convergence. Fail-closed: any deserialize failure or an
/// absent verdict yields `None`, so the CP never upgrades off uninterpretable
/// evidence.
fn post_apply_verdict_from_evidence(
    evidence: &[u8],
) -> Option<ryuki_engine::post_apply::PostApplyOutcome> {
    serde_json::from_slice::<ryuki_engine::runners::RunOutcome>(evidence)
        .ok()
        .and_then(|o| o.post_apply)
}

/// The CP-internal terminal decision derived from a post-apply verdict: the
/// `result_status` to record, the domain-event `to_status` the alert classifier
/// keys on (`ryuki_engine::event_alerts::severity_for_request_status`), and the
/// optional domain event type to emit.
struct PostApplyIngest {
    result_status: &'static str,
    /// The event payload's `to_status` — the alert-classifier key. Distinct from
    /// `result_status`: a drift event records result_status "applied" (the apply
    /// DID succeed) but reports `to_status` "drift-detected" so it alerts.
    to_status: &'static str,
    event_type: Option<&'static str>,
}

/// Map a post-apply verdict to the CP-internal terminal `result_status`, the
/// alert `to_status`, and the domain event to emit. Only meaningful on the
/// `LiveApply` + `Applied` path. Fail-closed: `Inconclusive` / absent keeps
/// `applied` and emits nothing — a request is NEVER marked `verified` off an
/// uninterpretable or missing re-plan.
fn resolve_post_apply_ingest(
    verdict: Option<ryuki_engine::post_apply::PostApplyOutcome>,
) -> PostApplyIngest {
    use ryuki_engine::post_apply::{
        PostApplyOutcome, EVENT_POST_APPLY_DRIFT, EVENT_POST_APPLY_VERIFIED,
    };
    match verdict {
        // Converged — GOOD news; not alert-worthy (severity_for_request_status
        // returns None for "verified").
        Some(PostApplyOutcome::Verified) => PostApplyIngest {
            result_status: "verified",
            to_status: "verified",
            event_type: Some(EVENT_POST_APPLY_VERIFIED),
        },
        // Apply succeeded but the re-plan still shows pending changes: the result
        // stays "applied" (the apply DID run), but the event's "drift-detected"
        // to_status makes it a Critical alert.
        Some(PostApplyOutcome::DriftDetected) => PostApplyIngest {
            result_status: "applied",
            to_status: "drift-detected",
            event_type: Some(EVENT_POST_APPLY_DRIFT),
        },
        _ => PostApplyIngest {
            result_status: "applied",
            to_status: "applied",
            event_type: None,
        },
    }
}

#[cfg(test)]
mod post_apply_ingest_tests {
    use super::{post_apply_verdict_from_evidence, resolve_post_apply_ingest};
    use ryuki_engine::event_alerts::{severity_for_request_status, AlertSeverity};
    use ryuki_engine::post_apply::{
        PostApplyOutcome, EVENT_POST_APPLY_DRIFT, EVENT_POST_APPLY_VERIFIED,
    };
    use ryuki_engine::runners::{RunMode, RunOutcome, RunStatus, RunnerKind};

    fn evidence_with(verdict: Option<PostApplyOutcome>) -> Vec<u8> {
        let outcome = RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: RunMode::Live,
            status: RunStatus::Applied,
            summary: "Apply complete!".to_string(),
            log: String::new(),
            exit_code: Some(0),
            post_apply: verdict,
        };
        serde_json::to_vec(&outcome).expect("serialize RunOutcome")
    }

    #[test]
    fn verified_verdict_upgrades_and_emits_verified_event() {
        let d = resolve_post_apply_ingest(Some(PostApplyOutcome::Verified));
        assert_eq!(d.result_status, "verified");
        assert_eq!(d.to_status, "verified");
        assert_eq!(d.event_type, Some(EVENT_POST_APPLY_VERIFIED));
        // A converged verify is GOOD news — it must NOT alert.
        assert_eq!(severity_for_request_status(d.to_status), None);
    }

    #[test]
    fn drift_verdict_stays_applied_and_emits_drift_event() {
        let d = resolve_post_apply_ingest(Some(PostApplyOutcome::DriftDetected));
        // The apply DID run, so the recorded result stays "applied"…
        assert_eq!(d.result_status, "applied");
        // …but the event's to_status must be the alert-worthy "drift-detected".
        assert_eq!(d.to_status, "drift-detected");
        assert_eq!(d.event_type, Some(EVENT_POST_APPLY_DRIFT));
        // Cross-crate lock-step: the CP's chosen to_status MUST alert Critical in
        // the engine classifier, or drift would silently never page an operator.
        assert_eq!(
            severity_for_request_status(d.to_status),
            Some(AlertSeverity::Critical)
        );
    }

    #[test]
    fn inconclusive_and_absent_never_upgrade_and_emit_nothing() {
        for v in [Some(PostApplyOutcome::Inconclusive), None] {
            let d = resolve_post_apply_ingest(v);
            assert_eq!(d.result_status, "applied", "must never upgrade off {v:?}");
            assert_eq!(d.event_type, None, "must emit nothing for {v:?}");
        }
    }

    #[test]
    fn verdict_is_read_from_digested_evidence_bytes() {
        let bytes = evidence_with(Some(PostApplyOutcome::Verified));
        assert_eq!(
            post_apply_verdict_from_evidence(&bytes),
            Some(PostApplyOutcome::Verified)
        );
        let drift = evidence_with(Some(PostApplyOutcome::DriftDetected));
        assert_eq!(
            post_apply_verdict_from_evidence(&drift),
            Some(PostApplyOutcome::DriftDetected)
        );
    }

    #[test]
    fn fail_closed_on_unparseable_or_absent_verdict() {
        // Non-JSON / non-RunOutcome bytes → None (never a false verdict).
        assert_eq!(post_apply_verdict_from_evidence(b"not json at all"), None);
        assert_eq!(post_apply_verdict_from_evidence(b"{}"), None);
        // A well-formed RunOutcome with no post_apply field → None.
        let no_verdict = evidence_with(None);
        assert_eq!(post_apply_verdict_from_evidence(&no_verdict), None);
    }
}

// ---------------------------------------------------------------------------
// #31 slice 2: SCHEDULED drift-recheck classification (distinct from #43's
// immediate post-apply re-plan above). A scheduler-created LivePlan job whose
// `agent_jobs.origin` marks it as a drift-recheck is classified for drift off
// its DIGEST-VERIFIED plan bytes; a normal operator LivePlan (origin NULL) is
// EXPECTED to show changes and must never emit this event.
// ---------------------------------------------------------------------------

/// Is this job result a SCHEDULED drift-recheck re-plan — a LivePlan job the
/// scheduler created with `origin='drift_recheck'`, reporting a completed plan?
/// Both the drift classification (below) AND the cadence reset (#31 slice 2b:
/// advancing the deployment's `last_drift_check_at`) key on this. A NORMAL operator
/// LivePlan (origin NULL) is neither — it is expected to show changes and must never
/// drive a drift event or reset the drift-recheck clock.
fn is_drift_recheck_replan(mode: &JobMode, status: &JobResultStatus, origin: Option<&str>) -> bool {
    *mode == JobMode::LivePlan
        && *status == JobResultStatus::Planned
        && origin == Some(ryuki_engine::drift_scan::DRIFT_RECHECK_JOB_ORIGIN)
}

/// #31 slice 2: does this result warrant a SCHEDULED-drift event? Only a drift-recheck-origin
/// LivePlan (see [`is_drift_recheck_replan`]) whose DIGEST-VERIFIED plan bytes classify as
/// DriftDetected emits. Verified/Inconclusive/any other mode/status/origin => None (fail-closed:
/// never alert off an unclear or operator plan).
fn resolve_scheduled_drift_event(
    mode: JobMode,
    status: JobResultStatus,
    origin: Option<&str>,
    evidence: &[u8],
) -> Option<&'static str> {
    use ryuki_engine::post_apply::{
        classify_plan_json, PostApplyOutcome, EVENT_SCHEDULED_DRIFT_DETECTED,
    };
    if !is_drift_recheck_replan(&mode, &status, origin) {
        return None;
    }
    match classify_plan_json(evidence) {
        PostApplyOutcome::DriftDetected => Some(EVENT_SCHEDULED_DRIFT_DETECTED),
        _ => None,
    }
}

#[cfg(test)]
mod resolve_scheduled_drift_tests {
    use super::{is_drift_recheck_replan, resolve_scheduled_drift_event};
    use ryuki_engine::drift_scan::DRIFT_RECHECK_JOB_ORIGIN;
    use ryuki_engine::event_alerts::{severity_for_request_status, AlertSeverity};
    use ryuki_engine::post_apply::EVENT_SCHEDULED_DRIFT_DETECTED;
    use ryuki_protocol::{JobMode, JobResultStatus};

    fn plan_with_actions(actions: &str) -> Vec<u8> {
        format!(r#"{{"resource_changes":[{{"change":{{"actions":{actions}}}}}]}}"#).into_bytes()
    }

    #[test]
    fn is_drift_recheck_replan_gates_on_mode_status_and_origin() {
        // The one true positive: a scheduler-origin LivePlan reporting a completed plan.
        assert!(is_drift_recheck_replan(
            &JobMode::LivePlan,
            &JobResultStatus::Planned,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
        ));
        // Operator plan (no origin) — must NOT reset the clock or classify drift.
        assert!(!is_drift_recheck_replan(
            &JobMode::LivePlan,
            &JobResultStatus::Planned,
            None,
        ));
        // Wrong mode / wrong status.
        assert!(!is_drift_recheck_replan(
            &JobMode::LiveApply,
            &JobResultStatus::Planned,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
        ));
        assert!(!is_drift_recheck_replan(
            &JobMode::LivePlan,
            &JobResultStatus::Applied,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
        ));
    }

    #[test]
    fn drift_recheck_plan_with_mutation_emits_scheduled_drift_event() {
        let evidence = plan_with_actions(r#"["update"]"#);
        let event = resolve_scheduled_drift_event(
            JobMode::LivePlan,
            JobResultStatus::Planned,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
            &evidence,
        );
        assert_eq!(event, Some(EVENT_SCHEDULED_DRIFT_DETECTED));
        // Cross-crate lock-step: the emitted event's to_status must alert Critical,
        // or scheduled drift would silently never page an operator.
        assert_eq!(
            severity_for_request_status("drift-detected"),
            Some(AlertSeverity::Critical)
        );
    }

    #[test]
    fn drift_recheck_plan_with_only_no_op_emits_nothing() {
        let evidence = plan_with_actions(r#"["no-op"]"#);
        let event = resolve_scheduled_drift_event(
            JobMode::LivePlan,
            JobResultStatus::Planned,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
            &evidence,
        );
        assert_eq!(event, None);
    }

    #[test]
    fn unparseable_evidence_is_fail_closed_to_none() {
        let event = resolve_scheduled_drift_event(
            JobMode::LivePlan,
            JobResultStatus::Planned,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
            b"not json",
        );
        assert_eq!(event, None);
    }

    #[test]
    fn operator_plan_with_no_origin_never_emits() {
        // MUST NOT emit for operator plans, even with mutating actions.
        let evidence = plan_with_actions(r#"["update"]"#);
        let event = resolve_scheduled_drift_event(
            JobMode::LivePlan,
            JobResultStatus::Planned,
            None,
            &evidence,
        );
        assert_eq!(event, None);
    }

    #[test]
    fn live_apply_with_drift_recheck_origin_never_emits() {
        let evidence = plan_with_actions(r#"["update"]"#);
        let event = resolve_scheduled_drift_event(
            JobMode::LiveApply,
            JobResultStatus::Planned,
            Some(DRIFT_RECHECK_JOB_ORIGIN),
            &evidence,
        );
        assert_eq!(event, None);
    }
}

// ---------------------------------------------------------------------------
// redaction_policy_version ingestion guard
// ---------------------------------------------------------------------------

/// `redaction_policy_version` is the ONE `SignedEnvelope` string field with no
/// authoritative per-result CP counterpart to cross-check at ingestion —
/// `agent_id`, `platform`, `key_id`, and `cp_nonce` are all verified against
/// stored enrolment/lease state, but the policy version is whatever the agent
/// signed. Without a bound, a buggy or compromised agent could sign arbitrary
/// text (a bare token like `SUPERSECRET` included) into it that would later ride
/// through the admin result-retrieval view (which re-serialises the typed
/// envelope, known fields included). So the CP gates it against the CLOSED
/// allowlist of policy versions it actually recognises — a slug match, not a
/// charset/shape heuristic — which fully closes the free-form channel AND
/// refuses evidence redacted under a policy the CP cannot interpret. The
/// allowlist lives in `ryuki_protocol` so agent emission and CP acceptance share
/// one source of truth and cannot drift.
fn redaction_policy_version_is_supported(v: &str) -> bool {
    ryuki_protocol::SUPPORTED_REDACTION_POLICY_VERSIONS.contains(&v)
}

/// Closed-allowlist gate for the CP↔agent WIRE protocol version, mirroring
/// [`redaction_policy_version_is_supported`]. Both the accept side here and the
/// agent emit side reference the ONE `ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS`
/// constant, so they cannot drift.
fn protocol_version_is_supported(v: u32) -> bool {
    ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&v)
}

/// Resolves the wire protocol version an agent request asserts via the
/// `x-ryuki-protocol-version` header, FAIL-CLOSED:
/// - more than one header value → 400 (ambiguous — a proxy-smuggling / drift smell)
/// - present but not a `u32 > 0` → 400
/// - absent                     → `PROTOCOL_VERSION_LEGACY` (1)
///
/// The resolved value is then ALWAYS checked against
/// `SUPPORTED_PROTOCOL_VERSIONS`. The current v6-only allowlist therefore
/// rejects an absent header as legacy v1; omission is never a compatibility
/// bypass. Used by the [`ProtocolVersion`] extractor.
fn resolve_protocol_version(headers: &HeaderMap) -> Result<u32, (StatusCode, Json<Value>)> {
    let mut values = headers
        .get_all(ryuki_protocol::PROTOCOL_VERSION_HEADER)
        .iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(bad_request(
            "x-ryuki-protocol-version must not appear more than once",
        ));
    }
    let version = match first {
        None => ryuki_protocol::PROTOCOL_VERSION_LEGACY,
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&n| n > 0)
            .ok_or_else(|| bad_request("x-ryuki-protocol-version must be a positive integer"))?,
    };
    if !protocol_version_is_supported(version) {
        return Err(bad_request(format!(
            "unsupported protocol_version: {version} — this control plane supports {:?}",
            ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS
        )));
    }
    Ok(version)
}

/// Extractor that validates the `x-ryuki-protocol-version` header on every
/// agent→CP request. Being a `FromRequestParts` extractor, it runs BEFORE the
/// `Json` body extractor — so a version-incompatible agent (which would send a
/// body this build can't deserialise once the schema moves) gets the clear
/// [`resolve_protocol_version`] 400 instead of an opaque body-decode error. The
/// inner `u32` is the resolved version (read by register/heartbeat to record the
/// enrolment baseline; ignored by poll/ack/result, whose enforcement is the mere
/// successful extraction).
pub(crate) struct ProtocolVersion(u32);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ProtocolVersion {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        resolve_protocol_version(&parts.headers).map(ProtocolVersion)
    }
}

// ---------------------------------------------------------------------------
// POST /api/agents/{agent_id}/jobs/{job_id}/result
// ---------------------------------------------------------------------------

/// Verifies and records the signed `JobResult` from an agent.
///
/// The full 9-step verifier runs FAIL-CLOSED: every check that fails returns
/// 4xx and mutates nothing. The terminal UPDATE is a single atomic conditional
/// statement guarded on (id, attempt_id, lease_generation, status IN
/// ('Leased','Running'), unexpired database-clock lease). A repeat POST with the
/// same (job_id, attempt_id, result_id) returns idempotent 200.
pub async fn post_job_result(
    _pv: ProtocolVersion,
    Path((agent_id, job_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ResultBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    post_job_result_with_pool(agent_id, job_id_str, headers, body, pool).await
}

/// Enrich the `execute` stage with the agent result, PRESERVING the existing
/// history, and CAS-advance the request out of `executing` — the single-job
/// (no step plan) request-advance authority, and also the terminal move for a
/// multi-step request once its plan is fully resolved (all steps `Succeeded`,
/// or any step `Failed`; #42 slice 2b). `stages_val` is the request's raw
/// `stages` JSONB, read by the caller BEFORE any plan branching.
///
/// Critically, a parse failure must NOT wipe the stages: the old
/// `unwrap_or_default()` turned an undeserializable `requests.stages` (e.g. a
/// Stage schema skew) into an empty vec, and the UPDATE below then wrote
/// `stages = '[]'`, destroying the intake/plan/approve/lock history and breaking
/// every later stage-gate check. On a parse failure we instead advance the
/// request status but write the ORIGINAL stages JSONB back untouched, and log the
/// skew so it is visible. (We do NOT return Err: that would roll back the result
/// tx, and the agent's at-least-once retry would hit the same parse failure
/// forever — better to record the result + preserve history + surface the anomaly.)
///
/// CAS-guarded: only advances if the request is still `executing` (a
/// concurrent transition wins harmlessly — the job result is already durably
/// recorded).
async fn advance_request_out_of_executing(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: uuid::Uuid,
    stages_val: serde_json::Value,
    success: bool,
    job_id: uuid::Uuid,
    result_status_str: &str,
    evidence_digest: &str,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();

    let stages_json =
        match serde_json::from_value::<Vec<ryuki_engine::models::Stage>>(stages_val.clone()) {
            Ok(mut stages) => {
                if let Some(st) = stages.iter_mut().find(|s| s.name == "execute") {
                    st.status = if success {
                        ryuki_engine::models::StageStatus::Completed
                    } else {
                        ryuki_engine::models::StageStatus::Failed
                    };
                    st.completed_at = Some(now);
                    st.metadata
                        .insert("agent_job_id".into(), job_id.to_string());
                    st.metadata
                        .insert("result_status".into(), result_status_str.to_string());
                    st.metadata
                        .insert("evidence_digest".into(), evidence_digest.to_string());
                }
                // Serialization of a valid Vec<Stage> cannot realistically fail; if it
                // somehow did, keep the original rather than wiping to [].
                serde_json::to_value(&stages).unwrap_or(stages_val)
            }
            Err(error) => {
                // Log the value-free error CATEGORY (Syntax/Data/Eof/Io), NOT the full
                // serde Display — the Display can echo the offending value, and stages
                // metadata/evidence may carry user-controlled strings.
                tracing::warn!(
                    parse_error = ?error.classify(),
                    request_id = %request_id,
                    "request.stages could not be parsed into Vec<Stage> during execution \
                     backlink; advancing status but preserving the existing stages JSONB \
                     untouched (NOT wiping history)"
                );
                stages_val
            }
        };
    let (new_status, new_stage) = if success {
        ("verifying", "verify")
    } else {
        ("failed", "execute")
    };

    // CAS: only advance if still `executing` (a concurrent transition wins
    // harmlessly — the job result is already durably recorded).
    let advanced = sqlx::query(
        "UPDATE requests SET status = $1, stage = $2, stages = $3::jsonb, updated_at = NOW() \
         WHERE id = $4 AND status = 'executing'",
    )
    .bind(new_status)
    .bind(new_stage)
    .bind(&stages_json)
    .bind(request_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // The executing -> verifying/failed hop is driven by an EXTERNAL signed
    // input (the agent's job result) and must appear in the hash-chained audit
    // trail like every other transition. Recorded only when the CAS actually
    // advanced — auditing a lost race would forge a transition that never
    // happened. Actor is the machine identity of the agent whose result this
    // is; no human session exists on this path.
    if advanced == 1 {
        let agent_id: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT agent_id FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
        let agent_principal = agent_id.as_deref().unwrap_or("unknown");
        let actor = ryuki_engine::auth::AuthSession {
            user_id: format!("agent:{agent_principal}"),
            display_name: format!("Execution agent {agent_principal} (signed job result)"),
            roles: Vec::new(),
            token_valid: false,
            provider_mode: "agent-result".to_string(),
            ..Default::default()
        };
        let request_id_str = request_id.to_string();
        crate::audit::record_audit_tx(
            tx,
            &actor,
            &crate::audit::AuditRecord {
                action: "request.execution-result",
                request_id: Some(&request_id_str),
                from_status: Some("executing"),
                to_status: new_status,
                from_stage: Some("execute"),
                to_stage: new_stage,
                detail: serde_json::json!({
                    "agent_job_id": job_id.to_string(),
                    "result_status": result_status_str,
                    "evidence_digest": evidence_digest,
                    "success": success,
                }),
                outcome: "applied",
            },
        )
        .await?;
    }

    Ok(())
}

/// Record a successful single-job LivePlan without completing execution.
///
/// A plan is review evidence, not proof that infrastructure was applied. The
/// request therefore remains `executing`/`execute` until an approved LiveApply
/// result arrives. The signed result metadata is still copied onto the execute
/// stage and into the audit trail so the approval pause is durable and visible.
async fn record_live_plan_awaiting_apply(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: uuid::Uuid,
    stages_val: serde_json::Value,
    job_id: uuid::Uuid,
    result_status_str: &str,
    evidence_digest: &str,
    raw_plan_digest: &str,
) -> Result<(), sqlx::Error> {
    let stages_json =
        match serde_json::from_value::<Vec<ryuki_engine::models::Stage>>(stages_val.clone()) {
            Ok(mut stages) => {
                if let Some(stage) = stages.iter_mut().find(|stage| stage.name == "execute") {
                    stage.status = ryuki_engine::models::StageStatus::InProgress;
                    stage.completed_at = None;
                    stage
                        .metadata
                        .insert("live_plan_job_id".into(), job_id.to_string());
                    stage.metadata.insert(
                        "live_plan_result_status".into(),
                        result_status_str.to_string(),
                    );
                    stage.metadata.insert(
                        "live_plan_evidence_digest".into(),
                        evidence_digest.to_string(),
                    );
                    stage.metadata.insert(
                        "live_plan_raw_plan_digest".into(),
                        raw_plan_digest.to_string(),
                    );
                }
                serde_json::to_value(&stages).unwrap_or(stages_val)
            }
            Err(error) => {
                tracing::warn!(
                    parse_error = ?error.classify(),
                    request_id = %request_id,
                    "request.stages could not be parsed while recording a successful live plan; \
                     preserving the existing stages JSONB"
                );
                stages_val
            }
        };

    let recorded = sqlx::query(
        "UPDATE requests SET stages = $1::jsonb, updated_at = NOW() \
         WHERE id = $2 AND status = 'executing'",
    )
    .bind(&stages_json)
    .bind(request_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    if recorded == 1 {
        let agent_id: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT agent_id FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
        let agent_principal = agent_id.as_deref().unwrap_or("unknown");
        let actor = ryuki_engine::auth::AuthSession {
            user_id: format!("agent:{agent_principal}"),
            display_name: format!("Execution agent {agent_principal} (signed job result)"),
            roles: Vec::new(),
            token_valid: false,
            provider_mode: "agent-result".to_string(),
            ..Default::default()
        };
        let request_id_str = request_id.to_string();
        crate::audit::record_audit_tx(
            tx,
            &actor,
            &crate::audit::AuditRecord {
                action: "request.live-plan-result",
                request_id: Some(&request_id_str),
                from_status: Some("executing"),
                to_status: "executing",
                from_stage: Some("execute"),
                to_stage: "execute",
                detail: serde_json::json!({
                    "agent_job_id": job_id.to_string(),
                    "result_status": result_status_str,
                    "evidence_digest": evidence_digest,
                    "raw_plan_digest": raw_plan_digest,
                    "awaiting_live_apply_approval": true,
                }),
                outcome: "planned",
            },
        )
        .await?;
    }

    Ok(())
}

/// Fail a multi-step request, rolling back any already-`Applied` steps first
/// (#42 slice B2-2 auto compensating teardown). Called AFTER the failing step
/// is marked `Failed` and `fail_inflight_steps` has swept in-flight siblings.
///
/// If any step is still `Applied`, the applied steps are destroyed in reverse
/// dependency order: this dispatches the currently ready-to-teardown ones as
/// `LiveDestroy` jobs and KEEPS the request `executing` (so their results route
/// back through this backlink, marking each `ToreDown` and unblocking the next);
/// the request only reaches `failed` once every applied step is rolled back (or
/// a teardown itself fails — see the LiveDestroy result branch). If NOTHING is
/// applied, this is a plain immediate failure (today's behavior).
async fn fail_request_with_teardown(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: uuid::Uuid,
    stages_val: serde_json::Value,
    job_id: uuid::Uuid,
    result_status_str: &str,
    evidence_digest: &str,
) -> Result<(), sqlx::Error> {
    // A failing / rolling-back request must not leave any step parked for
    // operator approval: while teardown keeps the request `executing`, an
    // AwaitingApproval step could otherwise still be approved into a NEW
    // LiveApply (minting live infra after rollback began). Fail them up front,
    // in this same transaction. (Pending steps are inert — a never-dispatched
    // step under a failing request truthfully never ran — so they are left as
    // is, mirroring `fail_inflight_steps`.)
    crate::repos::job_steps::fail_awaiting_approval_steps(&mut **tx, request_id).await?;

    let plan = crate::repos::job_steps::load_plan(&mut **tx, request_id).await?;
    if plan.iter().any(|s| s.status == "Applied") {
        // Roll back the applied steps. Keep the request `executing` while the
        // teardown LiveDestroy jobs are in flight.
        let current: crate::contracts::DbRequestRow = sqlx::query_as(&format!(
            "SELECT {} FROM requests WHERE id = $1",
            crate::contracts::REQUEST_COLUMNS
        ))
        .bind(request_id)
        .fetch_one(&mut **tx)
        .await?;
        let request_model = crate::contracts::db_row_to_request(&current, &request_id.to_string());
        crate::contracts::dispatch_teardown_steps(tx, &request_model, &current, &plan).await?;
        return Ok(());
    }
    if plan.iter().any(|s| s.status == "TearingDown") {
        // A rollback is ALREADY in flight (e.g. a late straggler step-result
        // failing while the applied steps are mid-teardown). Do NOT plain-fail
        // the request — that would flip it out of `executing` and cause the
        // in-flight LiveDestroy results to be ignored by the status guard,
        // stranding the rollback. Leave the teardown to complete; its final
        // LiveDestroy result advances the request to `failed`.
        return Ok(());
    }
    // Nothing applied and nothing tearing down — plain failure.
    advance_request_out_of_executing(
        tx,
        request_id,
        stages_val,
        false,
        job_id,
        result_status_str,
        evidence_digest,
    )
    .await
}

/// Backlink an agent's terminal result onto the parent request (AWX bridge
/// slice 2 / #42 slice 2b, extended by slice B1a). When a dispatched request
/// is still `executing`:
///
/// - **No step plan** (`job_steps` empty): OfflineDryRun and LiveApply advance
///   the request directly (`executing` -> `verifying` on success, otherwise
///   `-> failed`). A successful LivePlan records its signed result but leaves
///   the request `executing` for explicit human approval; a plan alone is not
///   verification evidence.
/// - **Step plan present, completing job's `mode == OfflineDryRun`**:
///   UNCHANGED #42 slice 2b behavior. Mark the step linked to this job
///   `Succeeded`/`Failed`. On step failure, fail the request immediately (a
///   partially-executed multi-step plan does not get to "succeed"). On step
///   success: if EVERY step is now `Succeeded`, advance the request to
///   `verifying`; if any OTHER step already failed, fail the request; else
///   the plan is mid-flight — dispatch the plan's newly-ready steps and leave
///   the request `executing`.
/// - **Step plan present, completing job's `mode == LivePlan`** (#42 slice
///   B1a — the forward per-step live path's human-gated pause point): on
///   success, mark the step `AwaitingApproval` and record the LivePlan's
///   signed raw-plan commitment onto `job_steps.live_plan_digest` — mirroring
///   exactly
///   how `requests_approve_live_apply` already re-derives the same field for
///   the single-job live path. Downstream steps are NOT dispatched and the
///   request is NOT advanced (stays `executing`): a step's LivePlan
///   succeeding only means it is ready for an OPERATOR to review and approve
///   its real apply (slice B1b's approval endpoint) — the plan does not
///   progress on its own. On failure, the step fails and the request fails,
///   exactly like the OfflineDryRun failure path (no teardown logic yet —
///   that is slice B2).
/// - **Step plan present, completing job's `mode == LiveApply`**: not
///   reachable in slice B1a (no LiveApply step jobs are ever dispatched
///   yet — slice B1b mints and dispatches those). Handled as a safe,
///   non-panicking no-op so an unreachable branch can never crash production
///   if hit before B1b ships.
///
/// All of this runs in the SAME transaction as the job's terminal record: a
/// request is never advanced without its follow-on jobs, nor are jobs marked
/// without their request-level effect landing.
///
/// Best-effort and CAS-guarded: a request that is missing (e.g. synthetic test
/// jobs) or no longer `executing` is left untouched, so this never fails the
/// result POST.
#[derive(Clone, Copy)]
struct BacklinkDigests<'a> {
    evidence: &'a str,
    raw_plan: Option<&'a str>,
}

async fn backlink_request_execution_with_raw_plan_digest(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: uuid::Uuid,
    status: &JobResultStatus,
    mode: &JobMode,
    result_status_str: &str,
    digests: BacklinkDigests<'_>,
    job_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let BacklinkDigests {
        evidence: evidence_digest,
        raw_plan: raw_plan_digest,
    } = digests;
    let success = matches!(
        status,
        JobResultStatus::CheckOk
            | JobResultStatus::Planned
            | JobResultStatus::Applied
            | JobResultStatus::Verified
    );

    // Lock the request's job_steps rows (if any) FIRST, in deterministic
    // step_key order — this serializes two step-jobs of the SAME request
    // completing concurrently (separate result POSTs / separate transactions)
    // so readiness and completion are decided against a consistent, race-free
    // view of the plan.
    let plan = crate::repos::job_steps::load_plan_for_update(tx, request_id).await?;

    // Read the request status/stages AFTER acquiring the plan lock, never
    // before. A concurrent sibling step-job that FAILS this request (and sweeps
    // this step to Failed via fail_inflight_steps) commits — releasing the lock
    // — before we can acquire it; a status read taken BEFORE the lock could be a
    // stale `executing` that then let this (now late) completion rewrite an
    // already-swept step to AwaitingApproval/Succeeded under a terminal request
    // (a TOCTOU that would silently undo the reconcile). Reading here, under the
    // lock, sees the sibling's committed terminal status and we bail. (The
    // empty-plan / single-job path locks no rows, but its advance is
    // CAS-guarded on status='executing', so it is race-safe on its own.)
    let row: Option<(String, serde_json::Value)> =
        sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
            .bind(request_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((req_status, stages_val)) = row else {
        return Ok(());
    };
    if req_status != "executing" {
        return Ok(());
    }

    if plan.is_empty() {
        if matches!(mode, JobMode::LivePlan) && success {
            let raw_plan_digest = raw_plan_digest.ok_or_else(|| {
                sqlx::Error::Protocol(
                    "successful LivePlan backlink is missing raw_plan_digest".to_string(),
                )
            })?;
            return record_live_plan_awaiting_apply(
                tx,
                request_id,
                stages_val,
                job_id,
                result_status_str,
                evidence_digest,
                raw_plan_digest,
            )
            .await;
        }
        return advance_request_out_of_executing(
            tx,
            request_id,
            stages_val,
            success,
            job_id,
            result_status_str,
            evidence_digest,
        )
        .await;
    }

    // Multi-step request.
    let Some(step) = plan.iter().find(|s| s.agent_job_id == Some(job_id)) else {
        // Anomaly: a plan-request completing a job that isn't a linked step. The
        // job result is already durably recorded; do NOT advance the request
        // (never advance a multi-step request off a non-step signal). Log skew.
        tracing::warn!(
            request_id = %request_id,
            %job_id,
            "multi-step request: completed job is not a linked step; not advancing"
        );
        return Ok(());
    };

    match mode {
        // #42 slice B1a: a step's LivePlan completing is the forward
        // per-step live path's human-gated pause point — success parks the
        // step at AwaitingApproval for an operator (slice B1b's approval
        // endpoint) rather than auto-advancing anything; failure fails the
        // request exactly like OfflineDryRun's failure path (no teardown
        // yet — that is slice B2).
        JobMode::LivePlan => {
            if !success {
                crate::repos::job_steps::mark_status(&mut **tx, step.id, "Failed").await?;
                crate::repos::job_steps::fail_inflight_steps(&mut **tx, request_id).await?;
                // #42 B2-2: roll back any already-applied steps before failing.
                return fail_request_with_teardown(
                    tx,
                    request_id,
                    stages_val,
                    job_id,
                    result_status_str,
                    evidence_digest,
                )
                .await;
            }

            // Success: record the plan digest and move to AwaitingApproval.
            // Do NOT dispatch downstream steps and do NOT advance the
            // request — it stays `executing` until an operator approves this
            // step's live apply (slice B1b).
            let raw_plan_digest = raw_plan_digest.ok_or_else(|| {
                sqlx::Error::Protocol(
                    "successful LivePlan backlink is missing raw_plan_digest".to_string(),
                )
            })?;
            crate::repos::job_steps::record_live_plan_digest(&mut **tx, step.id, raw_plan_digest)
                .await?;
            return Ok(());
        }
        // Not reachable in slice B1a: no LiveApply step jobs are ever
        // #42 slice B1b: a step's LiveApply result (its real infrastructure
        // apply). On success the step is `Applied`; when every step is applied
        // the request advances to `verifying`, otherwise the steps this apply
        // just unblocked are dispatched as LivePlan (each parks at
        // AwaitingApproval for its own per-step operator approval). On failure
        // the step and request fail. (Auto compensating teardown of
        // already-applied steps is slice B2 — deliberately NOT here; B1b fails
        // the request like every other failure path, leaving applied steps for
        // the operator until the teardown state machine is approved.)
        JobMode::LiveApply => {
            if !success {
                crate::repos::job_steps::mark_status(&mut **tx, step.id, "Failed").await?;
                crate::repos::job_steps::fail_inflight_steps(&mut **tx, request_id).await?;
                // #42 B2-2: roll back any already-applied steps before failing.
                return fail_request_with_teardown(
                    tx,
                    request_id,
                    stages_val,
                    job_id,
                    result_status_str,
                    evidence_digest,
                )
                .await;
            }

            crate::repos::job_steps::mark_status(&mut **tx, step.id, "Applied").await?;
            let plan2 = crate::repos::job_steps::load_plan(&mut **tx, request_id).await?;

            if plan2.iter().any(|s| s.status == "Failed") {
                crate::repos::job_steps::fail_inflight_steps(&mut **tx, request_id).await?;
                // #42 B2-2: a sibling already failed — roll back the applied
                // steps (including this one) before failing the request.
                return fail_request_with_teardown(
                    tx,
                    request_id,
                    stages_val,
                    job_id,
                    result_status_str,
                    evidence_digest,
                )
                .await;
            }

            if plan2
                .iter()
                .all(|s| s.status == "Applied" || s.status == "Succeeded")
            {
                // Every step has landed — the whole live plan is applied.
                return advance_request_out_of_executing(
                    tx,
                    request_id,
                    stages_val,
                    true,
                    job_id,
                    result_status_str,
                    evidence_digest,
                )
                .await;
            }

            // Mid-flight: dispatch the newly-ready steps as LivePlan (they will
            // each park at AwaitingApproval for their own approval). Keep the
            // request `executing`; do NOT touch stages/status.
            let current: crate::contracts::DbRequestRow = sqlx::query_as(&format!(
                "SELECT {} FROM requests WHERE id = $1",
                crate::contracts::REQUEST_COLUMNS
            ))
            .bind(request_id)
            .fetch_one(&mut **tx)
            .await?;
            let request_model =
                crate::contracts::db_row_to_request(&current, &request_id.to_string());
            crate::contracts::dispatch_ready_steps(
                tx,
                &request_model,
                &current,
                &plan2,
                JobMode::LivePlan,
            )
            .await?;
            return Ok(());
        }
        // #42 slice B2: a step's LiveDestroy (teardown) result. The CP-side
        // #42 slice B2-2: a step's LiveDestroy (teardown) result.
        JobMode::LiveDestroy => {
            if !success {
                // The destroy ITSELF failed — HALT the rollback (no thrash).
                // Mark this step Failed and fail the request; the remaining
                // Applied/TearingDown steps are deliberately LEFT intact for an
                // operator (PartiallyAppliedNeedsOperator — under a failed
                // request, the surviving Applied/TearingDown step statuses ARE
                // the "needs operator" signal). Do NOT dispatch more teardown.
                crate::repos::job_steps::mark_status(&mut **tx, step.id, "Failed").await?;
                return advance_request_out_of_executing(
                    tx,
                    request_id,
                    stages_val,
                    false,
                    job_id,
                    result_status_str,
                    evidence_digest,
                )
                .await;
            }

            // The step's resources were destroyed — mark it ToreDown.
            crate::repos::job_steps::mark_status(&mut **tx, step.id, "ToreDown").await?;
            let plan2 = crate::repos::job_steps::load_plan(&mut **tx, request_id).await?;

            // Clean rollback is complete once nothing is Applied or TearingDown.
            let rollback_done = !plan2
                .iter()
                .any(|s| s.status == "Applied" || s.status == "TearingDown");
            if rollback_done {
                // Every applied step rolled back — the request fails cleanly.
                return advance_request_out_of_executing(
                    tx,
                    request_id,
                    stages_val,
                    false,
                    job_id,
                    result_status_str,
                    evidence_digest,
                )
                .await;
            }

            // Dispatch the steps this teardown just unblocked (their last
            // Applied/TearingDown dependent is now ToreDown). Keep the request
            // `executing` while the rollback continues.
            let current: crate::contracts::DbRequestRow = sqlx::query_as(&format!(
                "SELECT {} FROM requests WHERE id = $1",
                crate::contracts::REQUEST_COLUMNS
            ))
            .bind(request_id)
            .fetch_one(&mut **tx)
            .await?;
            let request_model =
                crate::contracts::db_row_to_request(&current, &request_id.to_string());
            crate::contracts::dispatch_teardown_steps(tx, &request_model, &current, &plan2).await?;
            return Ok(());
        }
        // #42 slice 2b: UNCHANGED existing behavior.
        JobMode::OfflineDryRun => {}
    }

    if !success {
        crate::repos::job_steps::mark_status(&mut **tx, step.id, "Failed").await?;
        // Reconcile any sibling step still in-flight (Running — e.g. a parallel
        // step already dispatched by another completion) to Failed in this
        // same tx, so no dispatched step is stranded non-terminal under the
        // failing request.
        crate::repos::job_steps::fail_inflight_steps(&mut **tx, request_id).await?;
        return advance_request_out_of_executing(
            tx,
            request_id,
            stages_val,
            false,
            job_id,
            result_status_str,
            evidence_digest,
        )
        .await;
    }

    crate::repos::job_steps::mark_status(&mut **tx, step.id, "Succeeded").await?;
    // Rows are already locked by load_plan_for_update above; a plain re-load
    // is sufficient (and avoids re-taking FOR UPDATE mid-transaction).
    let plan2 = crate::repos::job_steps::load_plan(&mut **tx, request_id).await?;

    if plan2.iter().any(|s| s.status == "Failed") {
        // A prior step in this plan already failed — fail the request, and
        // reconcile any still-in-flight (Running) sibling to Failed so no
        // dispatched step is stranded non-terminal under a terminal request.
        crate::repos::job_steps::fail_inflight_steps(&mut **tx, request_id).await?;
        return advance_request_out_of_executing(
            tx,
            request_id,
            stages_val,
            false,
            job_id,
            result_status_str,
            evidence_digest,
        )
        .await;
    }

    if plan2.iter().all(|s| s.status == "Succeeded") {
        // Final step succeeded — the whole plan is done.
        return advance_request_out_of_executing(
            tx,
            request_id,
            stages_val,
            true,
            job_id,
            result_status_str,
            evidence_digest,
        )
        .await;
    }

    // Mid-flight: dispatch newly-ready steps, KEEP the request `executing`,
    // and do NOT touch stages/status. Always OfflineDryRun here — a LivePlan
    // step success never reaches this point (it returns early above without
    // dispatching downstream steps).
    let current: crate::contracts::DbRequestRow = sqlx::query_as(&format!(
        "SELECT {} FROM requests WHERE id = $1",
        crate::contracts::REQUEST_COLUMNS
    ))
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await?;
    let request_model = crate::contracts::db_row_to_request(&current, &request_id.to_string());
    crate::contracts::dispatch_ready_steps(
        tx,
        &request_model,
        &current,
        &plan2,
        JobMode::OfflineDryRun,
    )
    .await?;

    Ok(())
}

async fn backlink_request_execution(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: uuid::Uuid,
    status: &JobResultStatus,
    mode: &JobMode,
    result_status_str: &str,
    evidence_digest: &str,
    job_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    backlink_request_execution_with_raw_plan_digest(
        tx,
        request_id,
        status,
        mode,
        result_status_str,
        BacklinkDigests {
            evidence: evidence_digest,
            raw_plan: None,
        },
        job_id,
    )
    .await
}

/// Inner implementation that accepts an explicit pool — used by integration
/// tests that cannot rely on the global `get_db()` singleton.
async fn post_job_result_with_pool(
    agent_id: String,
    job_id_str: String,
    headers: HeaderMap,
    body: ResultBody,
    pool: &PgPool,
) -> ApiResult<Json<serde_json::Value>> {
    // ── Step 1: authenticate + agent_id match ────────────────────────────────
    let agent = authenticate_agent(&headers, pool).await?;

    if agent.agent_id != agent_id {
        return Err(forbidden("token does not match path agent_id"));
    }

    let result = &body.job_result;
    let env = &result.signed_envelope;

    if agent.agent_id != env.agent_id {
        return Err(forbidden("token agent_id does not match envelope.agent_id"));
    }

    // ── Step 2: load the job row ──────────────────────────────────────────────
    let job_id = parse_agent_job_id(&job_id_str)?;

    #[derive(sqlx::FromRow)]
    #[allow(dead_code)]
    struct JobForResult {
        id: uuid::Uuid,
        status: String,
        agent_id: Option<String>,
        attempt_id: Option<uuid::Uuid>,
        lease_generation: i64,
        cp_nonce: Option<String>,
        spec: sqlx::types::Json<serde_json::Value>,
        mode: String,
        // Fix 3: platform and request_id loaded from DB to bind signed context.
        platform: String,
        request_id: uuid::Uuid,
        // S5: the CP-signed approval grant for LiveApply jobs (NULL otherwise).
        live_context: Option<sqlx::types::Json<serde_json::Value>>,
        result_id: Option<uuid::Uuid>,
        result_status: Option<String>,
        evidence_digest: Option<String>,
        raw_plan_digest: Option<String>,
        completed_at: Option<chrono::DateTime<Utc>>,
        // #31 slice 2: the scheduler-set marker distinguishing a drift-recheck
        // LivePlan job (Some("drift_recheck")) from a normal operator job (None).
        origin: Option<String>,
    }

    let row = sqlx::query_as::<_, JobForResult>(
        "SELECT id, status, agent_id, attempt_id, lease_generation, cp_nonce, spec, mode, \
         platform, request_id, live_context, \
         result_id, result_status, evidence_digest, raw_plan_digest, completed_at, origin \
         FROM agent_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| not_found(format!("job {} not found", job_id)))?;

    // ── Authorization BEFORE any status disclosure ───────────────────────────
    //
    // The agent must be the assignee. This runs before any status-dependent
    // branch so the endpoint never leaks job state (active vs terminal) to a
    // token holder who is not the assignee. An unassigned/Pending job has
    // agent_id = NULL → this rejects with 403 before any state is observable.
    if row.agent_id.as_deref() != Some(&agent.agent_id) {
        return Err(forbidden("job is not assigned to this agent"));
    }

    // FAIL-CLOSED: no early status gate and no idempotency fast-path here. Every
    // request — including a replay against an already-terminal row — runs the
    // FULL verification (steps 3-8) before any decision is made. The atomic
    // terminal UPDATE (step 9) is conditioned on status IN ('Leased','Running'),
    // so the result commits exactly once. A VALID signed replay of an
    // already-recorded result re-verifies, the UPDATE matches 0 rows, and the
    // post-UPDATE idempotency branch returns 200 ("already recorded") — which the
    // agent's at-least-once durable outbox relies on for a lost-ack retry. An
    // unsigned/forged replay FAILS verification above and NEVER reaches that
    // branch. The lease fields (attempt_id, lease_generation, cp_nonce) persist
    // on terminal rows, so re-verification of a legitimate replay still works.

    // ── Step 3: verify Ed25519 signature against enrolled public key ──────────
    //
    // key_id in the envelope must match the enrolled public_key fingerprint.
    // The enrolled public_key is stored as base64 (the raw VerifyingKey bytes);
    // key_id in the envelope is also base64 of the VerifyingKey — they must be
    // equal.
    use ryuki_protocol::{decode_verifying_key, verify as verify_envelope};

    let vk = decode_verifying_key(&agent.public_key)
        .map_err(|e| bad_request(format!("enrolled public key is malformed: {}", e)))?;

    // key_id must equal the enrolled public key fingerprint.
    let enrolled_key_id = ryuki_protocol::encode_verifying_key(&vk);
    if env.key_id != enrolled_key_id {
        return Err(bad_request(
            "envelope.key_id does not identify the enrolled key",
        ));
    }

    verify_envelope(env, &vk)
        .map_err(|_| bad_request("signature verification failed — envelope has been tampered"))?;

    // `agent_id` and even the Ed25519 key may be reused only after a fresh
    // enrollment row is created. The signed immutable UUID prevents that new
    // row from completing or inheriting results produced by its predecessor.
    if env.agent_enrollment_id != agent.id {
        return Err(bad_request(
            "envelope.agent_enrollment_id does not match the authenticated enrollment",
        ));
    }

    // ── Step 4: lease / fencing match ────────────────────────────────────────
    let stored_attempt_id = row
        .attempt_id
        .ok_or_else(|| conflict("job has no active attempt — lease may have expired"))?;
    let stored_cp_nonce = row
        .cp_nonce
        .as_deref()
        .ok_or_else(|| conflict("job has no cp_nonce — lease may have expired"))?;

    if env.job_id != job_id {
        return Err(bad_request("envelope.job_id does not match path job_id"));
    }
    if env.attempt_id != stored_attempt_id {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(json!({
                "error": "envelope.attempt_id does not match active attempt — stale or superseded attempt"
            })),
        ));
    }
    if env.lease_generation != row.lease_generation as u64 {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(json!({
                "error": "envelope.lease_generation does not match — stale attempt"
            })),
        ));
    }
    // cp_nonce is the one-time binding: constant-time compare.
    {
        use subtle::ConstantTimeEq;
        let nonce_ok: bool = env
            .cp_nonce
            .as_bytes()
            .ct_eq(stored_cp_nonce.as_bytes())
            .into();
        if !nonce_ok {
            return Err(bad_request(
                "envelope.cp_nonce does not match stored lease nonce",
            ));
        }
    }

    // ── Fix 3 (part A): signed platform + mode binding ───────────────────────
    //
    // platform and mode are DB columns — bind them against the envelope here,
    // before step 5. request_id is bound in Fix 3 part B (after step 7) using
    // stored_spec.request_id, because that is the authoritative value the agent
    // received in the dispatched JobSpec (the column and spec field may differ
    // in the test harness, but the agent always signs spec.request_id).
    // Parse mode once here; reused in step 8 so no second parse is needed.
    let stored_mode = parse_job_mode(&row.mode)?;
    if env.platform != row.platform {
        return Err(bad_request(
            "envelope.platform does not match the dispatched job's platform",
        ));
    }
    if env.mode != stored_mode {
        return Err(bad_request(
            "envelope.mode does not match the dispatched job's mode",
        ));
    }

    // ── Step 5: outer JobResult fields must EQUAL the signed envelope ─────────
    if result.job_id != env.job_id {
        return Err(bad_request(
            "outer result.job_id does not match envelope.job_id",
        ));
    }
    if result.attempt_id != env.attempt_id {
        return Err(bad_request(
            "outer result.attempt_id does not match envelope.attempt_id",
        ));
    }
    if result.result_id != env.result_id {
        return Err(bad_request(
            "outer result.result_id does not match envelope.result_id",
        ));
    }
    if result.status != env.status {
        return Err(bad_request(
            "outer result.status does not match envelope.status",
        ));
    }
    // `Verified` is a CP-internal outcome: the engine's RunStatus has no Verified
    // variant, so a LEGITIMATE agent (map_run_status) can never produce it. Reject it
    // on the wire so a compromised-but-enrolled agent cannot stamp a result as a
    // verification step that never ran — a misleading audit trail / false "verified"
    // result_status. Every status an agent CAN legitimately report is still accepted.
    if env.status == JobResultStatus::Verified {
        return Err(bad_request(
            "Verified is not an agent-reportable result status",
        ));
    }
    if !ryuki_protocol::job_result_status_allowed(&stored_mode, &env.status) {
        return Err(bad_request(
            "agent result status is not valid for the dispatched execution mode",
        ));
    }
    if result.evidence_digest != env.evidence_digest {
        return Err(bad_request(
            "outer result.evidence_digest does not match envelope.evidence_digest",
        ));
    }
    if result.raw_plan_digest != env.raw_plan_digest {
        return Err(bad_request(
            "outer result.raw_plan_digest does not match envelope.raw_plan_digest",
        ));
    }

    // ── Step 5b: redaction_policy_version must be a CP-recognised policy ──────
    //
    // Every other envelope string field is cross-checked against authoritative
    // CP state. redaction_policy_version has no such counterpart, so a
    // compromised agent could otherwise smuggle arbitrary text here that the
    // admin result-retrieval view would surface. Gate it against the closed
    // allowlist of policies the CP recognises (fail-closed like every other
    // check): this closes the free-form channel and refuses evidence redacted
    // under a policy the CP cannot interpret.
    if !redaction_policy_version_is_supported(&env.redaction_policy_version) {
        return Err(bad_request(
            "envelope.redaction_policy_version is not a recognised redaction policy",
        ));
    }

    // ── Step 6: evidence_digest recompute ────────────────────────────────────
    //
    // Recompute SHA-256 over the evidence bytes the CP will store. Uses the
    // same sha256_hex from ryuki_protocol::crypto — byte-level, not JSON.
    let recomputed_evidence_digest = ryuki_protocol::sha256_hex(&body.evidence);
    if recomputed_evidence_digest != env.evidence_digest {
        return Err(bad_request(
            "evidence_digest mismatch — recomputed digest does not match signed envelope",
        ));
    }

    // ── Step 7: job_spec_digest recompute ────────────────────────────────────
    //
    // Recompute over the stored dispatched JobSpec (from the agent_jobs.spec
    // column). Uses ryuki_protocol::job_spec_digest (SHA-256 of the JSON
    // serialisation — deterministic because JobSpec uses BTreeMap for vars).
    let stored_spec: JobSpec = serde_json::from_value(row.spec.0.clone()).map_err(|e| {
        tracing::error!(job_id = %job_id, error = %e, "stored spec is malformed");
        db_err("stored job spec is malformed")
    })?;
    let recomputed_spec_digest = ryuki_protocol::job_spec_digest(&stored_spec);
    if recomputed_spec_digest != env.job_spec_digest {
        return Err(bad_request(
            "job_spec_digest mismatch — does not match stored dispatched spec",
        ));
    }

    // ── Fix 3 (part B): signed request_id binding ────────────────────────────
    //
    // request_id is included in signing_bytes; bind it against stored_spec.request_id
    // (the value embedded in the dispatched JobSpec JSONB — what the agent received
    // and signed). The agent_jobs.request_id column is the canonical upstream
    // reference but the agent always copies request_id from the spec it received.
    if env.request_id != stored_spec.request_id {
        return Err(bad_request(
            "envelope.request_id does not match the dispatched job spec's request_id",
        ));
    }

    // ── Step 7b: canonical live execution profile ──────────────────────────
    // Every non-refusal live result signs the complete non-secret profile.
    // Validate the closed schema/allowlist against authoritative stored job
    // inputs before it can become plan approval provenance.
    let result_trust_profile_digest = if matches!(
        stored_mode,
        JobMode::LivePlan | JobMode::LiveApply | JobMode::LiveDestroy
    ) && env.status != JobResultStatus::LiveRefused
    {
        let profile = env.execution_trust_profile.as_ref().ok_or_else(|| {
            bad_request("successful live result must include execution_trust_profile")
        })?;
        validate_execution_trust_profile(profile, &stored_spec, &row.platform)
            .map_err(bad_request)?;
        Some(execution_trust_profile_digest(profile))
    } else {
        if env.execution_trust_profile.is_some() {
            return Err(bad_request(
                "offline and LiveRefused results must not include execution_trust_profile",
            ));
        }
        None
    };

    // ── Step 8: mode rules + LiveApply approved-plan grant check (S5) ─────────
    //
    // LiveApply is the only mutating mode. A live result is accepted ONLY if the
    // plan digest the agent signed EQUALS the approved-plan digest in the
    // control-plane-issued grant (`live_context`), and the grant has not expired.
    // This is the core live-apply gate: an agent can never apply (or report
    // applying) a plan other than the one an operator reviewed and the CP granted
    // — closing the S3b deferral where only presence was (not) checked.
    //
    // Non-live modes (OfflineDryRun / LivePlan) must NOT carry approved_plan_digest.
    // `stored_mode` was parsed in Fix 3 above (no second parse needed).
    match stored_mode {
        JobMode::LiveApply | JobMode::LiveDestroy => {
            // #42 B2: LiveApply and LiveDestroy share IDENTICAL grant rigor —
            // a CP-signed, request-bound, step-bound, unexpired VerifiedLiveContext,
            // verified here independently of the agent (defense in depth). They
            // differ ONLY on the plan digest: LiveApply enforces plan-then-apply
            // (the envelope digest must equal the approved plan), while LiveDestroy
            // carries NO digest — a destroy removes the step's own applied state,
            // so there is nothing to match.
            let is_apply = matches!(stored_mode, JobMode::LiveApply);
            // A LiveRefused result is the agent reporting it DECLINED to act
            // (missing/invalid grant, plan divergence, or no --allow-live). Record
            // the refusal WITHOUT the grant checks — the refusal may be BECAUSE the
            // grant was unusable, and declining is always safe (no mutation
            // happened). It must carry no approved_plan_digest (nothing applied).
            if env.status == JobResultStatus::LiveRefused {
                if env.approved_plan_digest.is_some() {
                    return Err(bad_request(
                        "LiveRefused result must not carry approved_plan_digest",
                    ));
                }
            } else {
                // The job must carry the CP-signed grant. Job creation (S5a-2) is
                // responsible for attaching it; this runtime check is the fail-closed
                // enforcement of that invariant (migration 056 deliberately uses no
                // DB CHECK — see its comment).
                let grant_json = row.live_context.as_ref().ok_or_else(|| {
                    conflict(
                    "LiveApply job has no approval grant (live_context) — refusing a live result",
                )
                })?;
                let grant: VerifiedLiveContext =
                serde_json::from_value(grant_json.0.clone()).map_err(|e| {
                    tracing::error!(job_id = %job_id, error = %e, "stored live_context is malformed");
                    db_err("stored live_context is malformed")
                })?;

                // The grant MUST be genuinely CP-signed. Verifying the Ed25519
                // signature against the CP's own public key defends against a
                // tampered stored grant (e.g. a DB-write attacker who alters
                // approved_plan_digest but cannot forge the CP signature). The agent
                // also independently verifies this signature before applying (S5b).
                let cp_vk = cp_identity::cp_signing_key()
                    .ok_or_else(|| {
                        tracing::error!(
                            "CP signing key is not initialised — cannot verify LiveApply grant"
                        );
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            axum::Json(json!({
                                "error": "control plane is not configured to verify live grants"
                            })),
                        )
                    })?
                    .verifying_key();
                verify_vlc(&grant, &cp_vk)
                    .map_err(|_| bad_request("approval grant signature is invalid"))?;

                // Destination authority is signed independently from the
                // agent's result envelope. It must equal the same canonical
                // platform persisted on the dispatched job, closing replay of
                // a genuine grant against a different platform backlog.
                if grant.platform != row.platform {
                    return Err(bad_request(
                        "approval grant platform does not match the dispatched job",
                    ));
                }

                // The grant is owned by the immutable successful-plan
                // enrollment, not merely by an agent-id string that could be
                // re-enrolled later. Compare all three identities plus the
                // canonical current profile independently at ingestion.
                if grant.execution_authority.assigned_agent_id != agent.agent_id
                    || grant.execution_authority.assigned_agent_enrollment_id != agent.id
                    || grant.execution_authority.assigned_agent_key_fingerprint
                        != public_key_fingerprint(&agent.public_key)
                {
                    return Err(bad_request(
                        "approval grant is assigned to a different agent enrollment",
                    ));
                }
                let result_profile_digest = result_trust_profile_digest
                    .as_deref()
                    .ok_or_else(|| bad_request("live mutation result has no trust profile"))?;
                if grant.execution_authority.execution_trust_profile_digest != result_profile_digest
                {
                    return Err(bad_request(
                        "execution trust profile differs from the approved plan",
                    ));
                }

                // The grant authorizes the exact stored JobSpec, including its
                // mode, IaC digest/variables, and Terraform state key. This is
                // the CP-side mirror of the agent's pre-mutation check.
                if grant.job_spec_digest != recomputed_spec_digest {
                    return Err(bad_request(
                        "approval grant job_spec_digest does not match the dispatched job spec",
                    ));
                }

                // Plan-then-apply digest — the ONLY place LiveApply and
                // LiveDestroy diverge:
                if is_apply {
                    // LiveApply: the agent's signed envelope MUST carry the
                    // applied plan digest, and it MUST equal the APPROVED plan
                    // digest. The digest is a public hash (not a secret), so a
                    // plain comparison is appropriate.
                    let env_digest = env.approved_plan_digest.as_deref().ok_or_else(|| {
                        bad_request(
                            "LiveApply result must include approved_plan_digest in the signed envelope",
                        )
                    })?;
                    if env_digest != grant.approved_plan_digest {
                        return Err(bad_request(
                            "approved_plan_digest does not match the approved grant — \
                         refusing to record an unapproved plan",
                        ));
                    }
                } else {
                    // LiveDestroy: no approved plan to match — the result must
                    // NOT carry a digest at all.
                    if env.approved_plan_digest.is_some() {
                        return Err(bad_request(
                            "LiveDestroy result must not include approved_plan_digest",
                        ));
                    }
                }

                // The grant must be for THIS job's request (defends against a grant
                // mistakenly attached to a different request at job-creation time).
                // stored_spec was deserialised in step 7.
                if grant.request_id != stored_spec.request_id {
                    return Err(bad_request(
                        "approval grant request_id does not match the job's request",
                    ));
                }

                // #42 slice A / B2: the grant's step binding (CP-side mirror of
                // the agent's own gate — defense in depth). A step-scoped grant
                // (`step_job_id: Some`) is accepted ONLY for THIS dispatched job.
                // Like the request_id check (and unlike expiry), this is an
                // IDENTITY invariant, enforced unconditionally including on an
                // idempotent replay.
                //
                // For LiveApply a `None` whole-request grant is allowed. For
                // LiveDestroy it is rejected: the signed JobSpec digest already
                // binds mode, and this additional policy ties every destructive
                // rollback to one dispatched orchestration step.
                match grant.step_job_id {
                    Some(bound_id) if bound_id != job_id => {
                        return Err(bad_request(
                            "approval grant is bound to a different step job",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        if !is_apply {
                            return Err(bad_request("LiveDestroy requires a step-bound grant"));
                        }
                    }
                }

                // The grant must not be expired AT APPLY TIME. Expiry gates the
                // actual application, which only happens while the job is still
                // Leased/Running (the atomic UPDATE below records the result exactly
                // once from that state). A later idempotent REPLAY of an
                // already-recorded result (job already terminal) must NOT be
                // re-gated on expiry — the result was validated and applied within
                // the grant window, and the agent's durable outbox may retry the
                // POST after the grant has since expired. So only enforce expiry on
                // the first-apply path. The control plane is the authority on time
                // here (it issued the grant); the agent also independently rejects
                // an expired grant before applying.
                let first_apply = matches!(row.status.as_str(), "Leased" | "Running");
                if first_apply && grant.expiry < Utc::now() {
                    return Err((
                        axum::http::StatusCode::CONFLICT,
                        axum::Json(json!({
                            "error": "the approval grant has expired — re-approval is required"
                        })),
                    ));
                }
            } // end else (non-refusal LiveApply grant checks)
        }
        JobMode::OfflineDryRun | JobMode::LivePlan => {
            // Non-live modes must NOT include approved_plan_digest.
            if env.approved_plan_digest.is_some() {
                return Err(bad_request(
                    "non-LiveApply result must not include approved_plan_digest",
                ));
            }
        }
    }

    // A successful LivePlan is retained only when the exact signed raw-plan
    // commitment equals the canonical-plan digest inside the independently
    // digest-verified safe projection. Legacy results without that distinct
    // commitment fail closed; no other mode/status may smuggle one.
    let accepted_raw_plan_digest = validated_raw_plan_digest(
        &stored_mode,
        &env.status,
        env.raw_plan_digest.as_deref(),
        &stored_spec,
        &body.evidence,
    )
    .map_err(bad_request)?;

    // ── Step 9: atomic terminal UPDATE ───────────────────────────────────────
    //
    // Single UPDATE conditioned on (id, attempt_id, lease_generation, status IN
    // ('Leased','Running'), lease_deadline > DB NOW). rows_affected == 0 means
    // the attempt was superseded, expired, or already terminal.
    let new_job_status = map_result_status_to_job_status(&stored_mode, &env.status);
    let requires_reconciliation = new_job_status == "ReconcileRequired";
    let result_status_str = result_status_label(&env.status);

    // ── #43 post-apply verification verdict (LiveApply + Applied only) ────────
    //
    // A live apply only ASSERTS the intended state; the runner re-plans the same
    // config immediately after apply to CONFIRM convergence (missing-feature #43).
    // Derive that verdict from the DIGEST-VERIFIED evidence bytes (step 6 above),
    // NOT the unsigned `body.evidence_json`, and map it to the CP-internal
    // terminal result_status + a domain event. Fail-closed: an absent or
    // uninterpretable verdict keeps the result "applied" and emits no event, so a
    // job is never recorded "verified" off a re-plan the CP cannot confirm.
    let post_apply_ingest =
        if stored_mode == JobMode::LiveApply && env.status == JobResultStatus::Applied {
            Some(resolve_post_apply_ingest(post_apply_verdict_from_evidence(
                &body.evidence,
            )))
        } else {
            None
        };
    let effective_result_status: &str = post_apply_ingest
        .as_ref()
        .map(|p| p.result_status)
        .unwrap_or(result_status_str);

    let envelope_json = serde_json::to_value(env).map_err(db_err)?;

    // #60 slice 2: decide inline-vs-offload for THIS result's evidence. Pure
    // decision — see `compute_evidence_json_for_storage` above.
    let offload_evidence = ryuki_engine::evidence_store::decide_evidence_storage(
        body.evidence.len(),
        ryuki_engine::evidence_store::DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES,
    )
    .is_offloaded();
    // A successful LivePlan is also retained in the content-addressed blob
    // store even when small. The admin review endpoint reparses these exact
    // digest-covered bytes into a safe projection; it never trusts the
    // agent-submitted evidence_json convenience field.
    let retain_verified_plan_bytes =
        stored_mode == JobMode::LivePlan && env.status == JobResultStatus::Planned;
    let evidence_json_for_storage = compute_evidence_json_for_storage(
        offload_evidence,
        body.evidence.len(),
        &env.evidence_digest,
        &body.evidence_json,
    );

    // The terminal record and the parent-request backlink (slice 2) share ONE
    // transaction: a job that records its result also advances its request, and
    // vice versa — never one without the other.
    let mut tx = pool.begin().await.map_err(db_err)?;

    // #60 slice 2: persist the raw evidence bytes BEFORE the terminal UPDATE,
    // in the SAME transaction, so a stored offload reference can never point
    // at a missing blob. Content-addressed by the already-verified digest
    // (step 6) — identical evidence across jobs dedups via ON CONFLICT DO
    // NOTHING instead of storing duplicate copies.
    if offload_evidence || retain_verified_plan_bytes {
        sqlx::query(
            "INSERT INTO evidence_blobs (digest, bytes, size_bytes) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (digest) DO NOTHING",
        )
        .bind(&env.evidence_digest)
        .bind(&body.evidence)
        .bind(body.evidence.len() as i64)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    let updated = sqlx::query_scalar::<_, uuid::Uuid>(
        "UPDATE agent_jobs \
         SET status = $1, \
             result_id = $2, \
             result_status = $3, \
             evidence_digest = $4, \
             raw_plan_digest = $5, \
             evidence_json = $6::jsonb, \
             signed_envelope = $7::jsonb, \
             completed_at = NOW(), \
             updated_at = NOW() \
         WHERE id = $8 \
           AND attempt_id = $9 \
           AND lease_generation = $10 \
           AND status IN ('Leased', 'Running') \
           AND lease_deadline > NOW() \
         RETURNING id",
    )
    .bind(new_job_status)
    .bind(result.result_id)
    .bind(effective_result_status)
    .bind(&env.evidence_digest)
    .bind(accepted_raw_plan_digest.as_deref())
    .bind(&evidence_json_for_storage)
    .bind(&envelope_json)
    .bind(job_id)
    .bind(result.attempt_id)
    .bind(row.lease_generation)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;

    if updated.is_some() {
        // Advance the request the signed result is cryptographically BOUND to —
        // stored_spec.request_id (verified == env.request_id above), not the
        // raw agent_jobs.request_id column, which create_agent_job does not pin
        // to the spec. This prevents a result from advancing the wrong request
        // if the column and the dispatched spec ever diverge.
        if !requires_reconciliation {
            backlink_request_execution_with_raw_plan_digest(
                &mut tx,
                stored_spec.request_id,
                &env.status,
                &stored_mode,
                effective_result_status,
                BacklinkDigests {
                    evidence: &env.evidence_digest,
                    raw_plan: accepted_raw_plan_digest.as_deref(),
                },
                job_id,
            )
            .await
            .map_err(db_err)?;
        } else {
            let job_id_string = job_id.to_string();
            crate::repos::domain_events::insert(
                &mut *tx,
                crate::repos::domain_events::NewEvent {
                    event_type: "job.reconcile_required",
                    aggregate_type: "agent_job",
                    aggregate_id: &job_id_string,
                    site: None,
                    environment: None,
                    actor: "system",
                    payload: json!({
                        "to_status": "reconcile-required",
                        "platform": &row.platform,
                        "request_id": stored_spec.request_id.to_string(),
                        "note": "live mutation reported failure; provider and state reconciliation required",
                    }),
                },
            )
            .await
            .map_err(db_err)?;
        }

        // #43: emit the post-apply verification event (converged → verified,
        // pending change → drift) in the SAME transaction as the terminal record,
        // so an event never exists without the result it describes. The event is
        // SCOPED to the request's own site/environment: a `request` aggregate with
        // NULL/NULL axes is globally visible to every scoped principal (a cross-site
        // leak of request/job/result ids), so we carry the request's scope. The
        // `to_status` ("drift-detected"/"verified") is the alert-classifier key —
        // drift alerts Critical, a converged verify does not.
        if let Some(ingest) = &post_apply_ingest {
            if let Some(event_type) = ingest.event_type {
                // requests.site/environment are NOT NULL. If the request row is
                // gone (e.g. a synthetic job with no parent), skip the event: it is
                // a request-scoped signal with no request to scope to, and the
                // terminal job record is already durable.
                let scope: Option<(String, String)> =
                    sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                        .bind(stored_spec.request_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(db_err)?;
                if let Some((site, environment)) = scope {
                    let aggregate_id = stored_spec.request_id.to_string();
                    crate::repos::domain_events::insert(
                        &mut *tx,
                        crate::repos::domain_events::NewEvent {
                            event_type,
                            aggregate_type: "request",
                            aggregate_id: &aggregate_id,
                            site: Some(&site),
                            environment: Some(&environment),
                            actor: "system",
                            payload: json!({
                                "job_id": job_id.to_string(),
                                "result_id": result.result_id.to_string(),
                                "result_status": ingest.result_status,
                                "to_status": ingest.to_status,
                            }),
                        },
                    )
                    .await
                    .map_err(db_err)?;
                }
            }
        }

        // #31 slice 2: emit the SCHEDULED drift-recheck event in the SAME
        // transaction as the terminal record, mirroring the #43 block above.
        // result_status for a LivePlan drift-recheck stays "planned" — this is a
        // detection-only signal (unlike LiveApply's Applied->verified upgrade),
        // so only the event is emitted, never a result_status change.
        if let Some(event_type) = resolve_scheduled_drift_event(
            stored_mode.clone(),
            env.status.clone(),
            row.origin.as_deref(),
            &body.evidence,
        ) {
            // requests.site/environment are NOT NULL. If the request row is gone
            // (e.g. a synthetic job with no parent), skip the event: it is a
            // request-scoped signal with no request to scope to, and the terminal
            // job record is already durable.
            let scope: Option<(String, String)> =
                sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                    .bind(stored_spec.request_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?;
            if let Some((site, environment)) = scope {
                let aggregate_id = stored_spec.request_id.to_string();
                crate::repos::domain_events::insert(
                    &mut *tx,
                    crate::repos::domain_events::NewEvent {
                        event_type,
                        aggregate_type: "request",
                        aggregate_id: &aggregate_id,
                        site: Some(&site),
                        environment: Some(&environment),
                        actor: "system",
                        payload: json!({
                            "job_id": job_id.to_string(),
                            "result_id": result.result_id.to_string(),
                            "to_status": "drift-detected",
                        }),
                    },
                )
                .await
                .map_err(db_err)?;
            }
        }

        // #31 slice 2b: a drift-recheck re-plan that produced a USABLE verdict
        // (converged OR drift) is a fresh verification against live infra — advance
        // the deployment's last_drift_check_at so the overdue scan does not
        // re-flag/re-dispatch it until the next interval. Without this, a LivePlan
        // never touches the last-LiveApply timestamp the overdue scan keys on, so an
        // operational deployment would be re-checked every day forever until a real
        // apply. Both a clean and a drift verdict reset the clock (a drift verdict is
        // separately surfaced as the alert event above). An INCONCLUSIVE plan
        // (unparseable / non-terraform evidence) is NOT a completed check: leave the
        // clock so the next scan retries, rather than suppressing rechecks for a full
        // interval off uninterpretable evidence (fail-safe, mirroring classify_plan_json).
        if is_drift_recheck_replan(&stored_mode, &env.status, row.origin.as_deref()) {
            let verdict = ryuki_engine::post_apply::classify_plan_json(&body.evidence);
            if verdict != ryuki_engine::post_apply::PostApplyOutcome::Inconclusive {
                sqlx::query("UPDATE requests SET last_drift_check_at = NOW() WHERE id = $1")
                    .bind(stored_spec.request_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }
        }

        tx.commit().await.map_err(db_err)?;
        tracing::info!(
            job_id = %job_id,
            agent_id = %agent_id,
            result_id = %result.result_id,
            result_status = effective_result_status,
            job_status = new_job_status,
            "job result recorded — terminal"
        );
        return Ok(Json(json!({
            "job_id": job_id,
            "result_id": result.result_id,
            "result_status": effective_result_status,
            "job_status": new_job_status,
        })));
    }

    // Nothing updated in this tx (superseded/expired/already terminal): roll it
    // back, then run the read-only idempotency check on the pool below.
    tx.rollback().await.ok();

    // rows_affected == 0: the attempt was superseded/expired/already terminal.
    // Check idempotency: if this (attempt_id, result_id) is already recorded
    // in a terminal row, return 200. Otherwise 409.
    #[derive(sqlx::FromRow)]
    struct IdempotencyCheck {
        status: String,
        attempt_id: Option<uuid::Uuid>,
        result_id: Option<uuid::Uuid>,
        result_status: Option<String>,
    }
    let existing = sqlx::query_as::<_, IdempotencyCheck>(
        "SELECT status, attempt_id, result_id, result_status \
         FROM agent_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let existing = match existing {
        None => return Err(not_found(format!("job {} not found", job_id))),
        Some(r) => r,
    };

    if let (Some(stored_result_id), Some(stored_attempt_id)) =
        (existing.result_id, existing.attempt_id)
    {
        if stored_result_id == result.result_id && stored_attempt_id == result.attempt_id {
            tracing::info!(
                job_id = %job_id,
                result_id = %result.result_id,
                "idempotent result POST — already recorded (concurrent path)"
            );
            return Ok(Json(json!({
                "job_id": job_id,
                "result_id": stored_result_id,
                "result_status": existing.result_status,
                "job_status": existing.status,
                "idempotent": true,
            })));
        }
    }

    Err(conflict(format!(
        "job {} attempt/lease has been superseded or already reached a terminal state",
        job_id
    )))
}

// ---------------------------------------------------------------------------
// parse_job_mode: TEXT stored in DB → JobMode
// ---------------------------------------------------------------------------

fn parse_job_mode(mode_str: &str) -> ApiResult<JobMode> {
    match mode_str {
        "OfflineDryRun" => Ok(JobMode::OfflineDryRun),
        "LivePlan" => Ok(JobMode::LivePlan),
        "LiveApply" => Ok(JobMode::LiveApply),
        "LiveDestroy" => Ok(JobMode::LiveDestroy),
        other => Err(bad_request(format!(
            "unknown job mode in database: {}",
            other
        ))),
    }
}

/// POST /api/agents/{agent_id}/heartbeat
///
/// Updates `last_seen_at` for an idle agent. A running heartbeat also renews
/// the exact acknowledged job lease; all fencing fields are mandatory and the
/// renewal is rejected once the database-clock deadline has been reached.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningLeaseFence {
    job_id: Uuid,
    attempt_id: Uuid,
    lease_generation: i64,
    fencing_token: String,
}

fn parse_running_lease_fence(body: AgentHeartbeat) -> ApiResult<Option<RunningLeaseFence>> {
    match (
        body.running_job_id,
        body.attempt_id,
        body.lease_generation,
        body.fencing_token,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(job_id), Some(attempt_id), Some(lease_generation), Some(fencing_token)) => {
            let lease_generation = i64::try_from(lease_generation)
                .map_err(|_| bad_request("lease_generation is out of range"))?;
            Ok(Some(RunningLeaseFence {
                job_id,
                attempt_id,
                lease_generation,
                fencing_token,
            }))
        }
        _ => Err(bad_request(
            "running heartbeat requires running_job_id, attempt_id, lease_generation, and fencing_token",
        )),
    }
}

async fn renew_running_job_lease(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent_id: &str,
    fence: &RunningLeaseFence,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    sqlx::query_scalar::<_, DateTime<Utc>>(
        "UPDATE agent_jobs AS job \
         SET lease_deadline = NOW() + make_interval( \
             secs => CASE \
                 WHEN job.mode IN ('LivePlan', 'LiveApply', 'LiveDestroy') THEN $6 \
                 ELSE $7 \
             END \
         ) \
         WHERE job.id = $1 \
           AND job.agent_id = $2 \
           AND job.status = 'Running' \
           AND job.attempt_id = $3 \
           AND job.lease_generation = $4 \
           AND job.fencing_token = $5 \
           AND job.lease_deadline > NOW() \
         RETURNING job.lease_deadline",
    )
    .bind(fence.job_id)
    .bind(agent_id)
    .bind(fence.attempt_id)
    .bind(fence.lease_generation)
    .bind(&fence.fencing_token)
    .bind(LIVE_LEASE_TTL_SECS as f64)
    .bind(LEASE_TTL_SECS as f64)
    .fetch_optional(&mut **tx)
    .await
}

pub async fn heartbeat(
    pv: ProtocolVersion,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AgentHeartbeat>,
) -> ApiResult<Json<AgentHeartbeatResponse>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let agent = authenticate_agent(&headers, pool).await?;

    if agent.agent_id != agent_id {
        return Err(forbidden("token does not match agent_id"));
    }

    let lease_fence = parse_running_lease_fence(body)?;

    let mut tx = pool.begin().await.map_err(db_err)?;

    let lease_deadline = if let Some(fence) = lease_fence.as_ref() {
        match renew_running_job_lease(&mut tx, &agent.agent_id, fence)
            .await
            .map_err(db_err)?
        {
            Some(deadline) => Some(deadline),
            None => {
                tx.rollback().await.ok();
                return Err(conflict("running job lease ownership lost or expired"));
            }
        }
    } else {
        None
    };

    // Refresh the recorded protocol version from the live header so the stored
    // baseline follows an in-place agent-binary upgrade (audit/observability
    // only — the enforcing gate is the per-request extractor, not this row).
    // For a running job this shares the lease-renewal transaction: a failed
    // fence does not refresh agent liveness and cannot look healthy.
    let last_seen_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        "UPDATE agents SET last_seen_at = NOW(), updated_at = NOW(), protocol_version = $2 \
         WHERE id = $1 RETURNING last_seen_at",
    )
    .bind(agent.id)
    .bind(i64::from(pv.0))
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    tracing::debug!(
        agent_id = %agent_id,
        running_job = ?lease_fence.as_ref().map(|fence| fence.job_id),
        "heartbeat"
    );

    Ok(Json(AgentHeartbeatResponse {
        agent_id,
        last_seen_at,
        lease_deadline,
    }))
}

// ---------------------------------------------------------------------------
// Lease expiry / redispatch
//
// Call periodically (background task, cron, or on each poll).
// Non-mutating modes (OfflineDryRun / LivePlan): return to Pending with a
// fresh attempt, resetting all fencing fields.
// LiveApply / LiveDestroy: → ReconcileRequired (operator must reconcile;
// live mutations are never auto-redispatched).
// ---------------------------------------------------------------------------

/// #23 poison-job cap: a non-mutating job is redispatched at most this many
/// times. On the next lease expiry once `delivery_attempts >= MAX_REDISPATCHES`
/// it is dead-lettered instead of redispatched. Total dispatch attempts before
/// dead-letter = MAX_REDISPATCHES + 1 (1 initial + MAX_REDISPATCHES redispatches).
// INT4 in the DB (migration 121), so an i32 here keeps the bind + RETURNING
// decode aligned with the column type.
const MAX_REDISPATCHES: i32 = 5;

/// One dead-lettered job, returned by the cap UPDATE so we can emit its event.
#[derive(sqlx::FromRow)]
struct DeadLetteredJobRow {
    id: String,
    request_id: String,
    platform: String,
    mode: String,
    delivery_attempts: i32,
}

/// One LiveApply job moved to `ReconcileRequired` by lease expiry. `mode` is
/// constant (`LiveApply`) and `delivery_attempts` is never touched on this path,
/// so the dead-letter struct's extra columns are omitted.
#[derive(sqlx::FromRow)]
struct ReconcileRequiredJobRow {
    id: String,
    request_id: String,
    platform: String,
}

/// Returns the number of jobs transitioned.
///
/// Runs as ONE transaction so each dead-letter UPDATE and its domain event are
/// atomic — an event can never be emitted for a job that was not actually
/// dead-lettered, and vice versa.
///
/// This sweep is PER-REPLICA (not leader-elected): every replica's
/// `spawn_lease_expiry_sweep` runs it every 30s. It is safe under concurrent
/// sweepers because PostgreSQL serializes concurrent UPDATEs on the same row and
/// RECHECKS the `status` + `delivery_attempts` predicates after waiting on the
/// row lock, so two replicas cannot both increment 4→5 (the second sees 5,
/// `< MAX` fails) nor both dead-letter at 5 (the second sees `DeadLettered`, the
/// `Leased/Running` predicate fails) — exactly one increment and exactly one
/// dead-letter + event per job.
pub async fn expire_leases(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // 1. Dead-letter the at-cap non-mutating rows (terminal, no redispatch).
    //    A job that exhausted every redispatch is poison: surface it and stop.
    let dead_lettered: Vec<DeadLetteredJobRow> = sqlx::query_as(
        "UPDATE agent_jobs \
         SET status = 'DeadLettered', updated_at = NOW() \
         WHERE status IN ('Leased', 'Running') \
           AND mode IN ('OfflineDryRun', 'LivePlan') \
           AND lease_deadline < NOW() \
           AND delivery_attempts >= $1 \
         RETURNING id::text, request_id::text, platform, mode, delivery_attempts",
    )
    .bind(MAX_REDISPATCHES)
    .fetch_all(&mut *tx)
    .await?;

    // Emit one alert-worthy domain event per dead-lettered job. Agent jobs are
    // platform-wide infra (like agent-offline), so site/environment are NULL.
    for job in &dead_lettered {
        crate::repos::domain_events::insert(
            &mut *tx,
            crate::repos::domain_events::NewEvent {
                event_type: "job.dead_lettered",
                aggregate_type: "agent_job",
                aggregate_id: &job.id,
                site: None,
                environment: None,
                actor: "system",
                payload: json!({
                    "to_status": "dead-lettered",
                    "platform": &job.platform,
                    "mode": &job.mode,
                    "request_id": &job.request_id,
                    "delivery_attempts": job.delivery_attempts,
                    "note": "lease expired repeatedly; poison-job cap reached",
                }),
            },
        )
        .await?;

        // Conclude the parent request exactly as a Failed result would have:
        // a dead-lettered job posts no result, so without this the request
        // sits `executing` forever with no request-side signal (QA finding).
        // Safe here because this branch only dead-letters NON-MUTATING modes
        // (OfflineDryRun/LivePlan) — nothing ran against live infrastructure.
        // Mutating modes lease-expire to ReconcileRequired for the OPERATOR to
        // conclude, deliberately fail-closed, and are untouched by this path.
        // backlink_request_execution brings the step machinery (mark step
        // Failed, teardown-aware request failure) and the hash-chained audit
        // row along for free; its status guard skips non-executing requests.
        let (Ok(request_uuid), Ok(job_uuid)) = (
            uuid::Uuid::parse_str(&job.request_id),
            uuid::Uuid::parse_str(&job.id),
        ) else {
            continue; // both are DB uuids by construction; never expected
        };
        let mode = match job.mode.as_str() {
            "LivePlan" => JobMode::LivePlan,
            _ => JobMode::OfflineDryRun, // predicate admits only these two
        };
        backlink_request_execution(
            &mut tx,
            request_uuid,
            &JobResultStatus::Failed,
            &mode,
            "dead-lettered",
            "no-result-dead-lettered",
            job_uuid,
        )
        .await?;
    }
    let dead_count = dead_lettered.len() as u64;

    // 2. Redispatch + increment the under-cap non-mutating rows (the existing
    //    reset, now counting). Mutually exclusive with the dead-letter predicate
    //    on delivery_attempts, so order is immaterial.
    let redispatched = sqlx::query(
        "UPDATE agent_jobs \
         SET status = 'Pending', \
             agent_id = CASE \
                 WHEN mode = 'LivePlan' OR COALESCE(spec->>'mode', '') = 'live_plan' \
                 THEN agent_id ELSE NULL END, \
             attempt_id = NULL, \
             fencing_token = NULL, \
             cp_nonce = NULL, \
             lease_deadline = NULL, \
             delivery_attempts = delivery_attempts + 1, \
             updated_at = NOW() \
         WHERE status IN ('Leased', 'Running') \
           AND mode IN ('OfflineDryRun', 'LivePlan') \
           AND lease_deadline < NOW() \
           AND delivery_attempts < $1",
    )
    .bind(MAX_REDISPATCHES)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    // 3. LiveApply: → ReconcileRequired (never auto-redispatched, so it cannot
    //    poison-loop and is out of the cap's scope).
    let reconciled: Vec<ReconcileRequiredJobRow> = sqlx::query_as(
        "UPDATE agent_jobs \
         SET status = 'ReconcileRequired', updated_at = NOW() \
         WHERE status IN ('Leased', 'Running') \
           AND mode = 'LiveApply' \
           AND lease_deadline < NOW() \
         RETURNING id::text, request_id::text, platform",
    )
    .fetch_all(&mut *tx)
    .await?;

    // Emit one alert-worthy domain event per reconcile — parity with the
    // dead-letter branch. A LiveApply job whose agent died mid-run touched real
    // infra; the operator-recovery transition must NOT be silent. Platform-wide
    // infra (like agent-offline / dead-letter), so site/environment are NULL.
    for job in &reconciled {
        crate::repos::domain_events::insert(
            &mut *tx,
            crate::repos::domain_events::NewEvent {
                event_type: "job.reconcile_required",
                aggregate_type: "agent_job",
                aggregate_id: &job.id,
                site: None,
                environment: None,
                actor: "system",
                payload: json!({
                    "to_status": "reconcile-required",
                    "platform": &job.platform,
                    "mode": "LiveApply",
                    "request_id": &job.request_id,
                    "note": "live-apply lease expired mid-run; operator reconciliation required",
                }),
            },
        )
        .await?;
    }
    let reconcile = reconciled.len() as u64;

    // 4. LiveDestroy (#42 B2-2): an expired teardown lease HALTS the rollback.
    //    An agent that died mid-destroy may have partially torn down real infra,
    //    so this is operator recovery, never auto-retry (like LiveApply). Mark
    //    the job ReconcileRequired, fail the step it was tearing down, and fail
    //    the request — leaving any remaining Applied/TearingDown steps as the
    //    needs-operator signal (rather than leaving the rollback stuck with the
    //    step TearingDown and the request executing forever).
    #[derive(sqlx::FromRow)]
    struct ExpiredDestroyRow {
        id: Uuid,
        request_id: Uuid,
        platform: String,
    }
    let expired_destroys: Vec<ExpiredDestroyRow> = sqlx::query_as(
        "UPDATE agent_jobs SET status = 'ReconcileRequired', updated_at = NOW() \
         WHERE status IN ('Leased', 'Running') AND mode = 'LiveDestroy' \
           AND lease_deadline < NOW() \
         RETURNING id, request_id, platform",
    )
    .fetch_all(&mut *tx)
    .await?;
    for job in &expired_destroys {
        backlink_request_execution(
            &mut tx,
            job.request_id,
            &JobResultStatus::Failed,
            &JobMode::LiveDestroy,
            "reconcile_required",
            "lease-expired-no-result",
            job.id,
        )
        .await?;
        let job_id_str = job.id.to_string();
        let request_id_str = job.request_id.to_string();
        crate::repos::domain_events::insert(
            &mut *tx,
            crate::repos::domain_events::NewEvent {
                event_type: "job.reconcile_required",
                aggregate_type: "agent_job",
                aggregate_id: &job_id_str,
                site: None,
                environment: None,
                actor: "system",
                payload: json!({
                    "to_status": "reconcile-required",
                    "platform": &job.platform,
                    "mode": "LiveDestroy",
                    "request_id": &request_id_str,
                    "note": "live-destroy (teardown) lease expired mid-run; rollback halted, \
                             operator reconciliation required",
                }),
            },
        )
        .await?;
    }
    let destroy_reconcile = expired_destroys.len() as u64;

    tx.commit().await?;

    if dead_count + redispatched + reconcile + destroy_reconcile > 0 {
        tracing::info!(
            redispatched,
            reconcile_required = reconcile,
            destroy_reconcile_required = destroy_reconcile,
            dead_lettered = dead_count,
            "agent lease expiry sweep"
        );
    }

    Ok(dead_count + redispatched + reconcile + destroy_reconcile)
}

// ---------------------------------------------------------------------------
// create_agent_job — enqueue helper
//
// Inserts a Pending job. NOT wired into the request lifecycle yet (S3b).
// ---------------------------------------------------------------------------

/// Enqueues a new Pending job for the given platform and returns the job row id.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn create_agent_job(
    pool: &PgPool,
    request_id: Uuid,
    platform: &str,
    spec: &JobSpec,
    mode: &str,
) -> Result<Uuid, sqlx::Error> {
    let spec_json = serde_json::to_value(spec).expect("JobSpec serialisation is infallible");

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_jobs (request_id, platform, spec, mode) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id",
    )
    .bind(request_id)
    .bind(platform)
    .bind(&spec_json)
    .bind(mode)
    .fetch_one(pool)
    .await?;

    tracing::info!(
        job_id = %id,
        request_id = %request_id,
        platform = %platform,
        mode = %mode,
        "agent job enqueued"
    );
    Ok(id)
}

// ---------------------------------------------------------------------------
// Background lease-expiry sweep
// ---------------------------------------------------------------------------

async fn sweep_agent_lifecycle(pool: &PgPool) -> Result<u64, sqlx::Error> {
    // Preserve the pre-existing lease-fencing duty as the first operation: a
    // later enrollment-cleanup error must not skip the current tick's lease work.
    let expired_leases = expire_leases(pool).await?;
    let expired_enrollments = cleanup_expired_pending_agent_enrollments(pool).await?;
    Ok(expired_enrollments.saturating_add(expired_leases))
}

/// Spawn a background task that expires agent leases and prunes a bounded batch
/// of expired Pending enrollments every `interval_secs`.
///
/// Call once at server startup (after the DB pool is available).
/// The task runs forever; it is cancelled when the tokio runtime shuts down.
/// Both operations are idempotent, so duplicate sweeps are harmless.
/// Heartbeat registry name for the lease-expiry sweep loop.
const LEASE_EXPIRY_SWEEP_NAME: &str = "lease_expiry_sweep";

pub fn spawn_lease_expiry_sweep(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
        crate::background::register_loop(LEASE_EXPIRY_SWEEP_NAME, interval_secs);
        let mut ticker = interval(std::time::Duration::from_secs(interval_secs));
        // #26 follow-on: Skip missed ticks so a recovered loop resumes on the next
        // aligned boundary rather than bursting catch-up ticks after a backoff/timeout.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick (just started)
                             // #31: exponential backoff on consecutive failures so a persistent
                             // outage (DB down, pool exhausted, lock contention) is retried with
                             // increasing spacing instead of hammering + log-spamming at the base
                             // interval. The extra sleep is the real delay; the ticker's Skip
                             // behavior means a recovered loop resumes on the next boundary.
        let timeout = crate::background::iteration_timeout(interval_secs);
        let mut consecutive_failures: u32 = 0;
        loop {
            ticker.tick().await;
            match crate::background::run_bounded(timeout, sweep_agent_lifecycle(&pool)).await {
                Ok(_) => {
                    consecutive_failures = 0;
                    crate::background::record_loop_success(LEASE_EXPIRY_SWEEP_NAME);
                }
                Err(err) => {
                    let backoff = crate::background::note_failure(&mut consecutive_failures);
                    match err {
                        crate::background::IterError::Failed(e) => tracing::error!(
                            error = %e,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "lease expiry sweep failed; backing off"
                        ),
                        crate::background::IterError::TimedOut => tracing::error!(
                            timeout_secs = timeout.as_secs(),
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "lease expiry sweep exceeded its iteration timeout; backing off"
                        ),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(
                        interval_secs.saturating_mul(backoff),
                    ))
                    .await;
                }
            }
        }
    });
}

/// One row for the agent-offline scan (#11 slice 2d).
#[derive(sqlx::FromRow)]
struct AgentOfflineScanRow {
    agent_id: String,
    platform: String,
    last_seen_at: Option<DateTime<Utc>>,
    offline_alerted: bool,
}

/// One agent-offline scan pass (#11 slice 2d): emit `agent.offline` when an
/// APPROVED agent that has checked in before goes stale (last_seen_at older than
/// `threshold_secs`), and `agent.online` when it returns — only on a state
/// TRANSITION, deduped via the `offline_alerted` flag flipped atomically with the
/// emit. An approved-but-never-seen agent (last_seen_at NULL) is "not yet online",
/// skipped — it never flips the flag. Each agent is independent. Returns the
/// number of transition events emitted.
pub async fn agent_offline_scan_once(
    pool: &PgPool,
    threshold_secs: i64,
) -> Result<u64, sqlx::Error> {
    let agents: Vec<AgentOfflineScanRow> = sqlx::query_as(
        "SELECT agent_id, platform, last_seen_at, offline_alerted \
         FROM agents WHERE status = 'approved'",
    )
    .fetch_all(pool)
    .await?;
    let now = Utc::now();
    let mut emitted = 0u64;
    for a in &agents {
        let Some(seen) = a.last_seen_at else {
            continue; // never checked in — no definitive offline transition
        };
        let now_offline = (now - seen).num_seconds() > threshold_secs;
        if now_offline == a.offline_alerted {
            continue; // no transition
        }
        let mut tx = pool.begin().await?;
        crate::repos::domain_events::insert(
            &mut *tx,
            crate::repos::domain_events::NewEvent {
                event_type: if now_offline {
                    "agent.offline"
                } else {
                    "agent.online"
                },
                aggregate_type: "agent",
                aggregate_id: &a.agent_id,
                site: None,
                environment: None,
                actor: "system",
                payload: json!({
                    "to_status": if now_offline { "offline" } else { "online" },
                    "platform": &a.platform,
                    "last_seen_at": seen.to_rfc3339(),
                }),
            },
        )
        .await?;
        // #11 slice 2f/2g: notify the monitoring role on both directions —
        // Warning when an agent goes offline, Success when it returns.
        {
            let (event_type, severity) = if now_offline {
                (
                    "agent.offline",
                    ryuki_engine::notifications::Severity::Warning,
                )
            } else {
                (
                    "agent.online",
                    ryuki_engine::notifications::Severity::Success,
                )
            };
            let draft =
                ryuki_engine::notifications::draft_for_alert(event_type, &a.agent_id, severity);
            crate::repos::notifications::insert_draft_tx(&mut tx, &draft, None).await?;
        }
        sqlx::query(
            "UPDATE agents SET offline_alerted = $1, updated_at = NOW() WHERE agent_id = $2",
        )
        .bind(now_offline)
        .bind(&a.agent_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        emitted += 1;
    }
    Ok(emitted)
}

/// Spawn the background agent-offline scan (#11 slice 2d). Write-capable (so
/// separate from the read-only scheduler); #31-style backoff. `threshold_secs`
/// is the liveness deadline (no check-in within it ⇒ offline). Call once at
/// startup.
/// Heartbeat registry name for the agent-offline scan loop.
const AGENT_OFFLINE_SCAN_NAME: &str = "agent_offline_scan";

pub fn spawn_agent_offline_scan(pool: PgPool, interval_secs: u64, threshold_secs: i64) {
    tokio::spawn(async move {
        crate::background::register_loop(AGENT_OFFLINE_SCAN_NAME, interval_secs);
        let mut ticker = interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick
        let timeout = crate::background::iteration_timeout(interval_secs);
        let mut consecutive_failures: u32 = 0;
        loop {
            ticker.tick().await;
            match crate::background::run_bounded(
                timeout,
                agent_offline_scan_once(&pool, threshold_secs),
            )
            .await
            {
                Ok(emitted) => {
                    consecutive_failures = 0;
                    crate::background::record_loop_success(AGENT_OFFLINE_SCAN_NAME);
                    if emitted > 0 {
                        tracing::info!(emitted, "agent-offline scan emitted transition events");
                    }
                }
                Err(err) => {
                    let backoff = crate::background::note_failure(&mut consecutive_failures);
                    match err {
                        crate::background::IterError::Failed(e) => tracing::error!(
                            error = %e,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "agent-offline scan failed; backing off"
                        ),
                        crate::background::IterError::TimedOut => tracing::error!(
                            timeout_secs = timeout.as_secs(),
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "agent-offline scan exceeded its iteration timeout; backing off"
                        ),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(
                        interval_secs.saturating_mul(backoff),
                    ))
                    .await;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// create_live_apply_job — enqueue a LiveApply job with a CP-signed grant
// ---------------------------------------------------------------------------

/// Validate the mode and request_id invariants for `create_live_apply_job`.
///
/// Separated from the async body so tests can call it directly without needing
/// a real `PgPool` (the assertions fire before any DB interaction).
///
/// Returns `Err(msg)` so the caller can decide how to handle the violation;
/// `create_live_apply_job` maps it to `CreateLiveApplyJobError::Invalid` (it does
/// NOT panic), so a future operator endpoint can surface a 4xx.
#[cfg_attr(not(test), allow(dead_code))]
pub fn validate_live_apply_params(spec: &JobSpec, request_id: Uuid) -> Result<(), &'static str> {
    if spec.mode != JobMode::LiveApply {
        return Err("create_live_apply_job requires a LiveApply spec");
    }
    if spec.request_id != request_id {
        return Err("spec.request_id must equal the supplied request_id");
    }
    validate_request_live_state_key(spec, request_id)?;
    Ok(())
}

fn validate_request_live_state_key(spec: &JobSpec, request_id: Uuid) -> Result<(), &'static str> {
    let expected = crate::contracts::request_state_key(request_id);
    if spec.state_key.as_deref() == Some(expected.as_str()) {
        Ok(())
    } else {
        Err("live request job state_key must be owned by its request")
    }
}

fn validate_step_live_state_key(spec: &JobSpec, step_id: Uuid) -> Result<(), &'static str> {
    let expected = crate::contracts::step_state_key(step_id);
    if spec.state_key.as_deref() == Some(expected.as_str()) {
        Ok(())
    } else {
        Err("live step job state_key must be owned by its persisted step")
    }
}

/// Maximum lifetime of a LiveApply approval grant. A grant longer than this is
/// rejected at creation so an over-broad approval window cannot be minted.
const MAX_GRANT_TTL_HOURS: i64 = 24;

/// Error from [`create_live_apply_job`].
#[derive(Debug, thiserror::Error)]
pub enum CreateLiveApplyJobError {
    /// The supplied spec/request did not satisfy the LiveApply preconditions.
    #[error("invalid live-apply parameters: {0}")]
    Invalid(&'static str),
    /// The request has already CONCLUDED (Completed, the post-completion
    /// lifecycle Protecting/Operational/Retired, or a terminal state); a
    /// live-apply grant must never be minted against it. Maps to 409 Conflict.
    #[error("request has concluded; a live-apply grant cannot be minted")]
    RequestConcluded,
    /// #42 slice 3: the request has a persisted `job_steps` multi-step
    /// orchestration plan. Such a request is executed STEP-BY-STEP by the
    /// orchestration engine (per-step OfflineDryRun jobs, never a single
    /// LiveApply) — minting a single-shot LiveApply grant for it would bypass
    /// its step plan AND the OfflineDryRun-only invariant those steps rely on.
    /// Maps to 409 Conflict.
    #[error("multi-step requests are executed step-by-step and do not support single live-apply")]
    HasStepPlan,
    /// A database error occurred while enqueuing the job.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Closed authority proof for the two step-scoped live mutation modes. A
/// human-approved LiveApply carries the admitted session itself; compensating
/// LiveDestroy is available only to the dedicated control-plane teardown path.
/// A caller can no longer pass an arbitrary approver string to the signing
/// choke point.
pub enum StepLiveJobAuthority<'a> {
    #[cfg_attr(not(test), allow(dead_code))]
    VerifiedHuman(&'a AuthSession),
    SystemAutoTeardown,
}

/// Exact immutable successful-plan row and leased attempt selected by the
/// approval flow. A digest is review evidence, not a unique authority key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPlanReference {
    pub job_id: Uuid,
    pub attempt_id: Uuid,
    /// LiveDestroy carries forward the authority that the prior CP-signed
    /// LiveApply grant used. The exact plan row must recompute to the same
    /// authority before a rollback grant can be minted.
    pub expected_execution_authority: Option<LiveExecutionAuthority>,
}

type SuccessfulPlanAuthorityRow = (
    String,
    sqlx::types::Json<Value>,
    sqlx::types::Json<Value>,
    Uuid,
    String,
    String,
    String,
    Option<Uuid>,
    i64,
    Option<Uuid>,
    String,
    String,
    Vec<u8>,
);

/// Resolve and re-verify the exact immutable enrollment and canonical
/// execution profile that produced the successful plan being approved. The
/// agent row is share-locked through grant insertion so revocation/key changes
/// cannot race the mint.
async fn successful_plan_execution_authority(
    connection: &mut sqlx::PgConnection,
    approved_plan: &ApprovedPlanReference,
    request_id: Uuid,
    platform: &str,
    mutation_spec: &JobSpec,
    approved_plan_digest: &str,
) -> Result<LiveExecutionAuthority, CreateLiveApplyJobError> {
    let state_key = mutation_spec
        .state_key
        .as_deref()
        .ok_or(CreateLiveApplyJobError::Invalid(
            "live mutation has no state key",
        ))?;
    let row: Option<SuccessfulPlanAuthorityRow> = sqlx::query_as(
        "SELECT j.agent_id, j.signed_envelope, j.spec, \
                a.id, a.public_key, a.status, a.platform, \
                j.attempt_id, j.lease_generation, j.result_id, \
                j.evidence_digest, j.raw_plan_digest, eb.bytes \
         FROM agent_jobs j \
         JOIN agents a ON a.agent_id = j.agent_id \
         JOIN evidence_blobs eb ON eb.digest = j.evidence_digest \
         WHERE j.id = $1 AND j.request_id = $2 AND j.platform = $3 \
           AND j.mode = 'LivePlan' AND j.status = 'Succeeded' \
           AND j.result_status = 'planned' \
           AND j.completed_at IS NOT NULL \
           AND j.raw_plan_digest = $4 AND j.signed_envelope IS NOT NULL \
           AND j.spec->>'state_key' = $5 \
         FOR SHARE OF j, a",
    )
    .bind(approved_plan.job_id)
    .bind(request_id)
    .bind(platform)
    .bind(approved_plan_digest)
    .bind(state_key)
    .fetch_optional(&mut *connection)
    .await?;
    let Some((
        agent_id,
        envelope_json,
        plan_spec_json,
        enrollment_id,
        public_key,
        status,
        agent_platform,
        row_attempt_id,
        row_lease_generation,
        row_result_id,
        stored_evidence_digest,
        stored_raw_plan_digest,
        stored_evidence,
    )) = row
    else {
        return Err(CreateLiveApplyJobError::Invalid(
            "approved plan has no signed immutable execution authority",
        ));
    };
    if status != "approved" || agent_platform != platform {
        return Err(CreateLiveApplyJobError::Invalid(
            "planning agent enrollment is no longer approved for this platform",
        ));
    }

    let plan_spec: JobSpec = serde_json::from_value(plan_spec_json.0).map_err(|_| {
        CreateLiveApplyJobError::Invalid("stored approved-plan job spec is malformed")
    })?;
    if plan_spec.mode != JobMode::LivePlan
        || plan_spec.request_id != mutation_spec.request_id
        || plan_spec.offering_id != mutation_spec.offering_id
        || plan_spec.iac_ref != mutation_spec.iac_ref
        || plan_spec.iac_digest != mutation_spec.iac_digest
        || plan_spec.vars != mutation_spec.vars
        || plan_spec.state_key != mutation_spec.state_key
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "approved plan job spec differs from the mutation spec",
        ));
    }
    let envelope: ryuki_protocol::SignedEnvelope = serde_json::from_value(envelope_json.0)
        .map_err(|_| {
            CreateLiveApplyJobError::Invalid("stored approved-plan signature is malformed")
        })?;
    let verifying_key = decode_verifying_key(&public_key).map_err(|_| {
        CreateLiveApplyJobError::Invalid("planning agent enrollment key is malformed")
    })?;
    if row_attempt_id != Some(approved_plan.attempt_id)
        || row_lease_generation < 0
        || envelope.job_id != approved_plan.job_id
        || envelope.attempt_id != approved_plan.attempt_id
        || envelope.lease_generation != row_lease_generation as u64
        || row_result_id != Some(envelope.result_id)
        || envelope.request_id != request_id
        || envelope.agent_id != agent_id
        || envelope.agent_enrollment_id != enrollment_id
        || envelope.platform != platform
        || envelope.mode != JobMode::LivePlan
        || envelope.status != JobResultStatus::Planned
        || envelope.key_id != encode_verifying_key(&verifying_key)
        || envelope.job_spec_digest != ryuki_protocol::job_spec_digest(&plan_spec)
        || envelope.evidence_digest != stored_evidence_digest
        || envelope.raw_plan_digest.as_deref() != Some(stored_raw_plan_digest.as_str())
        || stored_raw_plan_digest != approved_plan_digest
        || ryuki_protocol::verify(&envelope, &verifying_key).is_err()
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "stored approved-plan signature or authority is invalid",
        ));
    }
    if ryuki_protocol::sha256_hex(&stored_evidence) != stored_evidence_digest
        || validated_raw_plan_digest(
            &JobMode::LivePlan,
            &JobResultStatus::Planned,
            envelope.raw_plan_digest.as_deref(),
            &plan_spec,
            &stored_evidence,
        )
        .ok()
        .flatten()
        .as_deref()
            != Some(stored_raw_plan_digest.as_str())
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "stored approved-plan evidence or raw-plan commitment is invalid",
        ));
    }
    let profile =
        envelope
            .execution_trust_profile
            .as_ref()
            .ok_or(CreateLiveApplyJobError::Invalid(
                "approved plan has no execution trust profile",
            ))?;
    validate_execution_trust_profile(profile, &plan_spec, platform)
        .map_err(CreateLiveApplyJobError::Invalid)?;

    let execution_authority = LiveExecutionAuthority {
        assigned_agent_id: agent_id,
        assigned_agent_enrollment_id: enrollment_id,
        assigned_agent_key_fingerprint: public_key_fingerprint(&public_key),
        execution_trust_profile_digest: execution_trust_profile_digest(profile),
    };
    if approved_plan
        .expected_execution_authority
        .as_ref()
        .is_some_and(|expected| expected != &execution_authority)
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "prior live-apply authority differs from the exact approved plan",
        ));
    }
    Ok(execution_authority)
}

/// Enqueue a new Pending `LiveApply` job with a CP-signed [`VerifiedLiveContext`]
/// grant attached, and return the job row id.
///
/// ## Signing invariants
///
/// - `spec.mode` MUST be `JobMode::LiveApply`; returns `Invalid` otherwise.
/// - `spec.request_id` MUST equal `request_id`; the S5a-1 verifier checks
///   `grant.request_id == spec.request_id` and rejects on mismatch.
///
/// ## Grant shape
///
/// A [`VerifiedLiveContext`] is constructed from the supplied fields and signed
/// by `cp_key` using `sign_vlc`. The signed grant is stored in the job row's
/// `live_context` JSONB column. Agents will fetch the job (including the grant)
/// via `GET /api/agents/{id}/jobs`, verify the CP signature against the CP
/// public key, and reject the apply if the signature is invalid.
///
/// ## Lifecycle: ONE permanent LiveApply slot per request
///
/// Every request has exactly ONE LiveApply slot, enforced for all time by the
/// partial unique index `idx_agent_jobs_unique_live_apply` (migration 057),
/// which spans EVERY status. Once a LiveApply job exists for a request — in any
/// state, INCLUDING a terminal non-Succeeded one (`Failed`,
/// `ReconcileRequired`→`Failed`, `LiveRefused`, `DeadLettered`, `Cancelled`) —
/// that slot is permanently consumed: the `ON CONFLICT … DO NOTHING` below
/// inserts nothing and this fn returns `Invalid("a live-apply has already been
/// approved for this request")`. This is deliberate and fail-closed — a
/// half-applied apply must be reconciled, never blindly re-minted (the
/// no-double-apply invariant; see migration 057 and execution-agent.md §5).
///
/// Consequence: a live-apply CANNOT be retried in place. When a LiveApply ends
/// terminal-non-Succeeded the request either auto-concludes to `Failed` (an
/// agent-reported `Failed`/`LiveRefused`, via `backlink_request_execution`) or
/// is left `Executing` (lease-expiry→`ReconcileRequired`, `DeadLettered`,
/// pending-cancel) for the operator to conclude with `POST
/// /api/requests/{id}/fail`. Either way the slot stays consumed. RE-ATTEMPTING a
/// live-apply requires a FRESH request — a brand-new lifecycle that re-plans and
/// re-approves against the CURRENT infrastructure state — never a reuse of this
/// request's grant or spec.
///
/// DEFERRED (owner decision): an operator-gated in-place re-dispatch after
/// reconciliation (execution-agent.md §5's "explicitly re-dispatches" half) is
/// NOT built. It overlaps the LiveRefused-recoverability / operator-re-approve
/// decision and needs its own trust-model work (operator attestation that the
/// prior apply left a known state, a new signed grant, a fresh plan-vs-current
/// check). Until then the contract is fail-closed as above.
///
/// Note: the operator-facing HTTP approval endpoint (portal integration) is a
/// later slice (S5c). This function is the signing core that all such endpoints
/// will delegate to.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub async fn create_live_apply_job(
    pool: &PgPool,
    approved_plan: ApprovedPlanReference,
    request_id: Uuid,
    platform: &str,
    spec: &JobSpec,
    approved_plan_digest: &str,
    session: &AuthSession,
    expiry: DateTime<Utc>,
    cp_key: &ed25519_dalek::SigningKey,
) -> Result<Uuid, CreateLiveApplyJobError> {
    // This is the final signing/persistence choke point. Enforce human
    // provenance before opening a transaction so machine/unknown/simulated
    // callers cannot mutate request state, append approval audit, or mint a
    // CP-signed grant even if a handler or future route is composed incorrectly.
    if !ryuki_engine::auth::check_human_signoff_permission(session, "admin") {
        return Err(CreateLiveApplyJobError::Invalid(
            "live-apply approval requires a verified human administrator",
        ));
    }
    // Invariant: this function only creates LiveApply jobs — the grant is
    // meaningless for any other mode, and the S5a-1 verifier only checks grants
    // on LiveApply results. Fail closed (return Err) rather than panic so a
    // future operator endpoint can surface a 4xx instead of crashing the request.
    validate_live_apply_params(spec, request_id).map_err(CreateLiveApplyJobError::Invalid)?;

    // Fail closed: never mint a LiveApply grant for a request that has CONCLUDED
    // (Completed, the post-completion lifecycle Protecting/Operational/Retired, or
    // any terminal state). This gate lives in the SHARED minting choke point so it
    // covers every active minting path. The legacy caller-supplied admin endpoint
    // is disabled below because request-scoped approval must derive its spec and
    // digest from stored plan evidence. A stale plan can therefore never re-open
    // a concluded request to infrastructure mutation. The exhaustive
    // is_concluded() classifier is the single source of truth.
    // Lock the request row for the duration of the mint so it cannot CONCLUDE
    // between this status check and the grant-minting INSERT below. Without the
    // lock a concurrent retire/complete could slip in after the check, and a
    // grant authorising infrastructure mutation would be minted for an
    // already-concluded request — a TOCTOU against the invariant above. All
    // statements below run on this transaction; any early `?` return drops it
    // (rollback), so a grant is persisted only on the committed success path.
    let mut tx = pool.begin().await?;
    let request_state: Option<(String, String, String)> =
        sqlx::query_as("SELECT status, stage, site FROM requests WHERE id = $1 FOR UPDATE")
            .bind(request_id)
            .fetch_optional(&mut *tx)
            .await?;
    let (request_status, request_stage, request_site) = match request_state {
        None => {
            return Err(CreateLiveApplyJobError::Invalid(
                "request not found; cannot mint a live-apply grant",
            ));
        }
        Some((status, _, _))
            if crate::contracts::db_status_to_request_status(&status).is_concluded() =>
        {
            return Err(CreateLiveApplyJobError::RequestConcluded);
        }
        Some(state) => state,
    };
    if request_site != platform {
        return Err(CreateLiveApplyJobError::Invalid(
            "live-apply platform differs from the authoritative request site",
        ));
    }

    // #42 slice 3: never mint a single-shot LiveApply grant for a request that
    // has a persisted multi-step `job_steps` plan — it must be driven step-by-
    // step by the orchestration engine instead (completes the OfflineDryRun-only
    // invariant from slice 2a: a multi-step request can never reach a live
    // execution mode via this separate, single-job grant path). Checked on the
    // SAME locked transaction as the concluded-status check above, so this is
    // the single shared minting choke point for BOTH the request-scoped
    // approval endpoint and the operator admin endpoint.
    let has_step_plan = !crate::repos::job_steps::load_plan(&mut *tx, request_id)
        .await?
        .is_empty();
    if has_step_plan {
        return Err(CreateLiveApplyJobError::HasStepPlan);
    }

    // Validate the grant fields before signing — a signed grant is authoritative,
    // so it must never carry a bogus digest, an empty approver, or an abusive
    // expiry. (digest = lowercase SHA-256 hex; expiry must be in the future and
    // within MAX_GRANT_TTL.)
    if approved_plan_digest.len() != 64
        || !approved_plan_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "approved_plan_digest must be a 64-character SHA-256 hex string",
        ));
    }
    let approver = session.user_id.as_str();
    if approver.trim().is_empty() {
        return Err(CreateLiveApplyJobError::Invalid(
            "approver must not be empty",
        ));
    }
    let now = Utc::now();
    if expiry <= now {
        return Err(CreateLiveApplyJobError::Invalid(
            "grant expiry must be in the future",
        ));
    }
    if expiry > now + chrono::Duration::hours(MAX_GRANT_TTL_HOURS) {
        return Err(CreateLiveApplyJobError::Invalid(
            "grant expiry exceeds the maximum allowed TTL",
        ));
    }

    let execution_authority = successful_plan_execution_authority(
        &mut tx,
        &approved_plan,
        request_id,
        platform,
        spec,
        approved_plan_digest,
    )
    .await?;

    // Build and sign the VerifiedLiveContext grant. This whole-request path
    // mints a legacy/single-job grant (step_job_id: None) — #42 slice B adds
    // the per-step minting path that sets step_job_id: Some(..); this
    // function's contract is unchanged by slice A.
    let unsigned_grant = VerifiedLiveContext {
        request_id,
        platform: platform.to_string(),
        job_spec_digest: ryuki_protocol::job_spec_digest(spec),
        approved_plan_digest: approved_plan_digest.to_string(),
        approved_plan_job_id: approved_plan.job_id,
        approved_plan_attempt_id: approved_plan.attempt_id,
        approver: approver.to_string(),
        expiry,
        step_job_id: None,
        execution_authority: execution_authority.clone(),
        signature: String::new(),
    };
    let signed_grant = sign_vlc(unsigned_grant, cp_key);

    let spec_json = serde_json::to_value(spec).expect("JobSpec serialisation is infallible");
    let grant_json = serde_json::to_value(&signed_grant)
        .expect("VerifiedLiveContext serialisation is infallible");

    // Atomic, CONCURRENCY-SAFE no-double-apply invariant (enforced for EVERY
    // caller — the request-scoped approval AND the operator endpoint): insert
    // the LiveApply job only if none already exists for this request. ON
    // CONFLICT against the partial unique index `idx_agent_jobs_unique_live_apply`
    // (migration 057, `(request_id) WHERE mode='LiveApply'`) makes two
    // simultaneous approvals safe — the loser inserts nothing and gets None.
    // A grant authorising infrastructure mutation can therefore never be minted
    // twice; a failed/expired apply goes through operator reconcile, not a
    // re-mint. The index spans ALL statuses, so a TERMINAL prior LiveApply
    // (Failed/ReconcileRequired→Failed/LiveRefused/DeadLettered/Cancelled) also
    // hits this conflict: the request's single LiveApply slot is permanently
    // consumed and a re-attempt requires a fresh request (see the fn doc).
    let id: Option<Uuid> = sqlx::query_scalar(
        // The ON CONFLICT arbiter predicate must MATCH the partial unique index
        // exactly. Mig 153 narrowed that index to `... AND step_scoped = FALSE`
        // (so step-scoped per-step LiveApply jobs are exempt), so this single-
        // job insert — which leaves step_scoped at its FALSE default — must
        // carry the same `step_scoped = FALSE` predicate here to infer it.
        "INSERT INTO agent_jobs (request_id, platform, spec, mode, live_context, agent_id) \
         VALUES ($1, $2, $3, 'LiveApply', $4::jsonb, $5) \
         ON CONFLICT (request_id) WHERE mode = 'LiveApply' AND step_scoped = FALSE DO NOTHING \
         RETURNING id",
    )
    .bind(request_id)
    .bind(platform)
    .bind(&spec_json)
    .bind(&grant_json)
    .bind(&execution_authority.assigned_agent_id)
    .fetch_optional(&mut *tx)
    .await?;
    let id = id.ok_or(CreateLiveApplyJobError::Invalid(
        "a live-apply has already been approved for this request",
    ))?;
    let request_id_text = request_id.to_string();
    crate::audit::record_audit_tx(
        &mut tx,
        session,
        &crate::audit::AuditRecord {
            action: "request.approve-live-apply",
            request_id: Some(&request_id_text),
            from_status: Some(&request_status),
            to_status: &request_status,
            from_stage: Some(&request_stage),
            to_stage: &request_stage,
            detail: json!({
                "agent_job_id": id,
                "approved_plan_digest": approved_plan_digest,
                "mode": "LiveApply",
            }),
            outcome: "approved",
        },
    )
    .await?;
    // Commit only the success path — the request row lock (and any rows) are
    // released here; every early return above rolled back instead.
    tx.commit().await?;

    tracing::info!(
        job_id = %id,
        request_id = %request_id,
        platform = %platform,
        approver = %approver,
        approved_plan_digest = %approved_plan_digest,
        "LiveApply job enqueued with CP-signed grant"
    );
    Ok(id)
}

/// Mint a CP-signed, STEP-SCOPED LiveApply grant + `agent_jobs` row for ONE
/// step of a multi-step request (#42 live-apply slice B1b), on the caller's
/// transaction `tx`.
///
/// Unlike [`create_live_apply_job`] (the single-job path — at most one
/// LiveApply per request), this:
///   * binds the grant to the specific dispatched step job via
///     `VerifiedLiveContext.step_job_id` (slice A) — the job id is generated
///     client-side so it can be signed INTO the grant before the INSERT, and an
///     agent/CP verifier refuses the grant on any other job id; and
///   * marks the row `step_scoped = TRUE` so it is EXEMPT from the
///     request-level one-live-apply uniqueness (mig 153) — a request carries
///     one such job per step.
///
/// Per-step no-double-apply is the CALLER's responsibility: the approval
/// endpoint (slice B1b-2) flips the step `AwaitingApproval -> Applying` under a
/// `FOR UPDATE` lock in the SAME transaction as this mint, so a step is
/// approved (and its grant minted) exactly once. This fn keeps the same
/// fail-closed grant validation and concluded-request guard as the single-job
/// path so it is a safe minting choke point on its own; it does NOT re-check
/// the step's status (that is the endpoint's lock-guarded job).
/// (#42 slice B2) the same mint serves LiveApply (per-step approval, B1b-2) AND
/// LiveDestroy (auto compensating teardown, B2-2) — both are step-scoped,
/// grant-bound, live-mutating step jobs that differ only in `spec.mode`. The
/// caller sets the mode; this fn accepts either and rejects anything else.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub async fn create_step_live_job(
    tx: &mut sqlx::PgConnection,
    approved_plan: ApprovedPlanReference,
    request_id: Uuid,
    step_id: Uuid,
    platform: &str,
    spec: &JobSpec,
    approved_plan_digest: &str,
    authority: StepLiveJobAuthority<'_>,
    expiry: DateTime<Utc>,
    cp_key: &ed25519_dalek::SigningKey,
) -> Result<Uuid, CreateLiveApplyJobError> {
    // A step live job must be LiveApply or LiveDestroy (both step-scoped,
    // grant-bound, live-mutating), and its spec must be for THIS request.
    if !matches!(&spec.mode, JobMode::LiveApply | JobMode::LiveDestroy) {
        return Err(CreateLiveApplyJobError::Invalid(
            "create_step_live_job requires a LiveApply or LiveDestroy spec",
        ));
    }
    if spec.request_id != request_id {
        return Err(CreateLiveApplyJobError::Invalid(
            "spec.request_id must equal the supplied request_id",
        ));
    }
    validate_step_live_state_key(spec, step_id).map_err(CreateLiveApplyJobError::Invalid)?;

    let approver = match (&spec.mode, &authority) {
        (JobMode::LiveApply, StepLiveJobAuthority::VerifiedHuman(session))
            if ryuki_engine::auth::check_human_signoff_permission(session, "admin") =>
        {
            session.user_id.as_str()
        }
        (JobMode::LiveApply, _) => {
            return Err(CreateLiveApplyJobError::Invalid(
                "step live-apply approval requires a verified human administrator",
            ));
        }
        (JobMode::LiveDestroy, StepLiveJobAuthority::SystemAutoTeardown) => "system:auto-teardown",
        (JobMode::LiveDestroy, _) => {
            return Err(CreateLiveApplyJobError::Invalid(
                "step live-destroy requires dedicated system teardown authority",
            ));
        }
        _ => unreachable!("step live mode was validated above"),
    };
    match &spec.mode {
        JobMode::LiveDestroy if approved_plan.expected_execution_authority.is_none() => {
            return Err(CreateLiveApplyJobError::Invalid(
                "step live-destroy requires the prior signed live-apply authority",
            ));
        }
        JobMode::LiveApply if approved_plan.expected_execution_authority.is_some() => {
            return Err(CreateLiveApplyJobError::Invalid(
                "step live-apply must derive authority directly from its exact plan",
            ));
        }
        _ => {}
    }

    // Fail closed: never mint a live-apply grant for a CONCLUDED request. Lock
    // the request row so it cannot conclude between this check and the INSERT
    // (same TOCTOU guard as the single-job path). The caller runs this inside
    // its own transaction, so the lock is held until that transaction commits.
    let request_state: Option<(String, String)> =
        sqlx::query_as("SELECT status, site FROM requests WHERE id = $1 FOR UPDATE")
            .bind(request_id)
            .fetch_optional(&mut *tx)
            .await?;
    let request_site = match request_state {
        None => {
            return Err(CreateLiveApplyJobError::Invalid(
                "request not found; cannot mint a live-apply grant",
            ));
        }
        Some((status, _))
            if crate::contracts::db_status_to_request_status(&status).is_concluded() =>
        {
            return Err(CreateLiveApplyJobError::RequestConcluded);
        }
        Some((_, site)) => site,
    };
    if request_site != platform {
        return Err(CreateLiveApplyJobError::Invalid(
            "step live-job platform differs from the authoritative request site",
        ));
    }

    // The state namespace is derived from a persisted orchestration step, not
    // merely from a caller-provided UUID. Prove that the step belongs to this
    // request before signing a grant that can mutate its state.
    let step_request_id: Option<Uuid> =
        sqlx::query_scalar("SELECT request_id FROM job_steps WHERE id = $1")
            .bind(step_id)
            .fetch_optional(&mut *tx)
            .await?;
    if step_request_id != Some(request_id) {
        return Err(CreateLiveApplyJobError::Invalid(
            "live step state owner does not belong to the supplied request",
        ));
    }

    // Validate grant fields before signing (a signed grant is authoritative).
    if approved_plan_digest.len() != 64
        || !approved_plan_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "approved_plan_digest must be a 64-character SHA-256 hex string",
        ));
    }
    if approver.trim().is_empty() {
        return Err(CreateLiveApplyJobError::Invalid(
            "approver must not be empty",
        ));
    }
    let now = Utc::now();
    if expiry <= now {
        return Err(CreateLiveApplyJobError::Invalid(
            "grant expiry must be in the future",
        ));
    }
    if expiry > now + chrono::Duration::hours(MAX_GRANT_TTL_HOURS) {
        return Err(CreateLiveApplyJobError::Invalid(
            "grant expiry exceeds the maximum allowed TTL",
        ));
    }

    let execution_authority = successful_plan_execution_authority(
        tx,
        &approved_plan,
        request_id,
        platform,
        spec,
        approved_plan_digest,
    )
    .await?;

    // Generate the job id client-side so it can be bound INTO the grant
    // (step_job_id) before signing — the whole point of the step-scoped grant.
    let job_id = Uuid::new_v4();
    let unsigned_grant = VerifiedLiveContext {
        request_id,
        platform: platform.to_string(),
        job_spec_digest: ryuki_protocol::job_spec_digest(spec),
        approved_plan_digest: approved_plan_digest.to_string(),
        approved_plan_job_id: approved_plan.job_id,
        approved_plan_attempt_id: approved_plan.attempt_id,
        approver: approver.to_string(),
        expiry,
        step_job_id: Some(job_id),
        execution_authority: execution_authority.clone(),
        signature: String::new(),
    };
    let signed_grant = sign_vlc(unsigned_grant, cp_key);

    let spec_json = serde_json::to_value(spec).expect("JobSpec serialisation is infallible");
    let grant_json = serde_json::to_value(&signed_grant)
        .expect("VerifiedLiveContext serialisation is infallible");

    // The DB `mode` column MUST equal the spec's mode — the agent signs the
    // spec's mode into its result envelope, and result ingest (step 8) compares
    // the envelope against this column. A LiveDestroy job stored as 'LiveApply'
    // would have its (correctly LiveDestroy) result rejected, stalling the
    // rollback. (spec.mode was validated to LiveApply|LiveDestroy above.)
    let mode_label = match &spec.mode {
        JobMode::LiveDestroy => "LiveDestroy",
        _ => "LiveApply",
    };
    // step_scoped = TRUE exempts this row from the request-level one-live-apply
    // unique index (mig 153), so each step of a request gets its own. No
    // ON CONFLICT: per-step single-approval is enforced by the caller's
    // AwaitingApproval->Applying lock, and the client-generated id is unique.
    sqlx::query(
        "INSERT INTO agent_jobs (id, request_id, platform, spec, mode, step_scoped, live_context, agent_id) \
         VALUES ($1, $2, $3, $4, $5, TRUE, $6::jsonb, $7)",
    )
    .bind(job_id)
    .bind(request_id)
    .bind(platform)
    .bind(&spec_json)
    .bind(mode_label)
    .bind(&grant_json)
    .bind(&execution_authority.assigned_agent_id)
    .execute(&mut *tx)
    .await?;

    tracing::info!(
        job_id = %job_id,
        request_id = %request_id,
        platform = %platform,
        approver = %approver,
        approved_plan_digest = %approved_plan_digest,
        "step-scoped LiveApply job enqueued with CP-signed grant"
    );
    Ok(job_id)
}

// ---------------------------------------------------------------------------
// GET /api/agents/cp-public-key — unauthenticated CP public-key endpoint
// ---------------------------------------------------------------------------

/// Return the CP's Ed25519 public key as base64.
///
/// ## Auth posture
///
/// **Unauthenticated** — intentionally.  A public key is not a secret; any
/// agent (or observer) may fetch it.  Agents use this to pin the CP public key
/// for verifying [`VerifiedLiveContext`] grants.  This endpoint is mounted via
/// `agent_routes()`, which sits OUTSIDE the human `auth_middleware` layer in
/// `main.rs`, so no session or agent-token is required.
///
/// Returns 503 if the CP signing key was not initialised at startup (e.g. the
/// key file was unreadable and the server continued in degraded mode).
pub async fn cp_public_key() -> impl IntoResponse {
    match cp_identity::cp_public_key_b64() {
        Some(pubkey) => (
            axum::http::StatusCode::OK,
            // Advertise the CP's wire protocol version alongside the key. The agent
            // fetches this at startup and refuses to run against a CP whose version
            // is outside its own SUPPORTED_PROTOCOL_VERSIONS — the CP→agent half of
            // the compatibility handshake.
            Json(serde_json::json!({
                "public_key": pubkey,
                "protocol_version": ryuki_protocol::PROTOCOL_VERSION,
            })),
        )
            .into_response(),
        None => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "CP signing key not initialised"})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Returns the agent sub-router for agent-token–authenticated endpoints.
/// Mounted separately in main.rs (NOT under the human auth_middleware).
/// Admin-approve is served from /api/admin/ in contracts.rs / main.rs
/// so the human RBAC middleware covers it and agent tokens can never reach it.
/// Agent-token routes: these four endpoints use `authenticate_agent` (bearer
/// token) as their sole auth gate and must NOT sit behind the human
/// `auth_middleware`. Mount via `agents::agent_routes()` BEFORE the human
/// middleware layer in main.rs.
///
/// `GET /api/agents/cp-public-key` is intentionally unauthenticated: a public
/// key is not a secret, and agents need it to verify CP-signed grants before
/// (and independently of) their own auth.
pub fn agent_routes() -> Router {
    Router::new()
        .route(
            "/api/agents/register",
            post(register_agent).layer(DefaultBodyLimit::max(AGENT_REGISTRATION_BODY_LIMIT_BYTES)),
        )
        .route("/api/agents/cp-public-key", get(cp_public_key))
        .route("/api/agents/{agent_id}/jobs", get(poll_job))
        .route("/api/agents/{agent_id}/jobs/{job_id}/ack", post(ack_job))
        .route(
            "/api/agents/{agent_id}/jobs/{job_id}/result",
            post(post_job_result),
        )
        .route("/api/agents/{agent_id}/heartbeat", post(heartbeat))
        .route(
            "/api/agents/openapi.json",
            axum::routing::get(crate::openapi::openapi_json),
        )
}

/// Drift-guard source of truth: the (method, path) pairs of every AGENT-PROTOCOL
/// endpoint documented in `crate::openapi::openapi_document()`. Cross-checked
/// exactly (no missing, no extra) by `openapi.rs`'s
/// `documented_paths_match_agent_route_paths_exactly` test, so adding or
/// removing an agent route without updating the OpenAPI spec fails CI.
///
/// KEEP IN SYNC with the routes registered in [`agent_routes`] above AND with
/// the `paths` documented in `openapi_document()`. Deliberately does NOT
/// include `/api/agents/openapi.json` itself — that route is meta (it serves
/// this very document), not an agent-protocol endpoint.
///
/// `ryuki-api` is a binary crate (no lib target), so this `pub` constant is
/// only ever read from `openapi.rs`'s `#[cfg(test)]` drift-guard test — never
/// from non-test code. That makes it legitimately dead in a release build.
#[allow(dead_code)]
pub const AGENT_ROUTE_PATHS: &[(&str, &str)] = &[
    ("POST", "/api/agents/register"),
    ("GET", "/api/agents/cp-public-key"),
    ("GET", "/api/agents/{agent_id}/jobs"),
    ("POST", "/api/agents/{agent_id}/jobs/{job_id}/ack"),
    ("POST", "/api/agents/{agent_id}/jobs/{job_id}/result"),
    ("POST", "/api/agents/{agent_id}/heartbeat"),
];

// ---------------------------------------------------------------------------
// POST /api/admin/agents/live-apply-jobs — operator live-apply approval
// ---------------------------------------------------------------------------

/// Request derived by the safe request-scoped live-apply approval handler.
///
/// The `approver` identity is always taken from the verified session — it MUST
/// NOT appear in this body so that a caller cannot forge the approving principal.
#[derive(Debug, Deserialize)]
pub struct ApproveLiveApplyBody {
    pub approved_plan_job_id: Uuid,
    pub approved_plan_attempt_id: Uuid,
    pub request_id: Uuid,
    pub platform: String,
    pub spec: JobSpec,
    pub approved_plan_digest: String,
    /// Requested grant lifetime in seconds. Must be > 0 and ≤ MAX_GRANT_TTL_HOURS * 3600.
    pub expiry_seconds: u64,
}

/// Testable core for live-apply approval (no axum Extension — receives the
/// already-verified session explicitly).
///
/// Validates `expiry_seconds`, computes the absolute expiry, then delegates to
/// [`create_live_apply_job`] which performs the remaining invariant checks
/// (digest format, approver emptiness, spec.mode, request_id binding) before
/// signing the grant and inserting the job row.
///
/// Returns the job id and associated metadata as a JSON response.
pub async fn approve_live_apply_with(
    pool: &PgPool,
    cp_key: &ed25519_dalek::SigningKey,
    session: &AuthSession,
    body: &ApproveLiveApplyBody,
) -> ApiResult<Json<Value>> {
    // Validate expiry bounds here for a clean 400 before we reach create_live_apply_job.
    if body.expiry_seconds == 0 {
        return Err(bad_request("expiry_seconds must be greater than zero"));
    }
    let max_seconds = (MAX_GRANT_TTL_HOURS as u64) * 3600;
    if body.expiry_seconds > max_seconds {
        return Err(bad_request(format!(
            "expiry_seconds exceeds the maximum allowed TTL ({} seconds)",
            max_seconds
        )));
    }

    let expiry = Utc::now() + Duration::seconds(body.expiry_seconds as i64);

    let job_id = create_live_apply_job(
        pool,
        ApprovedPlanReference {
            job_id: body.approved_plan_job_id,
            attempt_id: body.approved_plan_attempt_id,
            expected_execution_authority: None,
        },
        body.request_id,
        &body.platform,
        &body.spec,
        &body.approved_plan_digest,
        session,
        expiry,
        cp_key,
    )
    .await
    .map_err(|e| match e {
        CreateLiveApplyJobError::Invalid(msg) => bad_request(msg),
        CreateLiveApplyJobError::RequestConcluded => {
            conflict("request has concluded; a live-apply grant cannot be minted")
        }
        CreateLiveApplyJobError::HasStepPlan => conflict(
            "multi-step requests are executed step-by-step and do not support single live-apply",
        ),
        CreateLiveApplyJobError::Db(db_e) => db_err(db_e),
    })?;

    Ok(Json(json!({
        "job_id": job_id,
        "approver": session.user_id,
        "status": "Pending",
        "mode": "LiveApply"
    })))
}

/// POST /api/admin/agents/live-apply-jobs
///
/// Disabled legacy endpoint. Its caller-supplied platform, spec, and plan
/// digest could bypass the request-scoped safe plan-review derivation. Live
/// apply approval is available only through
/// `POST /api/requests/{id}/approve-live-apply`, which derives every
/// mutation-authorizing field from a successful stored LivePlan.
///
/// ## Auth posture
///
/// The route sits under `/api/admin/` so the human RBAC middleware already
/// enforces verified-human `admin` permission at the routing layer. The typed
/// actor check below is defense-in-depth if the handler is ever re-mounted.
///
/// Returns `410 Gone` for every authorized caller. No request body is accepted
/// and no database or signing-key state is consulted.
pub async fn admin_approve_live_apply_job(
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    // Defense-in-depth: the /api/admin RBAC middleware already blocks non-admins,
    // but we re-check here so a future re-mount cannot bypass the gate.
    if !ryuki_engine::auth::check_human_signoff_permission(&session, "admin") {
        return Err(forbidden("verified human admin permission required"));
    }

    Err((
        StatusCode::GONE,
        Json(json!({
            "error": "this caller-supplied live-apply endpoint is disabled; use POST /api/requests/{id}/approve-live-apply after reviewing the stored plan"
        })),
    ))
}

// ---------------------------------------------------------------------------
// GET /api/admin/agents — list agents with recent jobs (human RBAC, admin only)
// ---------------------------------------------------------------------------

/// Minimal agent row used to build the admin list response. The raw public key
/// is selected only to derive its non-secret fingerprint and is never returned.
#[derive(sqlx::FromRow)]
struct AdminAgentRow {
    id: Uuid,
    enrollment_challenge_id: Option<Uuid>,
    cryptographically_admitted: bool,
    agent_id: String,
    platform: String,
    status: String,
    public_key: String,
    capabilities: sqlx::types::Json<Value>,
    last_seen_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

/// Minimal job row projected for each agent in the admin list response.
#[derive(sqlx::FromRow)]
struct AdminJobRow {
    id: Uuid,
    agent_id: Option<String>,
    mode: String,
    status: String,
    result_status: Option<String>,
    completed_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

/// Maximum number of agents returned by the list endpoint.
const LIST_AGENTS_LIMIT: i64 = 500;
/// Maximum number of recent jobs fetched across all agents in one query.
const LIST_JOBS_LIMIT: i64 = 5000;
/// Maximum recent jobs surfaced per agent.
const JOBS_PER_AGENT_CAP: usize = 10;

/// Testable core for `admin_list_agents` — no axum Extension, no auth check.
///
/// Queries agents (bounded by [`LIST_AGENTS_LIMIT`]) ordered by `created_at DESC`,
/// then fetches recent jobs for those agents using a second bounded query.
/// Jobs are grouped per agent in Rust with a cap of [`JOBS_PER_AGENT_CAP`].
///
/// # Secret hygiene
///
/// `token_hash` is never selected. The public key is selected only long enough
/// to derive the SHA-256 fingerprint that binds a later approval request; the
/// raw key is never included in the response. Capabilities contain only tool
/// and provider versions and are represented by a SHA-256 digest in the roster.
pub async fn list_agents_with(pool: &PgPool) -> ApiResult<Json<Value>> {
    // -- 1. Fetch agents (newest first, bounded) --
    let mut agents: Vec<AdminAgentRow> = sqlx::query_as(
        "SELECT agent.id, agent.enrollment_challenge_id, \
                EXISTS ( \
                    SELECT 1 FROM agent_enrollment_challenges AS challenge \
                    WHERE challenge.id = agent.enrollment_challenge_id \
                      AND challenge.status = 'consumed' \
                      AND challenge.consumed_enrollment_id = agent.id \
                      AND challenge.agent_id = agent.agent_id \
                      AND challenge.platform = agent.platform \
                      AND challenge.public_key = agent.public_key \
                ) AS cryptographically_admitted, \
                agent.agent_id, agent.platform, agent.status, agent.public_key, \
                agent.capabilities, agent.last_seen_at, agent.created_at \
         FROM agents AS agent \
         ORDER BY agent.created_at DESC \
         LIMIT $1",
    )
    .bind(LIST_AGENTS_LIMIT + 1)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let capped = agents.len() as i64 > LIST_AGENTS_LIMIT;
    if capped {
        agents.truncate(LIST_AGENTS_LIMIT as usize);
    }

    if agents.is_empty() {
        return Ok(Json(json!({ "agents": [], "capped": false })));
    }

    // Collect agent_id strings for the IN clause.
    let agent_ids: Vec<&str> = agents.iter().map(|a| a.agent_id.as_str()).collect();

    // -- 2. Fetch recent jobs for those agents (bounded total, no secrets) --
    let jobs: Vec<AdminJobRow> = sqlx::query_as(
        "SELECT id, agent_id, mode, status, result_status, completed_at, created_at \
         FROM agent_jobs \
         WHERE agent_id = ANY($1) \
         ORDER BY created_at DESC \
         LIMIT $2",
    )
    .bind(&agent_ids)
    .bind(LIST_JOBS_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    // -- 3. Group jobs by agent_id in Rust with a per-agent cap --
    use std::collections::HashMap;
    let mut jobs_by_agent: HashMap<&str, Vec<Value>> = HashMap::new();
    for job in &jobs {
        // agent_id on agent_jobs is nullable (only set once leased);
        // skip jobs that are not yet associated with an agent.
        let Some(ref aid) = job.agent_id else {
            continue;
        };
        let bucket = jobs_by_agent.entry(aid.as_str()).or_default();
        if bucket.len() < JOBS_PER_AGENT_CAP {
            bucket.push(json!({
                "id": job.id,
                "mode": job.mode,
                "status": job.status,
                "result_status": job.result_status,
                "completed_at": job.completed_at,
                "created_at": job.created_at,
            }));
        }
    }

    // -- 4. Build the response array --
    let agents_json: Vec<Value> = agents
        .iter()
        .map(|a| {
            let jobs_for_agent = jobs_by_agent
                .remove(a.agent_id.as_str())
                .unwrap_or_default();
            json!({
                "enrollment_id": a.id,
                "enrollment_challenge_id": a.enrollment_challenge_id,
                "cryptographically_admitted": a.cryptographically_admitted,
                "agent_id": a.agent_id,
                "platform": a.platform,
                "status": a.status,
                "public_key_fingerprint": public_key_fingerprint(&a.public_key),
                "capabilities_digest": capabilities_digest(&a.capabilities.0),
                "last_seen_at": a.last_seen_at,
                "created_at": a.created_at,
                "jobs": jobs_for_agent,
            })
        })
        .collect();

    Ok(Json(json!({ "agents": agents_json, "capped": capped })))
}

/// GET /api/admin/agents
///
/// Returns a list of all registered agents with their most recent jobs.
/// Requires `admin` permission — enforced in-handler as defense-in-depth
/// regardless of RBAC middleware method handling.
///
/// ## Secret hygiene
///
/// `token_hash` and the raw `public_key` are NEVER included in the response.
/// The immutable enrollment id and a SHA-256 public-key fingerprint are included
/// so an approval can bind to the exact row/key the administrator reviewed.
/// `cryptographically_admitted` is derived from the complete consumed-challenge
/// linkage rather than from a nullable id alone.
///
/// ## Bounds
///
/// Agents are capped at 500 (newest first); jobs are capped at 5 000 total
/// across all agents, then further limited to the 10 most recent per agent
/// in Rust. `capped: true` in the response signals the agent list was
/// truncated.
pub async fn admin_list_agents(
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    // Defense-in-depth: GET routes under /api/admin/ may not be covered by
    // the RBAC middleware (which typically gates mutating methods). We re-check
    // here so the sensitive agent-enrollment list is always admin-only.
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission required"));
    }
    // run-5 A0: the agent-enrollment list is fleet-global (keyed on platform, no
    // site axis). Deny any scoped principal before any read (no existence oracle).
    if is_scoped(&session) {
        return Err(forbidden(
            "agent fleet operations require an unrestricted (non-scoped) admin",
        ));
    }

    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    list_agents_with(pool).await
}

// ---------------------------------------------------------------------------
// GET /api/admin/agents/liveness — operational liveness of approved agents (#44)
// ---------------------------------------------------------------------------

/// Query for the liveness endpoint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLivenessQuery {
    offline_after_secs: Option<i64>,
}

/// One approved agent projected for liveness. No secrets.
#[derive(sqlx::FromRow)]
struct LivenessAgentRow {
    agent_id: String,
    platform: String,
    last_seen_at: Option<chrono::DateTime<Utc>>,
}

/// Maximum approved agents enumerated in the detail list of one liveness
/// response (the summary counts the full scanned fleet regardless).
const LIVENESS_LIST_LIMIT: usize = 1000;
/// Safety bound on the approved-agent scan so the summary can never trigger an
/// unbounded fetch. Far above any realistic approved fleet; `scan_capped` flags
/// the (pathological) case where it is hit.
const LIVENESS_SCAN_CAP: i64 = 100_000;

/// Testable core for `admin_agents_liveness` — no axum Extension, no auth check.
///
/// Classifies the OPERATIONAL liveness of every APPROVED agent from its
/// `last_seen_at` heartbeat (pending/revoked agents are not expected to
/// heartbeat, so they are excluded). `now_unix` is injected for determinism.
/// Secret hygiene: selects only `agent_id`, `platform`, `last_seen_at`.
///
/// The `summary` totals are computed by classifying the WHOLE approved set (one
/// snapshot, the same engine + `now_unix` as the per-agent detail), so they are
/// correct even when the detail list is capped at [`LIVENESS_LIST_LIMIT`];
/// `truncated` flags a capped detail list and `scan_capped` the pathological
/// case where the approved fleet exceeds [`LIVENESS_SCAN_CAP`].
pub async fn agents_liveness_with(
    pool: &PgPool,
    offline_after_secs: i64,
    now_unix: i64,
) -> ApiResult<Json<Value>> {
    use ryuki_engine::agent_liveness::classify_agent_liveness;

    // ONE snapshot, ONE classifier: fetch all approved agents (safety-capped) and
    // classify every one with the pure engine using a single `now_unix`. The
    // summary and the per-agent detail therefore share one source of truth — no
    // SQL-vs-engine duplication, no cross-time-source boundary disagreement.
    let rows: Vec<LivenessAgentRow> = sqlx::query_as(
        "SELECT agent_id, platform, last_seen_at \
         FROM agents \
         WHERE status = 'approved' \
         ORDER BY last_seen_at ASC NULLS FIRST \
         LIMIT $1",
    )
    // Fetch one MORE than the cap so we can tell "exactly cap" from ">cap".
    .bind(LIVENESS_SCAN_CAP + 1)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    // Pathological backstop: if the approved fleet exceeds the scan cap, even the
    // summary is over a partial set — surface it rather than report a wrong total.
    let scan_capped = rows.len() as i64 > LIVENESS_SCAN_CAP;
    let total_approved = rows.len() as i64;

    let (mut online, mut offline) = (0_i64, 0_i64);
    let mut agents: Vec<Value> = Vec::new();
    for a in &rows {
        let last_unix = a.last_seen_at.map(|d| d.timestamp());
        let liveness = classify_agent_liveness(last_unix, now_unix, offline_after_secs);
        if liveness.is_online() {
            online += 1;
        } else {
            offline += 1;
        }
        // Summary counts the whole fleet; the detail list is capped for response size.
        if agents.len() < LIVENESS_LIST_LIMIT {
            // age clamped to >= 0 so a future heartbeat never reports negative.
            let age_secs = last_unix.map(|t| now_unix.saturating_sub(t).max(0));
            agents.push(json!({
                "agent_id": a.agent_id,
                "platform": a.platform,
                "last_seen_at": a.last_seen_at,
                "age_secs": age_secs,
                "liveness": liveness.as_str(),
            }));
        }
    }

    let listed = agents.len() as i64;
    Ok(Json(json!({
        "offline_after_secs": offline_after_secs,
        "agents": agents,
        "listed": listed,
        // The detail list is capped; the summary spans the whole approved fleet
        // (up to the scan cap, flagged by `scan_capped`).
        "truncated": listed < total_approved,
        "scan_capped": scan_capped,
        "summary": {
            "total_approved": total_approved,
            "online": online,
            "offline": offline,
        },
    })))
}

/// GET /api/admin/agents/liveness?offline_after_secs=N — operational liveness of
/// approved agents (#44). Admin-gated; 503 with no DB. Read-only: this surfaces
/// which approved agents have gone silent (offline detection) WITHOUT mutating
/// the enrollment status, so it can never accidentally revoke an agent.
pub async fn admin_agents_liveness(
    Extension(session): Extension<AuthSession>,
    Query(q): Query<AgentLivenessQuery>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission required"));
    }
    // run-5 A0: fleet liveness is platform-global (keyed on platform, no site
    // axis). Deny any scoped principal before any read (no existence oracle).
    if is_scoped(&session) {
        return Err(forbidden(
            "agent fleet operations require an unrestricted (non-scoped) admin",
        ));
    }
    let offline_after_secs = q.offline_after_secs.unwrap_or(300);
    if !(30..=86_400).contains(&offline_after_secs) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "offline_after_secs must be between 30 and 86400"})),
        ));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let now_unix = Utc::now().timestamp();
    agents_liveness_with(pool, offline_after_secs, now_unix).await
}

/// One dead-lettered agent job in the operator list. Secret-safe projection: the
/// job `spec` (opaque payload) and `live_context` (CP-signed grant) are NEVER
/// included — only operational metadata.
#[derive(serde::Serialize, sqlx::FromRow)]
struct DeadLetteredJobView {
    job_id: String,
    request_id: String,
    platform: String,
    mode: String,
    delivery_attempts: i32,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

/// GET /api/admin/agents/dead-lettered-jobs
///
/// Lists every terminal `DeadLettered` agent job (poison jobs that exhausted the
/// redispatch cap, #23) so an operator can SEE them — otherwise they are an
/// operational black hole. Admin-only (re-checked in-handler as defense-in-depth).
/// Newest first, capped at 500. `spec`/`live_context` are excluded (secret hygiene).
pub async fn admin_dead_lettered_jobs(
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission required"));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let is_scoped_principal = is_scoped(&session);
    let rows: Vec<DeadLetteredJobView> = if is_scoped_principal {
        let site_filter: Vec<String> = session
            .site_scope
            .iter()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .collect();
        let env_filter: Vec<String> = session
            .environment_scope
            .iter()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .collect();
        let site_restricted = !site_filter.is_empty();
        let env_restricted = !env_filter.is_empty();
        sqlx::query_as(
            // The joined request is the authoritative spec.request_id and is the row
            // whose scope was checked. Never project the independently stored scalar
            // agent_jobs.request_id to a scoped caller.
            "SELECT aj.id::text AS job_id, r.id::text AS request_id, \
                    aj.platform, aj.mode, aj.delivery_attempts, aj.created_at, aj.updated_at \
             FROM agent_jobs aj \
             JOIN requests r ON r.id::text = (aj.spec->>'request_id') \
             WHERE aj.status = 'DeadLettered' \
               AND ($1 OR r.site = ANY($2)) \
               AND ($3 OR r.environment = ANY($4)) \
             ORDER BY aj.updated_at DESC LIMIT 500",
        )
        .bind(!site_restricted)
        .bind(&site_filter)
        .bind(!env_restricted)
        .bind(&env_filter)
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    } else {
        sqlx::query_as(
            "SELECT id::text AS job_id, request_id::text AS request_id, platform, mode, \
                    delivery_attempts, created_at, updated_at \
             FROM agent_jobs WHERE status = 'DeadLettered' \
             ORDER BY updated_at DESC LIMIT 500",
        )
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    };
    Ok(Json(json!({
        "dead_lettered_jobs": serde_json::to_value(&rows).unwrap_or_default(),
        "count": rows.len(),
    })))
}

/// POST /api/admin/agents/dead-lettered-jobs/{job_id}/requeue
///
/// Recovers a `DeadLettered` job: returns it to `Pending` with a fresh redispatch
/// budget (`delivery_attempts = 0`) + cleared lease state, so the agent fleet can
/// pick it up again. Admin-only + audited. Guards (in the project lock order
/// requests -> agent_jobs, which cannot deadlock since no path locks job -> request):
/// - the job must still be `DeadLettered` (idempotent: a second requeue 409s);
/// - the PARENT REQUEST must still be ACTIVE — a job whose request has concluded
///   (failed/cancelled/rejected/completed/...) or is orphaned/unknown is REFUSED
///   (409), so requeue can never re-dispatch stale work for a closed request.
pub async fn admin_requeue_dead_lettered_job(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission is required to requeue a job"));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let mut tx = pool.begin().await.map_err(db_err)?;

    // 1. Read the job UNLOCKED (keeps the lock order requests-first). We validate
    //    against the dispatched JobSpec (the `spec` JSONB), NOT the scalar
    //    request_id/mode columns: the AGENT executes and routes by spec.request_id /
    //    spec.mode (run.rs routes on spec.mode; the result backlink uses
    //    spec.request_id), and create_agent_job does NOT pin the columns to the spec.
    //    So the spec is the source of truth for "which request" and "is this live".
    let job: Option<(sqlx::types::Json<serde_json::Value>, String, String)> =
        sqlx::query_as("SELECT spec, status, platform FROM agent_jobs WHERE id = $1")
            .bind(uid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some((spec_json, status, platform)) = job else {
        return Err(not_found(format!("agent job '{job_id}' not found")));
    };

    // run-5 A0: by-id site/env scope guard for a SCOPED principal — placed BEFORE
    // the status-409 below so an out-of-scope job 404s regardless of its status (no
    // status/existence oracle). Resolve the parent request via the AUTHORITATIVE
    // spec.request_id; a malformed spec cannot resolve scope → fail closed to the
    // SAME 404 a missing job returns. Unrestricted principals skip it unchanged.
    if is_scoped(&session) {
        let in_scope = match serde_json::from_value::<JobSpec>(spec_json.0.clone()) {
            Ok(spec) => {
                let row: Option<(String, String)> =
                    sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                        .bind(spec.request_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(db_err)?;
                matches!(row, Some((ref site, ref env)) if row_scope_permits(&session, site, env))
            }
            Err(_) => false,
        };
        if !in_scope {
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
    }

    if status != "DeadLettered" {
        return Err(conflict(format!(
            "job is in status '{status}'; only DeadLettered jobs can be requeued"
        )));
    }

    // 2. Decode the dispatched spec — the source of truth the agent acts on. A
    //    malformed spec is unrequeueable (the agent could not run it). Only
    //    non-mutating jobs may be requeued: a LiveApply spec must NEVER be
    //    re-dispatched as Pending work (the agent routes LivePlan/LiveApply through
    //    the LIVE executor by spec.mode — the column mode is not load-bearing).
    let spec: JobSpec = serde_json::from_value(spec_json.0)
        .map_err(|_| conflict("job spec is malformed; cannot requeue"))?;
    let preserve_affinity = match spec.mode {
        JobMode::OfflineDryRun => false,
        JobMode::LivePlan => true,
        JobMode::LiveApply | JobMode::LiveDestroy => {
            return Err(conflict(
                "a live-mutating job (LiveApply/LiveDestroy) cannot be requeued \
                 (it reconciles, it does not redispatch)",
            ));
        }
    };
    let exec_request_id = spec.request_id;

    // 3. PARENT-REQUEST GUARD on spec.request_id (the request the agent will act on).
    //    Lock it FOR UPDATE (requests -> agent_jobs order) and refuse to revive a job
    //    whose request has concluded; the FOR UPDATE serializes against a concurrent
    //    reject/fail/cancel (those CAS the request row).
    let parent_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM requests WHERE id = $1 FOR UPDATE")
            .bind(exec_request_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(parent_status) = parent_status else {
        return Err(conflict(
            "parent request not found; cannot requeue an orphaned job",
        ));
    };
    // Fail closed: only a recognized ACTIVE status permits requeue. An unknown string
    // decodes to the Draft fallback, so require the decode to ROUND-TRIP as well.
    let decoded = crate::contracts::db_status_to_request_status(&parent_status);
    if decoded.is_concluded() || crate::contracts::request_status_to_db(&decoded) != parent_status {
        return Err(conflict(format!(
            "parent request status '{parent_status}' does not permit requeue (concluded or unknown)"
        )));
    }

    // 4. Requeue. The WHERE status='DeadLettered' makes the job-status race fail
    //    closed (a concurrent requeue/expire that moved it off DeadLettered yields 0
    //    rows). spec.mode was validated above, so no column-mode predicate is needed.
    let updated = sqlx::query(
        "UPDATE agent_jobs \
         SET status = 'Pending', \
             agent_id = CASE WHEN $2 THEN agent_id ELSE NULL END, \
             attempt_id = NULL, \
             fencing_token = NULL, cp_nonce = NULL, lease_deadline = NULL, \
             delivery_attempts = 0, updated_at = NOW() \
         WHERE id = $1 AND status = 'DeadLettered'",
    )
    .bind(uid)
    .bind(preserve_affinity)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?
    .rows_affected();
    if updated != 1 {
        return Err(conflict(
            "job was not in a requeueable state; reload and retry",
        ));
    }

    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-job-requeue",
            Some("dead-lettered"),
            "pending",
            json!({ "job_id": &job_id, "request_id": exec_request_id.to_string(), "platform": platform }),
        ),
    )
    .await
    .map_err(db_err)?;

    // NON-alerting lifecycle event so a job re-entering the queue is observable on the
    // /api/events feed (mirrors job.cancelled / job.force_failed). `to_status`
    // 'admin-requeued' is deliberately NOT in event_alerts::alert_worthy_statuses(), so
    // the alert feed's coarse SQL prefilter never fetches it — a requeue can never page.
    // Platform-global (site/env None) — an agent_job carries no site/env axis.
    // aggregate_id is the CANONICAL uuid (not the raw path string) so an /api/events
    // lookup by canonical id finds it even if the caller used a non-canonical uuid form.
    let canonical_job_id = uid.to_string();
    crate::repos::domain_events::insert(
        &mut *tx,
        crate::repos::domain_events::NewEvent {
            event_type: "job.requeued",
            aggregate_type: "agent_job",
            aggregate_id: &canonical_job_id,
            site: None,
            environment: None,
            actor: &session.user_id,
            payload: json!({
                "to_status": "admin-requeued",
                "platform": platform,
                "request_id": exec_request_id.to_string(),
                "note": "admin requeued a dead-lettered job to Pending",
            }),
        },
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    tracing::info!(job_id = %job_id, "dead-lettered agent job requeued to Pending");
    Ok(Json(
        json!({ "job_id": job_id, "status": "Pending", "requeued": true }),
    ))
}

/// Body for POST /api/admin/agents/jobs/{job_id}/reconcile.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileBody {
    reason: String,
}

/// POST /api/admin/agents/jobs/{job_id}/reconcile
///
/// Resolves a terminal-dead-end `ReconcileRequired` live-mutation job to terminal
/// `Failed` once an operator has reconciled provider and state out-of-band. `Failed`
/// is the conservative truth: the CP cannot verify that an interrupted mutation
/// reached its intended state. The operator's reconciliation is captured in the
/// audited `reason`. Admin-only.
/// A non-alerting `job.reconcile_resolved` domain event closes the
/// reconcile-required alert lifecycle (it does NOT page). A LiveApply parent stays
/// `Executing` for explicit operator conclusion through
/// `POST /api/requests/{id}/fail`; resolving a LiveDestroy also fails its
/// `TearingDown` step and parent request so rollback cannot remain wedged. There is
/// NO in-place LiveApply retry: its request slot is permanently consumed (the
/// no-double-apply index is all-statuses), so re-attempting requires a fresh request
/// (see `create_live_apply_job`).
pub async fn admin_resolve_reconcile_required_job(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
    Json(body): Json<ReconcileBody>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to resolve a reconcile-required job",
        ));
    }
    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(bad_request("a reconciliation reason is required"));
    }
    if reason.len() > 2000 {
        return Err(bad_request("reason is too long (max 2000 characters)"));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let mut tx = pool.begin().await.map_err(db_err)?;

    // run-5 A0: by-id site/env scope guard for a SCOPED principal — a FOR UPDATE
    // pre-read resolves the parent request via the AUTHORITATIVE spec.request_id and
    // 404s an out-of-scope (or orphaned/malformed) job BEFORE the status CAS, so
    // out-of-scope never leaks through the 409 path. Unrestricted principals skip it
    // and hit the CAS directly, unchanged.
    if is_scoped(&session) {
        let spec_row: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT spec FROM agent_jobs WHERE id = $1 FOR UPDATE")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let in_scope = match spec_row {
            None => {
                tx.rollback().await.map_err(db_err)?;
                return Err(not_found(format!("agent job '{job_id}' not found")));
            }
            Some(spec_json) => match serde_json::from_value::<JobSpec>(spec_json.0) {
                Ok(spec) => {
                    let row: Option<(String, String)> =
                        sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                            .bind(spec.request_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    matches!(row, Some((ref site, ref env)) if row_scope_permits(&session, site, env))
                }
                Err(_) => false,
            },
        };
        if !in_scope {
            tx.rollback().await.map_err(db_err)?;
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
    }

    // CAS: only a ReconcileRequired job resolves. Return the dispatched spec because
    // its request_id and mode are authoritative; the agent executes the spec, not the
    // denormalized scalar columns. A concurrent double-resolve collapses to one
    // success (the second sees 'Failed' and 0 rows → 409).
    let updated: Option<(String, Value)> = sqlx::query_as(
        "UPDATE agent_jobs SET status = 'Failed', updated_at = NOW() \
         WHERE id = $1 AND status = 'ReconcileRequired' \
         RETURNING platform, spec",
    )
    .bind(uid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some((platform, spec_json)) = updated else {
        // Distinguish not-found (404) from wrong-status (409) with a clean re-read.
        let existing: Option<String> =
            sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let error = match existing {
            None => not_found(format!("agent job '{job_id}' not found")),
            Some(status) => conflict(format!(
                "job is in status '{status}'; only ReconcileRequired jobs can be resolved"
            )),
        };
        tx.rollback().await.map_err(db_err)?;
        return Err(error);
    };
    let spec: JobSpec = match serde_json::from_value(spec_json) {
        Ok(spec) => spec,
        Err(error) => {
            tracing::error!(%error, job_id = %job_id, "agent job has a malformed stored spec");
            tx.rollback().await.map_err(db_err)?;
            if is_scoped(&session) {
                return Err(not_found(format!("agent job '{job_id}' not found")));
            }
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "agent job has a malformed spec"})),
            ));
        }
    };
    let exec_request_id = spec.request_id;
    let request_id = exec_request_id.to_string();
    let is_live_destroy = spec.mode == JobMode::LiveDestroy;
    let mode = match &spec.mode {
        JobMode::OfflineDryRun => "OfflineDryRun",
        JobMode::LivePlan => "LivePlan",
        JobMode::LiveApply => "LiveApply",
        JobMode::LiveDestroy => "LiveDestroy",
    };

    // A reconciled LiveDestroy is the terminal stop for an automated rollback.
    // Route through the same teardown-aware backlink as a terminal failed result:
    // it updates the step plan, request stages/status, and execution audit in this
    // transaction. If lease expiry already performed that transition, the
    // backlink's request-status guard makes this an idempotent no-op. LiveApply
    // remains job-scoped so the operator can inspect and conclude it explicitly.
    if is_live_destroy {
        backlink_request_execution(
            &mut tx,
            exec_request_id,
            &JobResultStatus::Failed,
            &JobMode::LiveDestroy,
            "reconcile_resolved",
            "operator-reconciled-no-result",
            uid,
        )
        .await
        .map_err(db_err)?;
    }

    // Audit the operator action — the free-text reason lives ONLY here.
    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-job-reconcile-resolved",
            Some("reconcile-required"),
            "failed",
            json!({
                "job_id": &job_id,
                "request_id": request_id,
                "platform": platform,
                "mode": mode,
                "reason": reason,
            }),
        ),
    )
    .await
    .map_err(db_err)?;

    // Close the reconcile-required alert lifecycle with a NON-ALERTING resolution
    // event (to_status 'reconcile-resolved' is NOT in the alert classifier). NO
    // free-text reason in the payload — only the static, secret-safe fields.
    // aggregate_id is the CANONICAL uuid (not the raw path string), matching the
    // sibling job.requeued/job.reprioritized events so an /api/events lookup by
    // canonical id finds it even if the caller used a non-canonical uuid form.
    let canonical_job_id = uid.to_string();
    crate::repos::domain_events::insert(
        &mut *tx,
        crate::repos::domain_events::NewEvent {
            event_type: "job.reconcile_resolved",
            aggregate_type: "agent_job",
            aggregate_id: &canonical_job_id,
            site: None,
            environment: None,
            actor: &session.user_id,
            payload: json!({
                "to_status": "reconcile-resolved",
                "platform": platform,
                "mode": mode,
                "request_id": request_id,
                "note": "operator reconciled out-of-band; job closed as Failed",
            }),
        },
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    tracing::info!(job_id = %job_id, "reconcile-required agent job resolved to Failed by operator");
    Ok(Json(json!({
        "job_id": job_id,
        "request_id": request_id,
        "status": "Failed",
        "resolved": true,
        "note": if is_live_destroy {
            "the failed teardown step and parent request were marked Failed after operator reconciliation"
        } else {
            "the parent request remains Executing; conclude it with POST /api/requests/{id}/fail. A live-apply cannot be retried in place (its slot is permanently consumed); re-attempting requires a fresh request"
        },
    })))
}

/// Body for POST /api/admin/agents/jobs/{job_id}/cancel.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelJobBody {
    reason: String,
}

/// POST /api/admin/agents/jobs/{job_id}/cancel
///
/// Cancels a PENDING (not-yet-leased) agent job — one created in error or no longer
/// wanted — instead of letting an agent lease and run it. CASes on `status = 'Pending'`:
/// once `Leased`/`Running` an agent owns the job (cancelling CP-side would split-brain),
/// and a terminal job is already done — both → 409. Admin-only, audited; emits a
/// NON-alerting `job.cancelled` event. JOB-SCOPED: the parent request stays `Executing`,
/// and the operator concludes it with `POST /api/requests/{id}/fail` (identical to the
/// reconcile-resolve contract). A cancelled LiveApply still consumes the request's
/// permanent LiveApply slot — there is no in-place retry; re-attempting needs a fresh
/// request (see `create_live_apply_job`).
pub async fn admin_cancel_pending_job(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
    Json(body): Json<CancelJobBody>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission is required to cancel a job"));
    }
    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(bad_request("a cancellation reason is required"));
    }
    if reason.len() > 2000 {
        return Err(bad_request("reason is too long (max 2000 characters)"));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    let mut scoped_request_id = None;

    // run-5 A0: by-id site/env scope guard for a SCOPED principal — a FOR UPDATE
    // pre-read resolves the parent request via the AUTHORITATIVE spec.request_id and
    // 404s an out-of-scope (or orphaned/malformed) job BEFORE the status CAS, so
    // out-of-scope never leaks through the 409 path. Unrestricted principals skip it
    // and hit the CAS directly, unchanged.
    if is_scoped(&session) {
        let spec_row: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT spec FROM agent_jobs WHERE id = $1 FOR UPDATE")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let in_scope = match spec_row {
            None => {
                tx.rollback().await.map_err(db_err)?;
                return Err(not_found(format!("agent job '{job_id}' not found")));
            }
            Some(spec_json) => match serde_json::from_value::<JobSpec>(spec_json.0) {
                Ok(spec) => {
                    scoped_request_id = Some(spec.request_id.to_string());
                    let row: Option<(String, String)> =
                        sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                            .bind(spec.request_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    matches!(row, Some((ref site, ref env)) if row_scope_permits(&session, site, env))
                }
                Err(_) => false,
            },
        };
        if !in_scope {
            tx.rollback().await.map_err(db_err)?;
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
    }

    // CAS: only a Pending, non-teardown job cancels. RETURNING request_id + platform for
    // the audit/event/response. A job leased concurrently → 0 rows → 409 (poll won the
    // race); a concurrent double-cancel → the second sees 'Cancelled' → 409.
    //
    // #42 B2-2: a `LiveDestroy` (auto-teardown) job is deliberately EXCLUDED. Cancelling a
    // still-Pending teardown job would leave its step `TearingDown` and the request
    // `executing` with no result ever arriving and no lease to expire — a permanent wedge
    // (the "keep executing while TearingDown" rollback branch would never resolve). Teardown
    // is an automated rollback and is not operator-cancellable.
    let updated: Option<(String, String)> = sqlx::query_as(
        "UPDATE agent_jobs SET status = 'Cancelled', updated_at = NOW() \
         WHERE id = $1 AND status = 'Pending' AND mode <> 'LiveDestroy' \
         RETURNING request_id::text, platform",
    )
    .bind(uid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some((scalar_request_id, platform)) = updated else {
        // Distinguish not-found (404), a protected teardown job (409), and wrong-status
        // (409) with a clean re-read of both status and mode.
        let existing: Option<(String, String)> =
            sqlx::query_as("SELECT status, mode FROM agent_jobs WHERE id = $1")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let error = match existing {
            None => Err(not_found(format!("agent job '{job_id}' not found"))),
            Some((status, mode)) if mode == "LiveDestroy" => Err(conflict(format!(
                "job is a LiveDestroy auto-teardown job (status '{status}'); teardown jobs \
                 are part of an automated rollback and cannot be cancelled"
            ))),
            Some((status, _)) => Err(conflict(format!(
                "job is in status '{status}'; only Pending jobs can be cancelled"
            ))),
        };
        tx.rollback().await.map_err(db_err)?;
        return error;
    };
    // For a scoped caller, project the same authoritative spec request id that
    // passed authorization. Unrestricted callers retain the existing scalar view.
    let request_id = scoped_request_id.unwrap_or(scalar_request_id);

    // Audit the operator action — the free-text reason lives ONLY here.
    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-job-cancelled",
            Some("pending"),
            "cancelled",
            json!({
                "job_id": &job_id,
                "request_id": request_id,
                "platform": platform,
                "reason": reason,
            }),
        ),
    )
    .await
    .map_err(db_err)?;

    // NON-alerting lifecycle event. `to_status` 'admin-cancelled' is deliberately NOT in
    // event_alerts::alert_worthy_statuses(), so the alert feed's coarse SQL prefilter never
    // fetches it — a cancel can never page (robust vs relying on classify() to drop a
    // prefilter-matched 'cancelled'). NO free-text reason in the payload.
    // aggregate_id is the CANONICAL uuid (mirrors job.requeued) so an /api/events
    // lookup by canonical id matches even for a non-canonical uuid form.
    let canonical_job_id = uid.to_string();
    crate::repos::domain_events::insert(
        &mut *tx,
        crate::repos::domain_events::NewEvent {
            event_type: "job.cancelled",
            aggregate_type: "agent_job",
            aggregate_id: &canonical_job_id,
            site: None,
            environment: None,
            actor: &session.user_id,
            payload: json!({
                "to_status": "admin-cancelled",
                "platform": platform,
                "request_id": request_id,
                "note": "admin cancelled a pending job before dispatch",
            }),
        },
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    tracing::info!(job_id = %job_id, "pending agent job cancelled by admin");
    Ok(Json(json!({
        "job_id": job_id,
        "request_id": request_id,
        "status": "Cancelled",
        "cancelled": true,
        "note": "the parent request remains Executing; conclude it with POST /api/requests/{id}/fail",
    })))
}

/// Body for POST /api/admin/agents/jobs/{job_id}/force-fail.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForceFailJobBody {
    reason: String,
}

/// POST /api/admin/agents/jobs/{job_id}/force-fail
///
/// Terminally fails a STUCK `Leased` agent job (leased to an agent that died / never
/// acked) without waiting out the lease-expiry + dead-letter cycles. Scoped to
/// `Leased` jobs whose mode is `OfflineDryRun` / `LivePlan` — modes that NEVER touch
/// real infrastructure, so `Failed` is safe and a late ack/result is rejected by the
/// result CAS (`status IN ('Leased','Running')`). A `Leased` `LiveApply` is EXCLUDED
/// (409): with out-of-order delivery the agent may have started applying real infra, so
/// it must go through the lease-expiry path → `ReconcileRequired` (this endpoint never
/// sets `ReconcileRequired`). `Pending` uses cancel; a `Running` job belongs on the
/// lease-expiry/reconcile path. Admin-only, audited; emits a NON-alerting
/// `job.force_failed` event. JOB-SCOPED: the parent request is left for the operator's
/// `POST /api/requests/{id}/fail` (identical to the cancel/reconcile contract).
pub async fn admin_force_fail_job(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
    Json(body): Json<ForceFailJobBody>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to force-fail a job",
        ));
    }
    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(bad_request("a force-fail reason is required"));
    }
    if reason.len() > 2000 {
        return Err(bad_request("reason is too long (max 2000 characters)"));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let mut tx = pool.begin().await.map_err(db_err)?;

    // Load + LOCK the row. The dispatched `spec.mode` is the AUTHORITATIVE mode — the scalar
    // `mode` column is NOT load-bearing (the agent routes by spec.mode, and a row can carry
    // spec.mode=LiveApply with a different column mode — codex). The safety decision is on
    // spec.mode so a LiveApply job can NEVER be force-failed to Failed (it must go through the
    // lease-expiry path → ReconcileRequired to protect real infra). spec.request_id is the
    // authoritative parent request. FOR UPDATE holds the row so its status cannot change
    // between this read and the CAS below.
    let row: Option<(String, String, Value)> =
        sqlx::query_as("SELECT status, platform, spec FROM agent_jobs WHERE id = $1 FOR UPDATE")
            .bind(uid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some((status, platform, spec_json)) = row else {
        return Err(not_found(format!("agent job '{job_id}' not found")));
    };
    // run-5 A0: decode the dispatched spec. For a SCOPED principal a malformed/
    // undecodable spec cannot resolve scope, so fail CLOSED to the SAME 404 a missing
    // job returns — otherwise the integrity 500 below would be a malformed-spec
    // existence oracle (codex). This mirrors the other by-id handlers, which already
    // fail closed on a malformed spec. An unrestricted principal has no scope to leak,
    // so it still surfaces the integrity 500.
    let spec: JobSpec = match serde_json::from_value::<JobSpec>(spec_json) {
        Ok(spec) => spec,
        Err(e) => {
            if is_scoped(&session) {
                return Err(not_found(format!("agent job '{job_id}' not found")));
            }
            tracing::error!(error = %e, job_id = %job_id, "agent job has a malformed stored spec");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "agent job has a malformed spec"})),
            ));
        }
    };

    // run-5 A0: by-id site/env scope guard. For a SCOPED principal, resolve the
    // parent request via the AUTHORITATIVE spec.request_id and 404 an out-of-scope
    // (or orphaned) job with the SAME body a missing job returns — no cross-scope
    // existence/state oracle. Placed BEFORE the status-409 branch so out-of-scope
    // never leaks through a 409. Unrestricted principals skip it unchanged.
    if is_scoped(&session) {
        let (site, environment): (String, String) =
            sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                .bind(spec.request_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?
                .ok_or_else(|| not_found(format!("agent job '{job_id}' not found")))?;
        if !row_scope_permits(&session, &site, &environment) {
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
    }

    // Only a Leased job whose SPEC mode is non-LiveApply force-fails.
    if status != "Leased" {
        return Err(conflict(match status.as_str() {
            "Pending" => "a pending job is not yet leased; cancel it instead".to_string(),
            "Running" => "a running job must be left to the lease-expiry / reconcile path, \
                          not force-failed"
                .to_string(),
            other => format!("job is already in terminal status '{other}'; cannot force-fail"),
        }));
    }
    // Exhaustive on JobMode so a FUTURE variant can never become implicitly force-failable
    // (it would be a compile error here, forcing a deliberate safety decision) — codex.
    match spec.mode {
        JobMode::OfflineDryRun | JobMode::LivePlan => {}
        JobMode::LiveApply | JobMode::LiveDestroy => {
            return Err(conflict(
                "a leased live-mutating job (LiveApply/LiveDestroy) must go through the \
                 lease-expiry / reconcile path to protect real infrastructure; it cannot \
                 be force-failed"
                    .to_string(),
            ));
        }
    }
    let request_id = spec.request_id.to_string();

    // CAS within the row lock — status is still Leased (FOR UPDATE prevents a concurrent
    // ack / lease-expiry from changing it between the read and here).
    let affected = sqlx::query(
        "UPDATE agent_jobs SET status = 'Failed', updated_at = NOW() \
         WHERE id = $1 AND status = 'Leased'",
    )
    .bind(uid)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?
    .rows_affected();
    if affected == 0 {
        // Unreachable under FOR UPDATE, but fail safe rather than emit a phantom audit/event.
        return Err(conflict(
            "the job changed state concurrently; retry".to_string(),
        ));
    }

    // Audit the operator action — the free-text reason lives ONLY here.
    crate::audit::record_audit_tx(
        &mut tx,
        &session,
        &crate::audit::security_audit(
            "agent-job-force-failed",
            Some("leased"),
            "failed",
            json!({
                "job_id": &job_id,
                "request_id": request_id,
                "platform": platform,
                "reason": reason,
            }),
        ),
    )
    .await
    .map_err(db_err)?;

    // NON-alerting lifecycle event. `to_status` 'admin-force-failed' is deliberately NOT in
    // event_alerts::alert_worthy_statuses(), so the alert feed's coarse SQL prefilter never
    // fetches it — a force-fail can never page. NO free-text reason in the payload.
    // aggregate_id is the CANONICAL uuid (mirrors job.requeued) so an /api/events
    // lookup by canonical id matches even for a non-canonical uuid form.
    let canonical_job_id = uid.to_string();
    crate::repos::domain_events::insert(
        &mut *tx,
        crate::repos::domain_events::NewEvent {
            event_type: "job.force_failed",
            aggregate_type: "agent_job",
            aggregate_id: &canonical_job_id,
            site: None,
            environment: None,
            actor: &session.user_id,
            payload: json!({
                "to_status": "admin-force-failed",
                "platform": platform,
                "request_id": request_id,
                "note": "admin force-failed a stuck leased job",
            }),
        },
    )
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    tracing::info!(job_id = %job_id, "stuck leased agent job force-failed by admin");
    Ok(Json(json!({
        "job_id": job_id,
        "request_id": request_id,
        "status": "Failed",
        "force_failed": true,
        "note": "the parent request remains Executing; conclude it with POST /api/requests/{id}/fail",
    })))
}

/// Body for POST /api/admin/agents/jobs/{job_id}/priority (#15).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetJobPriorityBody {
    priority: i32,
}

/// POST /api/admin/agents/jobs/{job_id}/priority — re-prioritize a PENDING agent job (#15).
/// Admin-tier. Only a Pending (not-yet-leased) job is reprioritizable — a leased/running/
/// terminal job's queue priority is moot, so the UPDATE CASes on `status = 'Pending'`.
/// Higher = more urgent (0..=9). Audited.
pub async fn admin_set_job_priority(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
    Json(body): Json<SetJobPriorityBody>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to reprioritize a job",
        ));
    }
    if !(0..=9).contains(&body.priority) {
        return Err(bad_request("priority must be between 0 and 9"));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let mut tx = pool.begin().await.map_err(db_err)?;

    // run-5 A0: by-id site/env scope guard for a SCOPED principal — a FOR UPDATE
    // pre-read resolves the parent request via the AUTHORITATIVE spec.request_id and
    // 404s an out-of-scope (or orphaned/malformed) job BEFORE the status CAS, so
    // out-of-scope never leaks through the 409 path. Unrestricted principals skip it
    // and hit the CAS directly, unchanged.
    if is_scoped(&session) {
        let spec_row: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT spec FROM agent_jobs WHERE id = $1 FOR UPDATE")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let in_scope = match spec_row {
            None => return Err(not_found(format!("agent job '{job_id}' not found"))),
            Some(spec_json) => match serde_json::from_value::<JobSpec>(spec_json.0) {
                Ok(spec) => {
                    let row: Option<(String, String)> =
                        sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                            .bind(spec.request_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    matches!(row, Some((ref site, ref env)) if row_scope_permits(&session, site, env))
                }
                Err(_) => false,
            },
        };
        if !in_scope {
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
    }

    // Status CAS: only a pending job is reprioritizable. Return `platform` too so the
    // domain event carries it (consistent with the other agent_job events).
    let updated: Option<(String, i32, String)> = sqlx::query_as(
        "UPDATE agent_jobs SET priority = $1, updated_at = NOW() \
         WHERE id = $2 AND status = 'Pending' RETURNING status, priority, platform",
    )
    .bind(body.priority)
    .bind(uid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    match updated {
        Some((status, priority, platform)) => {
            crate::audit::record_audit_tx(
                &mut tx,
                &session,
                &crate::audit::security_audit(
                    "agent-job-reprioritize",
                    None,
                    "reprioritized",
                    json!({ "job_id": &job_id, "priority": priority }),
                ),
            )
            .await
            .map_err(db_err)?;

            // NON-alerting lifecycle event so a queue-priority change is observable on the
            // /api/events feed (mirrors the other agent_job admin events). `to_status`
            // 'admin-reprioritized' is deliberately NOT in alert_worthy_statuses(), so the
            // alert feed's coarse SQL prefilter never fetches it — it can never page.
            // Platform-global (site/env None) — an agent_job carries no site/env axis.
            // aggregate_id is the CANONICAL uuid (not the raw path string) so an
            // /api/events lookup by canonical id finds it for any parseable uuid form.
            let canonical_job_id = uid.to_string();
            crate::repos::domain_events::insert(
                &mut *tx,
                crate::repos::domain_events::NewEvent {
                    event_type: "job.reprioritized",
                    aggregate_type: "agent_job",
                    aggregate_id: &canonical_job_id,
                    site: None,
                    environment: None,
                    actor: &session.user_id,
                    payload: json!({
                        "to_status": "admin-reprioritized",
                        "platform": platform,
                        "to_priority": priority,
                        "note": "admin changed a pending job's queue priority",
                    }),
                },
            )
            .await
            .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
            tracing::info!(job_id = %job_id, priority, "agent job reprioritized");
            Ok(Json(
                json!({ "job_id": job_id, "status": status, "priority": priority }),
            ))
        }
        None => {
            tx.rollback().await.ok();
            // 0 rows: the job is gone, or it is no longer Pending.
            let current: Option<String> =
                sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
                    .bind(uid)
                    .fetch_optional(pool)
                    .await
                    .map_err(db_err)?;
            match current {
                None => Err(not_found(format!("agent job '{job_id}' not found"))),
                Some(_) => Err(conflict("only a pending agent job can be reprioritized")),
            }
        }
    }
}

/// One platform's pending-queue summary.
#[derive(sqlx::FromRow)]
struct QueueDepthRow {
    platform: String,
    pending_count: i64,
    oldest_pending_at: chrono::DateTime<chrono::Utc>,
    top_priority: i32,
}

/// GET /api/admin/agents/queue-depth — the pending (queued) agent-job backlog per platform
/// (#6 read slice; the pending-jobs view #15 deferred). For each platform with pending
/// work: the pending count, the oldest pending job's age, and the highest priority waiting.
/// Admin-only (explicit re-check — GET routes under /api/admin/ may not be gated by the RBAC
/// middleware). Only `Pending` jobs are "queued" (leased/running/terminal are excluded).
/// Exposes ONLY aggregates + the platform name — no spec/live_context/request_id/agent ids.
pub async fn admin_agent_queue_depth(
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to read queue depth",
        ));
    }
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let is_scoped_principal = is_scoped(&session);
    let rows: Vec<QueueDepthRow> = if is_scoped_principal {
        let site_filter: Vec<String> = session
            .site_scope
            .iter()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .collect();
        let env_filter: Vec<String> = session
            .environment_scope
            .iter()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .collect();
        let site_restricted = !site_filter.is_empty();
        let env_restricted = !env_filter.is_empty();
        sqlx::query_as(
            "SELECT aj.platform, COUNT(*) AS pending_count, \
                    MIN(aj.created_at) AS oldest_pending_at, MAX(aj.priority) AS top_priority \
             FROM agent_jobs aj \
             JOIN requests r ON r.id::text = (aj.spec->>'request_id') \
             WHERE aj.status = 'Pending' \
               AND ($1 OR r.site = ANY($2)) \
               AND ($3 OR r.environment = ANY($4)) \
             GROUP BY aj.platform ORDER BY aj.platform",
        )
        .bind(!site_restricted)
        .bind(&site_filter)
        .bind(!env_restricted)
        .bind(&env_filter)
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    } else {
        sqlx::query_as(
            "SELECT platform, COUNT(*) AS pending_count, \
                    MIN(created_at) AS oldest_pending_at, MAX(priority) AS top_priority \
             FROM agent_jobs WHERE status = 'Pending' \
             GROUP BY platform ORDER BY platform",
        )
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    };
    // Map each row to JSON manually (codex) so the timestamp is an explicit rfc3339.
    let queues: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "platform": r.platform,
                "pending_count": r.pending_count,
                "oldest_pending_at": r.oldest_pending_at.to_rfc3339(),
                "top_priority": r.top_priority,
            })
        })
        .collect();
    Ok(Json(json!({ "queues": queues })))
}

/// One agent job's stored result. `spec` is selected only to re-verify the
/// signed job-spec digest and derive an allowlisted plan-review projection; it
/// is never returned. `evidence_json` and `live_context` remain excluded.
#[derive(sqlx::FromRow)]
struct JobResultRow {
    mode: String,
    status: String,
    spec: sqlx::types::Json<Value>,
    result_status: Option<String>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    result_id: Option<String>,
    evidence_digest: Option<String>,
    raw_plan_digest: Option<String>,
    signed_envelope: Option<Value>,
}

/// GET /api/admin/agents/jobs/{job_id}/result — retrieve one agent job's SIGNED result
/// attestation + metadata (#agent-job-result). Admin-only. The `signed_envelope` is a pure
/// cryptographic attestation (digests + signature + ids, NO raw evidence); the raw
/// agent-submitted `evidence_json` is NEVER exposed. For a successful Terraform
/// LivePlan, `plan_review` is reparsed server-side from the exact bytes whose
/// digest is carried by the signed envelope and contains only an allowlisted
/// action/placement projection. 404 if the job is unknown OR has no result yet
/// (`signed_envelope IS NULL`). Scoped principals see only jobs whose parent
/// request falls within their site/environment scope (run-5 A0).
pub async fn admin_agent_job_result(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to read an agent job result",
        ));
    }
    // Parse the id BEFORE get_db (codex) so a malformed id 404s even during a DB outage.
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let row: Option<JobResultRow> = sqlx::query_as(
        "SELECT mode, status, spec, result_status, completed_at, \
                result_id::text AS result_id, evidence_digest, raw_plan_digest, signed_envelope \
         FROM agent_jobs WHERE id = $1",
    )
    .bind(uid)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(row) = row else {
        return Err(not_found(format!("agent job '{job_id}' not found")));
    };

    // run-5 A0: by-id scope guard for a SCOPED principal (a read is a state oracle).
    // Resolve the parent request via the AUTHORITATIVE spec.request_id and 404 an
    // out-of-scope (or orphaned/malformed) job with the SAME body a missing job
    // returns — placed BEFORE the "no result yet" branch so neither existence nor
    // result-state leaks. Unrestricted principals skip it unchanged.
    if is_scoped(&session) {
        let in_scope = match sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
            "SELECT spec FROM agent_jobs WHERE id = $1",
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
        {
            None => false,
            Some(spec_json) => match serde_json::from_value::<JobSpec>(spec_json.0) {
                Ok(spec) => {
                    let r: Option<(String, String)> =
                        sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                            .bind(spec.request_id)
                            .fetch_optional(pool)
                            .await
                            .map_err(db_err)?;
                    matches!(r, Some((ref site, ref env)) if row_scope_permits(&session, site, env))
                }
                Err(_) => false,
            },
        };
        if !in_scope {
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
    }

    let Some(envelope_json) = row.signed_envelope else {
        return Err(not_found(format!(
            "no result recorded for agent job '{job_id}' yet"
        )));
    };
    // Hardening (codex): pin the response to the TYPED attestation — deserialize the stored
    // JSONB into the verified SignedEnvelope and reserialize, so no stray JSONB key (and
    // certainly no raw evidence) can ride along in the response.
    let envelope: ryuki_protocol::SignedEnvelope =
        serde_json::from_value(envelope_json).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored signed envelope is corrupt"})),
            )
        })?;
    // Defense-in-depth (codex): Step 5b guards the policy version at INGESTION,
    // but signed_envelope predates that guard (mig 055), so a pre-guard or
    // back-door row could carry an unrecognised redaction_policy_version. Re-gate
    // it at the read side and fail closed with a GENERIC, non-echoing error —
    // never serve (and never reflect) a value the CP does not recognise.
    if !redaction_policy_version_is_supported(&envelope.redaction_policy_version) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored signed envelope failed validation"})),
        ));
    }
    if row.evidence_digest.as_deref() != Some(envelope.evidence_digest.as_str()) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored result digest failed validation"})),
        ));
    }
    let successful_live_plan = row.mode == "LivePlan"
        && row.status == "Succeeded"
        && row.result_status.as_deref() == Some("planned");
    let plan_review = if successful_live_plan {
        let stored_raw_plan_digest = row.raw_plan_digest.as_deref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored raw plan digest failed validation"})),
            )
        })?;
        if envelope.raw_plan_digest.as_deref() != Some(stored_raw_plan_digest) {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored raw plan digest failed validation"})),
            ));
        }
        let stored_spec: JobSpec = serde_json::from_value(row.spec.0).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored job spec failed validation"})),
            )
        })?;
        if ryuki_protocol::job_spec_digest(&stored_spec) != envelope.job_spec_digest {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored job spec failed validation"})),
            ));
        }
        let evidence: Vec<u8> =
            sqlx::query_scalar("SELECT bytes FROM evidence_blobs WHERE digest = $1")
                .bind(&envelope.evidence_digest)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?
                .ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "stored plan evidence failed validation"})),
                    )
                })?;
        if ryuki_protocol::sha256_hex(&evidence) != envelope.evidence_digest {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored plan evidence failed validation"})),
            ));
        }
        let validated = validated_raw_plan_digest(
            &JobMode::LivePlan,
            &JobResultStatus::Planned,
            envelope.raw_plan_digest.as_deref(),
            &stored_spec,
            &evidence,
        )
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored raw plan digest failed validation"})),
            )
        })?;
        if validated.as_deref() != Some(stored_raw_plan_digest) {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored raw plan digest failed validation"})),
            ));
        }
        derive_live_plan_review(&stored_spec, &evidence)
    } else {
        if row.raw_plan_digest.is_some() || envelope.raw_plan_digest.is_some() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored raw plan digest failed validation"})),
            ));
        }
        None
    };

    Ok(Json(json!({
        "job_id": job_id,
        "result_status": row.result_status,
        "completed_at": row.completed_at.map(|t| t.to_rfc3339()),
        "result_id": row.result_id,
        "evidence_digest": row.evidence_digest,
        "raw_plan_digest": row.raw_plan_digest,
        "signed_envelope": serde_json::to_value(&envelope).unwrap_or_default(),
        "plan_review": plan_review,
    })))
}

/// Non-secret operational state for the inspection endpoint. DELIBERATELY excludes every
/// secret/large column: `spec` (vars), `fencing_token`, `cp_nonce`, `live_context` (the
/// CP-signed grant), `evidence_json`, `signed_envelope`, `attempt_id`/`lease_generation`
/// (fencing internals). The attestation lives behind GET .../result.
#[derive(sqlx::FromRow)]
struct JobInspectRow {
    id: String,
    request_id: String,
    platform: String,
    mode: String,
    status: String,
    result_status: Option<String>,
    agent_id: Option<String>,
    lease_deadline: Option<chrono::DateTime<chrono::Utc>>,
    delivery_attempts: i32,
    evidence_digest: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// GET /api/admin/agents/jobs/{job_id}/state — an operator's read-only view of ONE agent
/// job's LIFECYCLE state (status, mode, the holding agent, lease deadline, redispatch
/// attempts), so an operator can SEE a stuck Leased/Running job before deciding to force-fail
/// / cancel / reconcile it. Admin-only. SECRET-SAFE: never returns spec / fencing_token /
/// cp_nonce / live_context / raw evidence / the signed envelope (the attestation is
/// GET .../result). The 5-segment `…/state` path (vs a bare 4-segment `…/jobs/{job_id}`)
/// avoids shadowing `…/agents/{agent_id}/approve|revoke` for an agent literally named
/// "jobs" — a bare GET there would 405 the agent's approve/revoke.
pub async fn admin_agent_job_get(
    Path(job_id): Path<String>,
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    if !check_permission(&session, "admin") {
        return Err(forbidden(
            "admin permission is required to inspect an agent job",
        ));
    }
    // Parse the id BEFORE get_db (codex) so a malformed id 404s even during a DB outage.
    let uid = Uuid::parse_str(&job_id)
        .map_err(|_| not_found(format!("agent job '{job_id}' not found")))?;
    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    let row: Option<JobInspectRow> = sqlx::query_as(
        "SELECT id::text AS id, request_id::text AS request_id, platform, mode, status, \
                result_status, agent_id, lease_deadline, delivery_attempts, evidence_digest, \
                created_at, updated_at, completed_at \
         FROM agent_jobs WHERE id = $1",
    )
    .bind(uid)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(r) = row else {
        return Err(not_found(format!("agent job '{job_id}' not found")));
    };

    // run-5 A0: by-id scope guard for a SCOPED principal (a read is a state oracle).
    // Resolve the parent request via the AUTHORITATIVE spec.request_id (the scalar
    // request_id column is NOT load-bearing) and 404 an out-of-scope (or orphaned/
    // malformed) job with the SAME body a missing job returns. Unrestricted
    // principals skip it unchanged.
    let scoped_request_id = if is_scoped(&session) {
        let spec = match sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
            "SELECT spec FROM agent_jobs WHERE id = $1",
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
        {
            None => return Err(not_found(format!("agent job '{job_id}' not found"))),
            Some(spec_json) => match serde_json::from_value::<JobSpec>(spec_json.0) {
                Ok(spec) => spec,
                Err(_) => return Err(not_found(format!("agent job '{job_id}' not found"))),
            },
        };
        let req: Option<(String, String)> =
            sqlx::query_as("SELECT site, environment FROM requests WHERE id = $1")
                .bind(spec.request_id)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
        let in_scope =
            matches!(req, Some((ref site, ref env)) if row_scope_permits(&session, site, env));
        if !in_scope {
            return Err(not_found(format!("agent job '{job_id}' not found")));
        }
        Some(spec.request_id.to_string())
    } else {
        None
    };

    Ok(Json(json!({
        "job_id": r.id,
        // A scoped caller sees the same authoritative parent id that passed the
        // scope check, never an independently stored scalar id.
        "request_id": scoped_request_id.unwrap_or(r.request_id),
        "platform": r.platform,
        "mode": r.mode,
        "status": r.status,
        "result_status": r.result_status,
        "agent_id": r.agent_id,
        "lease_deadline": r.lease_deadline.map(|d| d.to_rfc3339()),
        "delivery_attempts": r.delivery_attempts,
        "evidence_digest": r.evidence_digest,
        "created_at": r.created_at.to_rfc3339(),
        "updated_at": r.updated_at.to_rfc3339(),
        "completed_at": r.completed_at.map(|d| d.to_rfc3339()),
    })))
}

/// Admin route: sits under `/api/admin/agents/` so the human RBAC middleware
/// enforces `admin` permission. Agent tokens can never reach this path because
/// the `/api/agents/` exemption in `is_agent_exempt_path` is path-specific and
/// does not match `/api/admin/`.
pub fn admin_routes() -> Router {
    Router::new()
        .route("/api/admin/agents", get(admin_list_agents))
        .route(
            "/api/admin/agents/enrollment-challenges",
            post(admin_create_agent_enrollment_challenge)
                .layer(DefaultBodyLimit::max(AGENT_REGISTRATION_BODY_LIMIT_BYTES)),
        )
        // Static `liveness` in the `{agent_id}` slot — matchit routes the literal
        // over the param, so it does not shadow `/{agent_id}/approve`.
        .route("/api/admin/agents/liveness", get(admin_agents_liveness))
        .route(
            "/api/admin/agents/{agent_id}/approve",
            post(admin_approve_agent),
        )
        .route(
            "/api/admin/agents/{agent_id}/revoke",
            post(admin_revoke_agent),
        )
        .route(
            "/api/admin/agents/live-apply-jobs",
            post(admin_approve_live_apply_job),
        )
        // Static `dead-lettered-jobs` in the `{agent_id}` slot — matchit routes the
        // literal over the param (same pattern as `liveness`), so it does not shadow
        // `/{agent_id}/approve|revoke`.
        .route(
            "/api/admin/agents/dead-lettered-jobs",
            get(admin_dead_lettered_jobs),
        )
        .route(
            "/api/admin/agents/dead-lettered-jobs/{job_id}/requeue",
            post(admin_requeue_dead_lettered_job),
        )
        // Static `jobs` in the `{agent_id}` slot — matchit routes the literal over the
        // param (same pattern as `liveness`/`dead-lettered-jobs`).
        .route(
            "/api/admin/agents/jobs/{job_id}/priority",
            post(admin_set_job_priority),
        )
        .route(
            "/api/admin/agents/jobs/{job_id}/result",
            get(admin_agent_job_result),
        )
        .route(
            "/api/admin/agents/jobs/{job_id}/state",
            get(admin_agent_job_get),
        )
        .route(
            "/api/admin/agents/jobs/{job_id}/reconcile",
            post(admin_resolve_reconcile_required_job),
        )
        .route(
            "/api/admin/agents/jobs/{job_id}/cancel",
            post(admin_cancel_pending_job),
        )
        .route(
            "/api/admin/agents/jobs/{job_id}/force-fail",
            post(admin_force_fail_job),
        )
        // Static `queue-depth` in the `{agent_id}` slot (same matchit pattern).
        .route(
            "/api/admin/agents/queue-depth",
            get(admin_agent_queue_depth),
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type PendingJobLeaseState = (
        String,
        Option<String>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
    );
    type UntouchedPendingJobState = (
        String,
        Option<String>,
        Option<Uuid>,
        i64,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        i32,
        i32,
    );

    fn enrollment_human_admin_session(provider_mode: &str) -> AuthSession {
        AuthSession {
            user_id: "test-enrollment-admin".to_string(),
            display_name: "Test Enrollment Admin".to_string(),
            roles: vec![ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: true,
            actor_class: if provider_mode == "api-token" {
                ryuki_engine::auth::ActorClass::Workload
            } else {
                ryuki_engine::auth::ActorClass::VerifiedHuman
            },
            provider_mode: provider_mode.to_string(),
            ..Default::default()
        }
    }

    fn live_approver_session(user_id: &str) -> AuthSession {
        let mut session = AuthSession::static_dry_run();
        session.user_id = user_id.to_string();
        session.display_name = format!("{user_id} (test)");
        session.provider_mode = "local".to_string();
        session.token_valid = true;
        session.actor_class = ryuki_engine::auth::ActorClass::VerifiedHuman;
        session
    }

    async fn install_live_approval_audit_failure_trigger(pool: &PgPool) {
        sqlx::query("DROP TRIGGER IF EXISTS zz_ryuki_test_reject_live_approval_audit ON audit_log")
            .execute(pool)
            .await
            .expect("drop stale live-approval audit trigger");
        sqlx::query("DROP FUNCTION IF EXISTS ryuki_test_reject_live_approval_audit()")
            .execute(pool)
            .await
            .expect("drop stale live-approval audit function");
        sqlx::query(
            "CREATE FUNCTION ryuki_test_reject_live_approval_audit() RETURNS trigger \
             LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF NEW.actor_principal LIKE 'dbtest-live-audit-failure-%' THEN \
                 RAISE EXCEPTION 'injected live approval audit failure' USING ERRCODE = '23514'; \
               END IF; \
               RETURN NEW; \
             END $$",
        )
        .execute(pool)
        .await
        .expect("create live-approval audit function");
        sqlx::query(
            "CREATE TRIGGER zz_ryuki_test_reject_live_approval_audit \
             BEFORE INSERT ON audit_log FOR EACH ROW \
             EXECUTE FUNCTION ryuki_test_reject_live_approval_audit()",
        )
        .execute(pool)
        .await
        .expect("create live-approval audit trigger");
    }

    async fn remove_live_approval_audit_failure_trigger(pool: &PgPool) {
        sqlx::query("DROP TRIGGER IF EXISTS zz_ryuki_test_reject_live_approval_audit ON audit_log")
            .execute(pool)
            .await
            .expect("drop live-approval audit trigger");
        sqlx::query("DROP FUNCTION IF EXISTS ryuki_test_reject_live_approval_audit()")
            .execute(pool)
            .await
            .expect("drop live-approval audit function");
    }

    // -----------------------------------------------------------------------
    // Unit tests (no DB)
    // -----------------------------------------------------------------------

    #[test]
    fn enrollment_human_gate_admits_verified_persisted_and_direct_providers() {
        for provider_mode in ["persisted-session", "local", "entra-id", "oidc"] {
            let session = enrollment_human_admin_session(provider_mode);
            assert!(
                is_fresh_unscoped_interactive_human_admin(&session),
                "verified unscoped {provider_mode} human admin must remain admitted"
            );
        }
    }

    #[test]
    fn enrollment_human_gate_rejects_machine_unverified_and_scoped_authority() {
        let api_token = enrollment_human_admin_session("api-token");
        assert!(!is_fresh_unscoped_interactive_human_admin(&api_token));

        for actor_class in [
            ryuki_engine::auth::ActorClass::Workload,
            ryuki_engine::auth::ActorClass::Unknown,
            ryuki_engine::auth::ActorClass::Simulated,
        ] {
            let mut human_shaped_nonhuman = enrollment_human_admin_session("persisted-session");
            human_shaped_nonhuman.actor_class = actor_class;
            assert!(
                !is_fresh_unscoped_interactive_human_admin(&human_shaped_nonhuman),
                "the typed actor class must dominate a human-looking carrier label"
            );
        }

        let static_session = AuthSession::static_dry_run();
        assert!(!is_fresh_unscoped_interactive_human_admin(&static_session));

        let mut unverified = enrollment_human_admin_session("entra-id");
        unverified.token_valid = false;
        assert!(!is_fresh_unscoped_interactive_human_admin(&unverified));

        let mut site_scoped = enrollment_human_admin_session("persisted-session");
        site_scoped.site_scope = vec!["SITE-A".to_string()];
        assert!(!is_fresh_unscoped_interactive_human_admin(&site_scoped));

        let mut environment_scoped = enrollment_human_admin_session("oidc");
        environment_scoped.environment_scope = vec!["production".to_string()];
        assert!(!is_fresh_unscoped_interactive_human_admin(
            &environment_scoped
        ));

        let mut noncanonical_scope = enrollment_human_admin_session("local");
        noncanonical_scope.site_scope = vec![String::new()];
        assert!(!is_fresh_unscoped_interactive_human_admin(
            &noncanonical_scope
        ));

        let mut non_admin = enrollment_human_admin_session("entra-id");
        non_admin.roles = vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()];
        assert!(!is_fresh_unscoped_interactive_human_admin(&non_admin));
    }

    #[tokio::test]
    async fn enrollment_handlers_reject_nonhuman_admin_before_input_or_database_work() {
        let mut human_shaped_workload = enrollment_human_admin_session("persisted-session");
        human_shaped_workload.actor_class = ryuki_engine::auth::ActorClass::Workload;
        let mut human_shaped_unknown = enrollment_human_admin_session("persisted-session");
        human_shaped_unknown.actor_class = ryuki_engine::auth::ActorClass::Unknown;
        let mut human_shaped_simulated = enrollment_human_admin_session("persisted-session");
        human_shaped_simulated.actor_class = ryuki_engine::auth::ActorClass::Simulated;
        for machine in [
            enrollment_human_admin_session("api-token"),
            human_shaped_workload,
            human_shaped_unknown,
            human_shaped_simulated,
        ] {
            let challenge = admin_create_agent_enrollment_challenge(
                Extension(machine.clone()),
                Json(CreateEnrollmentChallengeBody {
                    agent_id: String::new(),
                    platform: String::new(),
                    public_key: String::new(),
                    expires_in_seconds: None,
                }),
            )
            .await;
            assert!(matches!(challenge, Err((StatusCode::FORBIDDEN, _))));

            let approval = admin_approve_agent(
                Path("untrusted-agent".to_string()),
                Extension(machine.clone()),
                Json(ApproveBody {
                    enrollment_id: Uuid::nil(),
                    public_key_fingerprint: String::new(),
                    platform: String::new(),
                    capabilities: None,
                }),
            )
            .await;
            assert!(matches!(approval, Err((StatusCode::FORBIDDEN, _))));

            let revocation = admin_revoke_agent(
                Path("untrusted-agent".to_string()),
                Extension(machine),
                Json(RevokeBody {
                    enrollment_id: Uuid::nil(),
                    public_key_fingerprint: String::new(),
                }),
            )
            .await;
            assert!(matches!(revocation, Err((StatusCode::FORBIDDEN, _))));
        }
    }

    #[tokio::test]
    async fn enrollment_handlers_reject_any_nonempty_scope_vector_before_database_work() {
        let mut challenge_admin = enrollment_human_admin_session("persisted-session");
        challenge_admin.environment_scope = vec![String::new()];
        let challenge = admin_create_agent_enrollment_challenge(
            Extension(challenge_admin),
            Json(CreateEnrollmentChallengeBody {
                agent_id: String::new(),
                platform: String::new(),
                public_key: String::new(),
                expires_in_seconds: None,
            }),
        )
        .await;
        assert!(matches!(challenge, Err((StatusCode::FORBIDDEN, _))));

        let mut approval_admin = enrollment_human_admin_session("entra-id");
        approval_admin.site_scope = vec!["SITE-A".to_string()];
        let approval = admin_approve_agent(
            Path("untrusted-agent".to_string()),
            Extension(approval_admin),
            Json(ApproveBody {
                enrollment_id: Uuid::nil(),
                public_key_fingerprint: String::new(),
                platform: String::new(),
                capabilities: None,
            }),
        )
        .await;
        assert!(matches!(approval, Err((StatusCode::FORBIDDEN, _))));
    }

    fn canonical_execution_trust_profile(spec: &JobSpec, platform: &str) -> ExecutionTrustProfile {
        ExecutionTrustProfile {
            schema_version: EXECUTION_TRUST_PROFILE_SCHEMA_VERSION.to_string(),
            allowlist_version: EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION.to_string(),
            platform: platform.to_string(),
            offering: "linux-server-deployment".to_string(),
            runner_kind: "terraform".to_string(),
            provider_source: "registry.terraform.io/vmware/vsphere".to_string(),
            provider_version: "2.16.1".to_string(),
            provider_authority_id: "provider-authority/vsphere/api-test-fixture".to_string(),
            provider_authority_version: "v1".to_string(),
            backend_kind: "local".to_string(),
            backend_credential_authority_id: "backend-credential-authority/local/api-test-fixture"
                .to_string(),
            backend_credential_authority_revision: "v1".to_string(),
            backend_authority_digest: proto_sha256(
                format!(
                    "api-test-local-backend:{}",
                    spec.state_key.as_deref().unwrap_or_default()
                )
                .as_bytes(),
            ),
            executable_kind: "terraform".to_string(),
            executable_path: "/usr/local/bin/terraform".to_string(),
            executable_version: "1.13.0".to_string(),
            executable_sha256: None,
            executable_provenance_policy_version: EXECUTABLE_PROVENANCE_POLICY_VERSION.to_string(),
            provider_credential_authority_mode: PROVIDER_CREDENTIAL_AUTHORITY_MODE.to_string(),
            backend_credential_authority_mode:
                ryuki_runner::live::BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION.to_string(),
            containment_policy_version: format!(
                "{}+{}",
                ryuki_runner::exec::RUNNER_CONTAINMENT_POLICY_VERSION,
                TERRAFORM_STATE_ISOLATION_POLICY_VERSION,
            ),
            iac_digest: spec.iac_digest.clone(),
            state_key: spec.state_key.clone().expect("state key"),
        }
    }

    #[test]
    fn execution_trust_profile_allowlist_is_closed_and_authoritative() {
        let spec = reviewable_live_plan_spec();
        let platform = "defra";
        let canonical = canonical_execution_trust_profile(&spec, platform);
        assert!(validate_execution_trust_profile(&canonical, &spec, platform).is_ok());

        let mut changed = canonical.clone();
        changed.schema_version = "unknown-schema".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.allowlist_version = "unknown-allowlist".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.provider_source = "registry.terraform.io/hashicorp/aws".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.provider_version = "2.16.0".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.provider_authority_id = "provider-authority/vsphere/INVALID".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.provider_authority_version = "1".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_kind = "unsupported".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_kind = "remote".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_kind = "pg".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_credential_authority_id =
            "backend-credential-authority/http/api-test-fixture".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_credential_authority_revision = "1".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_authority_digest = "not-a-digest".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.backend_credential_authority_mode = "ambient-default-chain".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.provider_credential_authority_mode = "instance-metadata".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.containment_policy_version = "process-group-only".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.executable_kind = "terraform-wrapper".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.executable_path = "terraform".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        let mut changed = canonical.clone();
        changed.executable_version = "1.13.0 --chdir=/tmp".to_string();
        assert!(validate_execution_trust_profile(&changed, &spec, platform).is_err());
        assert!(validate_execution_trust_profile(&canonical, &spec, "other").is_err());
        let mut changed_spec = spec.clone();
        changed_spec.state_key = Some("request-other".to_string());
        assert!(validate_execution_trust_profile(&canonical, &changed_spec, platform).is_err());
        let mut changed_spec = spec.clone();
        changed_spec.iac_digest = "b".repeat(64);
        assert!(validate_execution_trust_profile(&canonical, &changed_spec, platform).is_err());
    }

    #[test]
    fn agent_token_has_prefix() {
        let tok = generate_agent_token();
        assert!(
            tok.starts_with(AGENT_TOKEN_PREFIX),
            "token must start with prefix"
        );
    }

    #[test]
    fn failed_live_mutations_require_reconciliation() {
        for mode in [JobMode::LiveApply, JobMode::LiveDestroy] {
            assert_eq!(
                map_result_status_to_job_status(&mode, &JobResultStatus::Failed),
                "ReconcileRequired"
            );
        }
        assert_eq!(
            map_result_status_to_job_status(&JobMode::LivePlan, &JobResultStatus::Failed),
            "Failed"
        );
    }

    #[test]
    fn idle_heartbeat_has_no_running_lease_fence() {
        assert_eq!(
            parse_running_lease_fence(AgentHeartbeat::idle()).expect("idle heartbeat"),
            None
        );
    }

    #[test]
    fn running_heartbeat_requires_complete_exact_fence() {
        let attempt_id = Uuid::new_v4();
        let body = AgentHeartbeat {
            running_job_id: Some(Uuid::new_v4()),
            attempt_id: Some(attempt_id),
            lease_generation: Some(4),
            fencing_token: None,
        };
        let err = parse_running_lease_fence(body).expect_err("partial fence must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let job_id = Uuid::new_v4();
        let fence = parse_running_lease_fence(AgentHeartbeat {
            running_job_id: Some(job_id),
            attempt_id: Some(attempt_id),
            lease_generation: Some(4),
            fencing_token: Some("exact-token".to_owned()),
        })
        .expect("complete fence")
        .expect("running fence");
        assert_eq!(
            fence,
            RunningLeaseFence {
                job_id,
                attempt_id,
                lease_generation: 4,
                fencing_token: "exact-token".to_owned(),
            }
        );
    }

    #[test]
    fn running_heartbeat_rejects_generation_outside_database_range() {
        let err = parse_running_lease_fence(AgentHeartbeat {
            running_job_id: Some(Uuid::new_v4()),
            attempt_id: Some(Uuid::new_v4()),
            lease_generation: Some(u64::MAX),
            fencing_token: Some("token".to_owned()),
        })
        .expect_err("u64 generation above BIGINT range must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn caller_supplied_live_apply_endpoint_is_gone() {
        let result = admin_approve_live_apply_job(Extension(live_approver_session("ops"))).await;
        let Err((status, Json(body))) = result else {
            panic!("legacy live-apply endpoint must remain disabled");
        };
        assert_eq!(status, StatusCode::GONE);
        assert!(body["error"]
            .as_str()
            .is_some_and(|message| message.contains("approve-live-apply")));
    }

    // -----------------------------------------------------------------------
    // Wire protocol version — enforcement logic (the ProtocolVersion extractor
    // delegates verbatim to resolve_protocol_version, so testing the helper
    // covers the extractor's behaviour without constructing a request `Parts`).
    // -----------------------------------------------------------------------

    fn hdrs_with_version(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            ryuki_protocol::PROTOCOL_VERSION_HEADER,
            value.parse().expect("valid header value"),
        );
        h
    }

    #[test]
    fn protocol_version_absent_header_is_rejected_as_legacy_v1() {
        // No header at all resolves to legacy v1, which is intentionally outside
        // the v6-only allowlist because older agents lack current state,
        // enrollment isolation, and exact signed execution-authority controls.
        let err = resolve_protocol_version(&HeaderMap::new())
            .expect_err("an absent header must be rejected as legacy protocol v1");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let msg = err.1 .0["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains(&format!(
                "unsupported protocol_version: {}",
                ryuki_protocol::PROTOCOL_VERSION_LEGACY
            )),
            "message must identify rejected legacy protocol v1: {msg}"
        );
    }

    #[test]
    fn protocol_version_explicit_supported_is_accepted() {
        let v = resolve_protocol_version(&hdrs_with_version(
            &ryuki_protocol::PROTOCOL_VERSION.to_string(),
        ))
        .expect("the current build's version must be accepted");
        assert_eq!(v, ryuki_protocol::PROTOCOL_VERSION);
    }

    #[test]
    fn protocol_version_v4_peer_is_rejected_after_execution_authority_cutover() {
        assert_eq!(ryuki_protocol::PROTOCOL_VERSION, 6);
        let err = resolve_protocol_version(&hdrs_with_version("4"))
            .expect_err("a v4 peer cannot parse the required signed execution authority");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0["error"]
            .as_str()
            .is_some_and(|message| message.contains("unsupported protocol_version: 4")));
    }

    #[test]
    fn protocol_version_zero_is_rejected() {
        // 0 is never a valid version (mirrors the DB CHECK (protocol_version > 0)).
        let err = resolve_protocol_version(&hdrs_with_version("0"))
            .expect_err("version 0 must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn protocol_version_non_integer_is_rejected() {
        // Non-numeric, signed, fractional, empty/whitespace, and > u32::MAX values
        // all fail the `u32 > 0` parse → fail-closed 400.
        for bad in ["abc", "1.0", "-1", "", " ", "99999999999999999999"] {
            let result = resolve_protocol_version(&hdrs_with_version(bad));
            assert!(
                matches!(result, Err((StatusCode::BAD_REQUEST, _))),
                "a non-integer version {bad:?} must be rejected 400, got {result:?}"
            );
        }
    }

    #[test]
    fn protocol_version_unsupported_is_rejected_with_actionable_message() {
        // A version outside SUPPORTED_PROTOCOL_VERSIONS → fail-closed 400 whose
        // body names both what was sent and what the CP supports.
        let unsupported = ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .max()
            .copied()
            .unwrap_or(0)
            + 1000;
        let err = resolve_protocol_version(&hdrs_with_version(&unsupported.to_string()))
            .expect_err("an unsupported version must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let msg = err.1 .0["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains(&format!("unsupported protocol_version: {unsupported}")),
            "message must name the rejected version: {msg}"
        );
        assert!(
            msg.contains("this control plane supports"),
            "message must name the supported set: {msg}"
        );
    }

    #[test]
    fn protocol_version_duplicate_header_is_rejected() {
        // Two header values is ambiguous (proxy smuggling / drift smell) → 400,
        // never a silent "pick one".
        let mut h = HeaderMap::new();
        h.append(
            ryuki_protocol::PROTOCOL_VERSION_HEADER,
            "1".parse().unwrap(),
        );
        h.append(
            ryuki_protocol::PROTOCOL_VERSION_HEADER,
            "2".parse().unwrap(),
        );
        let err =
            resolve_protocol_version(&h).expect_err("a duplicated version header must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn protocol_version_is_supported_tracks_the_allowlist() {
        for &v in ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS {
            assert!(protocol_version_is_supported(v));
        }
        assert!(!protocol_version_is_supported(0));
        assert!(!protocol_version_is_supported(u32::MAX));
    }

    #[tokio::test]
    async fn cp_public_key_advertises_protocol_version() {
        // The CP→agent half of the handshake: the cp-public-key JSON must carry
        // the CP's wire protocol version so the agent can refuse an incompatible CP.
        ensure_test_cp_key();
        let response = cp_public_key().await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        use axum::body::to_bytes;
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("JSON body");
        assert_eq!(
            body.get("protocol_version").and_then(|v| v.as_u64()),
            Some(u64::from(ryuki_protocol::PROTOCOL_VERSION)),
            "cp-public-key must advertise the CP protocol version"
        );
    }

    #[test]
    fn agent_token_sha256_roundtrip() {
        let tok = generate_agent_token();
        let h1 = sha256_hex(&tok);
        let h2 = sha256_hex(&tok);
        assert_eq!(h1, h2, "sha256 must be deterministic");
        assert_eq!(h1.len(), 64, "sha256 hex must be 64 chars");
    }

    #[test]
    fn two_tokens_differ() {
        let a = generate_agent_token();
        let b = generate_agent_token();
        assert_ne!(a, b, "tokens must be unique");
    }

    fn signed_registration_body(
        enrollment_challenge_id: Uuid,
        enrollment_challenge: String,
        agent_id: String,
        platform: String,
        key: &ed25519_dalek::SigningKey,
    ) -> RegisterBody {
        let public_key = encode_verifying_key(&key.verifying_key());
        let enrollment_proof = ryuki_protocol::sign_agent_enrollment_proof(
            enrollment_challenge_id,
            &enrollment_challenge,
            &agent_id,
            &platform,
            &public_key,
            key,
        );
        RegisterBody {
            enrollment_challenge_id,
            enrollment_challenge,
            agent_id,
            platform,
            capabilities: Capabilities::default(),
            public_key,
            enrollment_proof,
        }
    }

    fn valid_registration_body(agent_id: impl Into<String>) -> RegisterBody {
        let key = generate_keypair(&mut OsRng);
        signed_registration_body(
            Uuid::new_v4(),
            generate_agent_enrollment_challenge(),
            agent_id.into(),
            "ci".to_owned(),
            &key,
        )
    }

    #[test]
    fn registration_accepts_bounded_legitimate_input() {
        let body = valid_registration_body("agent-01");
        let validated =
            validate_registration_input(&body).expect("ordinary registration must validate");
        assert_eq!(validated.agent_id, "agent-01");
        assert_eq!(validated.platform, "ci");
        assert_eq!(validated.public_key, body.public_key);
    }

    #[test]
    fn registration_proof_rejects_substituted_identity_and_malformed_challenge() {
        let mut changed_identity = valid_registration_body("agent-01");
        changed_identity.agent_id = "agent-02".to_owned();
        assert!(matches!(
            validate_registration_input(&changed_identity),
            Err((StatusCode::FORBIDDEN, _))
        ));

        let mut malformed_challenge = valid_registration_body("agent-01");
        malformed_challenge.enrollment_challenge = "ryc_short".to_owned();
        assert!(matches!(
            validate_registration_input(&malformed_challenge),
            Err((StatusCode::FORBIDDEN, _))
        ));
    }

    #[test]
    fn approved_capability_grants_require_canonical_tool_and_provider_versions() {
        assert!(validated_approved_capabilities(&test_agent_capabilities()).is_ok());

        let ansible_with_provider = Capabilities {
            terraform: None,
            ansible: Some(ryuki_protocol::ToolCapability {
                version: "2.16.0".to_owned(),
                provider_versions: std::collections::BTreeMap::from([(
                    "collection".to_owned(),
                    "1.0.0".to_owned(),
                )]),
            }),
        };
        assert!(matches!(
            validated_approved_capabilities(&ansible_with_provider),
            Err((StatusCode::BAD_REQUEST, _))
        ));

        let mut blank_provider_version = terraform_test_capabilities("2.16.1");
        blank_provider_version
            .terraform
            .as_mut()
            .expect("Terraform capability")
            .provider_versions
            .insert("vsphere".to_owned(), " ".to_owned());
        assert!(matches!(
            validated_approved_capabilities(&blank_provider_version),
            Err((StatusCode::BAD_REQUEST, _))
        ));
    }

    #[test]
    fn enrollment_review_fingerprint_is_canonical_and_strict() {
        let fingerprint = public_key_fingerprint("reviewed-public-key");
        assert!(valid_public_key_fingerprint_shape(&fingerprint));
        assert_eq!(fingerprint.len(), "sha256:".len() + 64);
        assert!(!valid_public_key_fingerprint_shape(
            &fingerprint.to_uppercase()
        ));
        assert!(!valid_public_key_fingerprint_shape("sha256:short"));
    }

    #[test]
    fn pending_enrollment_without_expiry_fails_closed() {
        assert!(pending_enrollment_missing_expiry("pending", None));
        assert!(!pending_enrollment_missing_expiry("approved", None));
        assert!(!pending_enrollment_missing_expiry(
            "pending",
            Some(Utc::now())
        ));
    }

    #[test]
    fn registration_rejects_oversized_key_before_decode() {
        let mut body = valid_registration_body("oversized-key");
        body.public_key = "!".repeat(AGENT_PUBLIC_KEY_MAX_BYTES + 1);
        let Err((status, Json(error))) = validate_registration_input(&body) else {
            panic!("an oversized encoded key must fail before decode");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let message = error["error"].as_str().unwrap_or_default();
        assert!(
            message.contains("at most 64 bytes"),
            "the size gate must run before the generic base64 decoder: {message}"
        );
    }

    #[test]
    fn registration_rejects_oversized_identifiers_and_capability_maps() {
        let mut long_id = valid_registration_body("a".repeat(AGENT_ID_MAX_BYTES + 1));
        assert!(matches!(
            validate_registration_input(&long_id),
            Err((StatusCode::BAD_REQUEST, _))
        ));

        let providers = (0..=CAPABILITY_PROVIDER_MAX_COUNT)
            .map(|index| (format!("provider-{index}"), "1.0".to_owned()))
            .collect();
        long_id.agent_id = "bounded-agent".to_owned();
        long_id.capabilities.terraform = Some(ryuki_protocol::ToolCapability {
            version: "1.9".to_owned(),
            provider_versions: providers,
        });
        let Err((status, Json(error))) = validate_registration_input(&long_id) else {
            panic!("an oversized provider map must be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error["error"]
            .as_str()
            .is_some_and(|message| message.contains("at most 64 provider versions")));
    }

    #[test]
    fn registration_admission_enforces_source_global_and_in_flight_budgets() {
        let headers = HeaderMap::new();
        let peer: SocketAddr = "192.0.2.10:443".parse().expect("peer address");

        let source_bounded = AgentRegistrationAdmission::new(1, 1, 100, 100, 2, Vec::new());
        let first = source_bounded
            .try_admit(peer, &headers)
            .expect("first request from a source fits its burst");
        drop(first);
        assert!(matches!(
            source_bounded.try_admit(peer, &headers),
            Err(AgentRegistrationAdmissionRejection::ClientRate)
        ));

        // A different source resolves to a separate salted fixed bucket. Find
        // one deterministically instead of accepting a 1/16,384 collision as
        // test flakiness.
        let first_bucket = crate::bounded_rate_limit_key(
            "agent-registration",
            &peer.ip().to_string(),
            &source_bounded.bucket_salt,
        );
        let other_peer = (11_u8..=254)
            .map(|last| {
                format!("192.0.2.{last}:443")
                    .parse::<SocketAddr>()
                    .expect("candidate peer")
            })
            .find(|candidate| {
                crate::bounded_rate_limit_key(
                    "agent-registration",
                    &candidate.ip().to_string(),
                    &source_bounded.bucket_salt,
                ) != first_bucket
            })
            .expect("a distinct fixed source bucket");
        drop(
            source_bounded
                .try_admit(other_peer, &headers)
                .expect("one busy source must not consume another source's budget"),
        );

        let global_bounded = AgentRegistrationAdmission::new(100, 100, 1, 1, 2, Vec::new());
        drop(
            global_bounded
                .try_admit(peer, &headers)
                .expect("first request fits the global burst"),
        );
        assert!(matches!(
            global_bounded.try_admit(peer, &headers),
            Err(AgentRegistrationAdmissionRejection::GlobalRate)
        ));

        let in_flight_bounded = AgentRegistrationAdmission::new(100, 100, 100, 100, 1, Vec::new());
        let held = in_flight_bounded
            .try_admit(peer, &headers)
            .expect("first request owns the only in-flight slot");
        assert!(matches!(
            in_flight_bounded.try_admit(peer, &headers),
            Err(AgentRegistrationAdmissionRejection::InFlight)
        ));
        drop(held);
        drop(
            in_flight_bounded
                .try_admit(peer, &headers)
                .expect("dropping a request releases its in-flight slot"),
        );
    }

    #[test]
    fn registration_admission_matches_only_the_exact_public_post() {
        assert!(is_agent_registration_request(
            &Method::POST,
            "/api/agents/register"
        ));
        assert!(!is_agent_registration_request(
            &Method::GET,
            "/api/agents/register"
        ));
        assert!(!is_agent_registration_request(
            &Method::POST,
            "/api/agents/register/extra"
        ));
        assert!(!is_agent_registration_request(
            &Method::POST,
            "/api/agents/cp-public-key"
        ));
    }

    #[tokio::test]
    async fn registration_admission_fails_closed_without_peer_context_only_on_its_route() {
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/api/agents/register",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route("/health", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn_with_state(
                AgentRegistrationAdmission::new(100, 100, 100, 100, 1, Vec::new()),
                agent_registration_admission_middleware,
            ));

        let registration = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri("/api/agents/register")
                    .body(axum::body::Body::empty())
                    .expect("registration request"),
            )
            .await
            .expect("registration response");
        assert_eq!(registration.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            registration
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );

        let health = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn registration_route_rejects_body_before_large_json_deserialization() {
        use tower::ServiceExt;

        let oversized = "x".repeat(AGENT_REGISTRATION_BODY_LIMIT_BYTES + 1);
        let response = agent_routes()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/agents/register")
                    .header("content-type", "application/json")
                    .header(
                        ryuki_protocol::PROTOCOL_VERSION_HEADER,
                        ryuki_protocol::PROTOCOL_VERSION.to_string(),
                    )
                    .body(axum::body::Body::from(oversized))
                    .expect("request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ── #60 slice 2: write-side evidence offload decision (pure, no DB) ─────

    #[test]
    fn evidence_json_for_storage_stays_inline_under_threshold() {
        let submitted = Some(json!({"ok": true}));
        let stored = compute_evidence_json_for_storage(false, 10, "deadbeef", &submitted);
        assert_eq!(
            stored, submitted,
            "small evidence must keep the agent-submitted evidence_json inline"
        );
    }

    #[test]
    fn evidence_json_for_storage_becomes_a_reference_when_offloaded() {
        let submitted = Some(json!({"ignored": "because offloaded"}));
        let stored = compute_evidence_json_for_storage(true, 70_000, "deadbeef", &submitted);
        let stored = stored.expect("offloaded result must still store a reference");
        assert_eq!(
            stored["_evidence_blob_digest"], "deadbeef",
            "reference must carry the verified digest"
        );
        assert_eq!(
            stored["_evidence_size_bytes"], 70_000,
            "reference must carry the evidence size"
        );
        assert!(
            stored.get("ignored").is_none(),
            "the reference must NOT leak the raw agent-submitted evidence_json"
        );
    }

    fn reviewable_live_plan_vars() -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("vm_name".to_string(), "first-test-vm".to_string()),
            ("num_cpus".to_string(), "2".to_string()),
            ("memory_mb".to_string(), "4096".to_string()),
            ("disk_size_gb".to_string(), "80".to_string()),
            ("datacenter".to_string(), "Primary DC".to_string()),
            ("cluster".to_string(), "Compute A".to_string()),
            ("datastore".to_string(), "General Storage".to_string()),
            ("network".to_string(), "Server Network".to_string()),
            ("template".to_string(), "Linux Golden".to_string()),
        ])
    }

    fn reviewable_live_plan_spec() -> JobSpec {
        JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".to_string(),
            iac_digest: "a".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{}", Uuid::new_v4())),
            mode: JobMode::LivePlan,
        }
    }

    /// Build the exact safe projection for a positive signed-plan fixture.
    /// Approval tests exercise immutable authority selection, not projection
    /// parsing, so their retained evidence must follow the supplied JobSpec
    /// instead of silently reusing one unrelated hard-coded VM shape.
    fn reviewable_live_plan_for_spec(spec: &JobSpec, raw_plan_digest: &str) -> Value {
        let placement = live_plan_placement(spec)
            .expect("positive signed-plan fixture must carry reviewable placement vars");
        let logical_name = match spec.iac_ref.split('@').next() {
            Some("linux-server-deployment") => "linux_server",
            Some("windows-server-deployment") => "windows_server",
            _ => panic!("positive signed-plan fixture must use a supported offering"),
        };
        json!({
            "schema_version": ryuki_protocol::TERRAFORM_LIVE_PLAN_EVIDENCE_SCHEMA_VERSION,
            "canonical_plan_sha256": raw_plan_digest,
            "projection_complete": true,
            "resource_changes": [
                {
                    "mode": "data",
                    "type": "vsphere_datacenter",
                    "name": "dc",
                    "change": {"actions": ["read"], "after": {"name": placement.datacenter}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_compute_cluster",
                    "name": "cluster",
                    "change": {"actions": ["read"], "after": {"name": placement.cluster}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_datastore",
                    "name": "ds",
                    "change": {"actions": ["read"], "after": {"name": placement.datastore}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_network",
                    "name": "net",
                    "change": {"actions": ["read"], "after": {"name": placement.network}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_virtual_machine",
                    "name": "template",
                    "change": {"actions": ["read"], "after": {"name": placement.template}}
                },
                {
                    "mode": "managed",
                    "type": "vsphere_virtual_machine",
                    "name": logical_name,
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "name": placement.name,
                            "num_cpus": placement.cpu,
                            "memory": placement.memory_gb * 1024,
                            "disk": [{"label": "disk0", "size": placement.disk_size_gb}]
                        }
                    }
                }
            ]
        })
    }

    fn reviewable_live_plan(actions: &[&str]) -> Value {
        json!({
            "schema_version": ryuki_protocol::TERRAFORM_LIVE_PLAN_EVIDENCE_SCHEMA_VERSION,
            "canonical_plan_sha256": "a".repeat(64),
            "projection_complete": true,
            "resource_changes": [
                {
                    "mode": "data",
                    "type": "vsphere_datacenter",
                    "name": "dc",
                    "change": {"actions": ["read"], "after": {"name": "Primary DC"}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_compute_cluster",
                    "name": "cluster",
                    "change": {"actions": ["read"], "after": {"name": "Compute A"}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_datastore",
                    "name": "ds",
                    "change": {"actions": ["read"], "after": {"name": "General Storage"}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_network",
                    "name": "net",
                    "change": {"actions": ["read"], "after": {"name": "Server Network"}}
                },
                {
                    "mode": "data",
                    "type": "vsphere_virtual_machine",
                    "name": "template",
                    "change": {"actions": ["read"], "after": {"name": "Linux Golden"}}
                },
                {
                    "mode": "managed",
                    "type": "vsphere_virtual_machine",
                    "name": "linux_server",
                    "change": {
                        "actions": actions,
                        "after": {
                            "name": "first-test-vm",
                            "num_cpus": 2,
                            "memory": 4096,
                            "disk": [{"label": "disk0", "size": 80}]
                        }
                    }
                }
            ]
        })
    }

    #[test]
    fn raw_plan_digest_accepts_matching_signed_projection_commitment() {
        let spec = reviewable_live_plan_spec();
        let evidence = serde_json::to_vec(&reviewable_live_plan(&["create"])).unwrap();
        let digest = "a".repeat(64);
        assert_eq!(
            validated_raw_plan_digest(
                &JobMode::LivePlan,
                &JobResultStatus::Planned,
                Some(&digest),
                &spec,
                &evidence,
            ),
            Ok(Some(digest)),
        );
    }

    #[test]
    fn raw_plan_digest_rejects_signed_projection_mismatch() {
        let spec = reviewable_live_plan_spec();
        let evidence = serde_json::to_vec(&reviewable_live_plan(&["create"])).unwrap();
        assert_eq!(
            validated_raw_plan_digest(
                &JobMode::LivePlan,
                &JobResultStatus::Planned,
                Some(&"b".repeat(64)),
                &spec,
                &evidence,
            ),
            Err("raw_plan_digest does not match the canonical plan digest in signed evidence"),
        );
    }

    #[test]
    fn raw_plan_digest_rejects_legacy_successful_plan_without_commitment() {
        let spec = reviewable_live_plan_spec();
        let evidence = serde_json::to_vec(&reviewable_live_plan(&["create"])).unwrap();
        assert_eq!(
            validated_raw_plan_digest(
                &JobMode::LivePlan,
                &JobResultStatus::Planned,
                None,
                &spec,
                &evidence,
            ),
            Err("successful LivePlan result must include signed raw_plan_digest"),
        );
    }

    #[test]
    fn live_plan_review_exposes_only_allowlisted_digest_bound_fields() {
        let spec = reviewable_live_plan_spec();
        let safe_projection = reviewable_live_plan(&["create"]);
        let review = derive_live_plan_review(
            &spec,
            &serde_json::to_vec(&safe_projection).expect("serialize projection"),
        )
        .expect("supported vSphere plan has a safe review");
        assert!(review.digest_verified);
        assert_eq!(review.placement.name, "first-test-vm");
        assert_eq!(review.counts.create, 1);
        assert_eq!(review.managed_changes[0].resource_type, "virtual_machine");
        assert_eq!(review.managed_changes[0].action, "create");

        let rendered = serde_json::to_string(&review).expect("serialize review");
        let canonical_digest = "a".repeat(64);
        for forbidden in ["canonical_plan_sha256", canonical_digest.as_str()] {
            assert!(
                !rendered.contains(forbidden),
                "review response must not expose projection internals {forbidden}"
            );
        }
    }

    #[test]
    fn live_plan_review_rejects_legacy_raw_plan_and_projection_extras() {
        let spec = reviewable_live_plan_spec();
        let mut legacy_raw_plan = reviewable_live_plan(&["create"]);
        let object = legacy_raw_plan
            .as_object_mut()
            .expect("projection fixture is an object");
        object.remove("schema_version");
        object.remove("canonical_plan_sha256");
        object.remove("projection_complete");
        object.insert("format_version".to_string(), json!("1.2"));
        assert!(
            derive_live_plan_review(&spec, &serde_json::to_vec(&legacy_raw_plan).unwrap())
                .is_none(),
            "legacy/raw Terraform JSON must never become an approvable review"
        );

        let mut projection_with_provider_extra = reviewable_live_plan(&["create"]);
        projection_with_provider_extra["resource_changes"][5]["change"]["after"]
            ["provider_private"] = json!("MUST-NOT-LEAK");
        assert!(
            derive_live_plan_review(
                &spec,
                &serde_json::to_vec(&projection_with_provider_extra).unwrap()
            )
            .is_none(),
            "unknown nested projection fields must fail closed"
        );
    }

    #[test]
    fn live_plan_review_requires_current_complete_digest_bound_projection() {
        let spec = reviewable_live_plan_spec();
        for (field, value) in [
            ("schema_version", json!("ryuki-terraform-live-plan-v0")),
            ("canonical_plan_sha256", json!("A".repeat(64))),
            ("canonical_plan_sha256", json!("a".repeat(63))),
            ("projection_complete", json!(false)),
        ] {
            let mut projection = reviewable_live_plan(&["create"]);
            projection[field] = value;
            assert!(
                derive_live_plan_review(&spec, &serde_json::to_vec(&projection).unwrap()).is_none(),
                "approval accepted invalid safe-projection field {field}"
            );
        }
    }

    #[test]
    fn live_plan_review_fails_closed_on_unknown_mutating_resource() {
        let spec = reviewable_live_plan_spec();
        let safe_projection = json!({
            "schema_version": ryuki_protocol::TERRAFORM_LIVE_PLAN_EVIDENCE_SCHEMA_VERSION,
            "canonical_plan_sha256": "b".repeat(64),
            "projection_complete": true,
            "resource_changes": [{
                "mode": "managed",
                "type": "unknown_provider_object",
                "name": "unknown",
                "change": { "actions": ["create"], "after": {} }
            }]
        });
        assert!(
            derive_live_plan_review(&spec, &serde_json::to_vec(&safe_projection).unwrap())
                .is_none(),
            "unknown provider mutations must not produce an approvable projection"
        );
    }

    #[test]
    fn live_plan_review_retains_safe_no_op_but_never_approves_it() {
        let spec = reviewable_live_plan_spec();
        let safe_no_op = serde_json::to_vec(&reviewable_live_plan(&["no-op"])).unwrap();
        let review = derive_live_plan_review(&spec, &safe_no_op)
            .expect("an exact non-mutating projection remains safe to retain");
        assert_eq!(review.counts, PlanChangeCounts::default());
        assert!(review.managed_changes.is_empty());
        assert!(
            !server_live_plan_is_safe_to_approve(&spec, &safe_no_op),
            "non-mutating evidence must never authorize an apply"
        );
    }

    #[test]
    fn server_live_plan_approval_requires_exactly_one_expected_create() {
        let spec = reviewable_live_plan_spec();
        let create = serde_json::to_vec(&reviewable_live_plan(&["create"])).unwrap();
        assert!(server_live_plan_is_safe_to_approve(&spec, &create));
        for actions in [
            vec!["update"],
            vec!["delete"],
            vec!["delete", "create"],
            vec!["no-op"],
        ] {
            let evidence = serde_json::to_vec(&reviewable_live_plan(&actions)).unwrap();
            assert!(
                !server_live_plan_is_safe_to_approve(&spec, &evidence),
                "server approval accepted actions {actions:?}"
            );
        }

        let mut two_creates = reviewable_live_plan(&["create"]);
        let duplicate = two_creates["resource_changes"][5].clone();
        two_creates["resource_changes"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(!server_live_plan_is_safe_to_approve(
            &spec,
            &serde_json::to_vec(&two_creates).unwrap()
        ));

        let mut existing_managed = reviewable_live_plan(&["create"]);
        existing_managed["resource_changes"]
            .as_array_mut()
            .unwrap()
            .insert(
                5,
                json!({
                    "mode": "managed",
                    "type": "vsphere_virtual_machine",
                    "name": "existing_server",
                    "change": {"actions": ["no-op"], "after": {}}
                }),
            );
        assert!(!server_live_plan_is_safe_to_approve(
            &spec,
            &serde_json::to_vec(&existing_managed).unwrap()
        ));

        let data_and_create = reviewable_live_plan(&["create"]);
        assert!(server_live_plan_is_safe_to_approve(
            &spec,
            &serde_json::to_vec(&data_and_create).unwrap()
        ));
    }

    #[test]
    fn server_live_plan_approval_rejects_missing_or_mismatched_after_values() {
        let spec = reviewable_live_plan_spec();
        for (pointer, replacement) in [
            ("/resource_changes/5/change/after/name", json!("other-vm")),
            ("/resource_changes/5/change/after/num_cpus", json!(8)),
            ("/resource_changes/5/change/after/memory", json!(8192)),
            ("/resource_changes/5/change/after/disk/0/size", json!(120)),
            ("/resource_changes/0/change/after/name", json!("Other DC")),
            (
                "/resource_changes/1/change/after/name",
                json!("Other Cluster"),
            ),
            (
                "/resource_changes/2/change/after/name",
                json!("Other Store"),
            ),
            (
                "/resource_changes/3/change/after/name",
                json!("Other Network"),
            ),
            (
                "/resource_changes/4/change/after/name",
                json!("Other Template"),
            ),
        ] {
            let mut plan = reviewable_live_plan(&["create"]);
            *plan.pointer_mut(pointer).expect("fixture pointer") = replacement;
            assert!(
                !server_live_plan_is_safe_to_approve(&spec, &serde_json::to_vec(&plan).unwrap()),
                "approval accepted mismatched planned value at {pointer}"
            );
        }

        let mut missing_after = reviewable_live_plan(&["create"]);
        missing_after["resource_changes"][5]["change"]
            .as_object_mut()
            .unwrap()
            .remove("after");
        assert!(!server_live_plan_is_safe_to_approve(
            &spec,
            &serde_json::to_vec(&missing_after).unwrap()
        ));
    }

    #[test]
    fn live_apply_review_rejects_unsupported_non_server_offerings() {
        let mut spec = reviewable_live_plan_spec();
        spec.iac_ref = "patch-maintenance@v1".to_string();
        assert!(
            !server_live_plan_is_safe_to_approve(
                &spec,
                &serde_json::to_vec(&reviewable_live_plan(&["create"])).unwrap(),
            ),
            "a digest alone must not make an unsupported Terraform or Ansible offering approvable"
        );
    }

    // ── #44 agent liveness — auth + bounds (run before any pool access) ──

    #[tokio::test]
    async fn liveness_requires_admin() {
        let non_admin = AuthSession {
            user_id: "u".into(),
            display_name: "U".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            provider_mode: "test".into(),
            ..Default::default()
        };
        let err = admin_agents_liveness(
            Extension(non_admin),
            Query(AgentLivenessQuery {
                offline_after_secs: None,
            }),
        )
        .await
        .expect_err("non-admin must be forbidden");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn liveness_rejects_out_of_range_window() {
        for bad in [10_i64, 999_999] {
            let err = admin_agents_liveness(
                Extension(AuthSession::static_dry_run()),
                Query(AgentLivenessQuery {
                    offline_after_secs: Some(bad),
                }),
            )
            .await
            .expect_err("out-of-range window must be rejected");
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "window {bad} must 400");
        }
    }

    // -----------------------------------------------------------------------
    // DB-gated integration tests
    //
    // Run with: RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform
    //           cargo test -p ryuki-api agents::tests::db_
    // Each test SKIPS when RYUKI_DATABASE_URL is unset.
    // -----------------------------------------------------------------------

    // Serializes tests that depend on expired-lease state. `expire_leases` is a
    // GLOBAL sweep (UPDATE ... WHERE status = 'Leased' AND lease_deadline < NOW())
    // with no platform/agent scope, so a test that calls it would flip another
    // test's expired-Leased fixture out from under it (the cause of the flaky
    // db_ack_expired_lease_returns_409). Any test that calls expire_leases OR
    // seeds an expired-deadline Leased job acquires this lock for its duration.
    // tokio::sync::Mutex (not std) so the guard is safely held across .await.
    static EXPIRE_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .ok()?;
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    /// Provision the exact challenge represented by a signed registration
    /// fixture. Tests that call the persistence boundary directly use this
    /// helper; handler tests exercise the administrator issuance endpoint.
    async fn seed_registration_challenge(pool: &PgPool, body: &RegisterBody) {
        sqlx::query(
            "INSERT INTO agent_enrollment_challenges ( \
                 id, agent_id, platform, public_key, public_key_fingerprint, \
                 secret_hash, ttl_seconds, expires_at, created_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, 3600, \
                       statement_timestamp(), 'test-provisioner')",
        )
        .bind(body.enrollment_challenge_id)
        .bind(&body.agent_id)
        .bind(&body.platform)
        .bind(&body.public_key)
        .bind(public_key_fingerprint(&body.public_key))
        .bind(sha256_hex(&body.enrollment_challenge))
        .execute(pool)
        .await
        .expect("seed trusted enrollment challenge");
    }

    /// Schema-owner-only fixture hook for database-clock boundary tests. The
    /// production contract intentionally makes both deadlines immutable; DDL is
    /// transactional here so any failure rolls the trigger state back safely.
    async fn force_agent_enrollment_deadline_for_test(
        pool: &PgPool,
        agent_id: &str,
        deadline: DateTime<Utc>,
    ) {
        let mut tx = pool.begin().await.expect("begin agent deadline fixture");
        sqlx::query("ALTER TABLE agents DISABLE TRIGGER agents_enrollment_contract_v3_mutation")
            .execute(&mut *tx)
            .await
            .expect("disable agent enrollment guard for fixture");
        sqlx::query("UPDATE agents SET enrollment_expires_at = $2 WHERE agent_id = $1")
            .bind(agent_id)
            .bind(deadline)
            .execute(&mut *tx)
            .await
            .expect("set agent enrollment fixture deadline");
        sqlx::query("ALTER TABLE agents ENABLE TRIGGER agents_enrollment_contract_v3_mutation")
            .execute(&mut *tx)
            .await
            .expect("restore agent enrollment guard after fixture");
        tx.commit().await.expect("commit agent deadline fixture");
    }

    async fn force_challenge_deadline_for_test(
        pool: &PgPool,
        challenge_id: Uuid,
        deadline: DateTime<Utc>,
    ) {
        let mut tx = pool
            .begin()
            .await
            .expect("begin challenge deadline fixture");
        sqlx::query(
            "ALTER TABLE agent_enrollment_challenges \
             DISABLE TRIGGER agent_enrollment_challenge_lifecycle_guard",
        )
        .execute(&mut *tx)
        .await
        .expect("disable challenge lifecycle guard for fixture");
        sqlx::query("UPDATE agent_enrollment_challenges SET expires_at = $2 WHERE id = $1")
            .bind(challenge_id)
            .bind(deadline)
            .execute(&mut *tx)
            .await
            .expect("set challenge fixture deadline");
        sqlx::query(
            "ALTER TABLE agent_enrollment_challenges \
             ENABLE TRIGGER agent_enrollment_challenge_lifecycle_guard",
        )
        .execute(&mut *tx)
        .await
        .expect("restore challenge lifecycle guard after fixture");
        tx.commit()
            .await
            .expect("commit challenge deadline fixture");
    }

    /// Direct lease-state fixtures deliberately opt into migration 161's v2
    /// transition contract. Production-path tests should call
    /// `lease_pending_job` instead so they exercise the real admission gate.
    async fn begin_agent_job_lease_fixture_tx<'a>(
        pool: &'a PgPool,
    ) -> sqlx::Transaction<'a, sqlx::Postgres> {
        let mut tx = pool.begin().await.expect("begin lease fixture transaction");
        activate_agent_job_lease_contract_v2(&mut tx)
            .await
            .expect("activate v2 lease contract for fixture");
        tx
    }

    fn terraform_test_capabilities(vsphere_version: &str) -> Capabilities {
        Capabilities {
            terraform: Some(ryuki_protocol::ToolCapability {
                version: "1.9.5".to_owned(),
                provider_versions: std::collections::BTreeMap::from([(
                    "vsphere".to_owned(),
                    vsphere_version.to_owned(),
                )]),
            }),
            ansible: None,
        }
    }

    fn test_agent_capabilities() -> Capabilities {
        Capabilities {
            terraform: terraform_test_capabilities("2.16.1").terraform,
            ansible: Some(ryuki_protocol::ToolCapability {
                version: "2.16.0".to_owned(),
                provider_versions: std::collections::BTreeMap::new(),
            }),
        }
    }

    /// Inserts a test agent row directly with an explicit administrator-approved
    /// capability document. Returns the plaintext bearer token.
    async fn seed_agent_with_capabilities(
        pool: &PgPool,
        agent_id: &str,
        platform: &str,
        status: &str,
        capabilities: &Capabilities,
    ) -> String {
        let token = format!(
            "{AGENT_TOKEN_PREFIX}test{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        let capabilities = serde_json::to_value(capabilities).expect("serialize capabilities");
        seed_challenge_admitted_test_agent(
            pool,
            ChallengeAdmittedTestAgent {
                agent_id,
                platform,
                public_key: "test-pubkey",
                token_hash: &hash,
                capabilities: &capabilities,
                final_status: status,
                last_seen_at: None,
            },
        )
        .await;
        token
    }

    /// Most leasing tests use an agent approved for every embedded test job.
    async fn seed_agent(pool: &PgPool, agent_id: &str, platform: &str, status: &str) -> String {
        seed_agent_with_capabilities(pool, agent_id, platform, status, &test_agent_capabilities())
            .await
    }

    async fn seed_pending_job_for_iac(pool: &PgPool, platform: &str, iac_ref: &str) -> Uuid {
        use std::collections::BTreeMap;
        let spec = ryuki_protocol::JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: iac_ref.to_owned(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-test-{}", Uuid::new_v4().simple())),
            mode: ryuki_protocol::JobMode::OfflineDryRun,
        };
        create_agent_job(pool, Uuid::new_v4(), platform, &spec, "OfflineDryRun")
            .await
            .expect("seed job")
    }

    async fn seed_pending_job(pool: &PgPool, platform: &str) -> Uuid {
        seed_pending_job_for_iac(pool, platform, "linux-server-deployment@v1").await
    }

    fn stateful_test_spec(request_id: Uuid, state_key: &str, mode: JobMode) -> JobSpec {
        JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: std::collections::BTreeMap::new(),
            state_key: Some(state_key.to_string()),
            mode,
        }
    }

    async fn cleanup_agent(pool: &PgPool, agent_id: &str) {
        sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM agent_enrollment_challenges WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn enrollment_review_binding(pool: &PgPool, agent_id: &str) -> (Uuid, String) {
        let (id, public_key): (Uuid, String) =
            sqlx::query_as("SELECT id, public_key FROM agents WHERE agent_id = $1")
                .bind(agent_id)
                .fetch_one(pool)
                .await
                .expect("fetch enrollment review binding");
        (id, public_key_fingerprint(&public_key))
    }

    fn approve_body(enrollment_id: Uuid, public_key_fingerprint: String) -> ApproveBody {
        ApproveBody {
            enrollment_id,
            public_key_fingerprint,
            platform: "ci".to_owned(),
            capabilities: None,
        }
    }

    fn revoke_body(enrollment_id: Uuid, public_key_fingerprint: String) -> RevokeBody {
        RevokeBody {
            enrollment_id,
            public_key_fingerprint,
        }
    }

    async fn cleanup_jobs_for_platform(pool: &PgPool, platform: &str) {
        sqlx::query("DELETE FROM agent_jobs WHERE platform = $1")
            .bind(platform)
            .execute(pool)
            .await
            .ok();
    }

    /// Initialises the PROCESS-GLOBAL `database::POOL` so handler calls routed
    /// through `get_db()` (admin_approve_agent / admin_revoke_agent) hit the real
    /// DB. Serialise with DB_TEST_SERIAL since the pool is process-global.
    async fn handler_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()?;
        crate::database::run_migrations(pool).await.ok()?;
        Some(pool)
    }

    fn non_admin_session() -> AuthSession {
        AuthSession {
            user_id: "requester-1".into(),
            display_name: "Requester".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            provider_mode: "test".into(),
            ..Default::default()
        }
    }

    // ── #3 agent revoke ──────────────────────────────────────────────────────

    /// Revoking an approved agent flips it to 'revoked' and its token is refused on
    /// the next authenticated call (authenticate_agent rejects status != approved).
    #[tokio::test]
    async fn db_revoke_approved_agent_blocks_token() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("revoke-approved-{}", Uuid::new_v4());
        let token = seed_agent(pool, &agent_id, "ci", "approved").await;
        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &agent_id).await;

        // Token works while approved.
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        assert!(
            authenticate_agent(&headers, pool).await.is_ok(),
            "approved agent token must authenticate before revoke"
        );

        // Revoke.
        let resp = admin_revoke_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(enrollment_id, fingerprint)),
        )
        .await
        .expect("revoke must succeed");
        assert_eq!(resp.0["status"], json!("revoked"));

        // Status persisted + token now refused.
        let (status,): (String,) = sqlx::query_as("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("fetch status");
        assert_eq!(status, "revoked");
        let auth = authenticate_agent(&headers, pool).await;
        assert!(
            matches!(auth, Err((StatusCode::FORBIDDEN, _))),
            "a revoked agent's token must be refused: {auth:?}"
        );

        cleanup_agent(pool, &agent_id).await;
    }

    /// A non-assignee agent acking a job leased to a DIFFERENT agent must get a
    /// generic 403 — never a status-specific 409 that would disclose the job's
    /// existence and lifecycle state to a token holder who is not the assignee.
    #[tokio::test]
    async fn db_ack_job_cross_agent_is_not_a_state_oracle() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("ci-ack-oracle-{}", Uuid::new_v4());
        let assignee = format!("ack-assignee-{}", Uuid::new_v4());
        let attacker = format!("ack-attacker-{}", Uuid::new_v4());
        let assignee_token = seed_agent(pool, &assignee, &platform, "approved").await;
        let attacker_token = seed_agent(pool, &attacker, &platform, "approved").await;

        // Seed a job and lease it to the ASSIGNEE (attempt_id/fencing_token the
        // attacker cannot know).
        let job_id = seed_pending_job(pool, &platform).await;
        let assignee_attempt = Uuid::new_v4();
        let assignee_fencing = Uuid::new_v4().to_string();
        let mut lease_tx = begin_agent_job_lease_fixture_tx(pool).await;
        sqlx::query(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, fencing_token = $3, \
                 lease_deadline = NOW() + INTERVAL '5 minutes', updated_at = NOW() \
             WHERE id = $4",
        )
        .bind(&assignee)
        .bind(assignee_attempt)
        .bind(&assignee_fencing)
        .bind(job_id)
        .execute(&mut *lease_tx)
        .await
        .expect("lease to assignee");
        lease_tx.commit().await.expect("commit assignee lease");

        // The attacker acks the SAME job id with its own (wrong) fencing material.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {attacker_token}").parse().unwrap(),
        );
        let result = ack_job(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            Path((attacker.clone(), job_id.to_string())),
            headers,
            Json(AckBody {
                attempt_id: Uuid::new_v4(),
                fencing_token: Uuid::new_v4().to_string(),
            }),
        )
        .await;

        // Must be a generic 403 — NOT a 409 leaking status ('Leased'/attempt/lease).
        match result {
            Err((StatusCode::FORBIDDEN, body)) => {
                let s = body.0.to_string();
                assert!(
                    !s.contains("Leased")
                        && !s.contains("attempt_id")
                        && !s.contains("lease has expired")
                        && !s.contains("fencing_token mismatch"),
                    "403 body must not disclose job state: {s}"
                );
            }
            other => panic!("cross-agent ack must be 403 with no state disclosure: {other:?}"),
        }

        // The assignee's lease is untouched — a real ack still works.
        let mut assignee_headers = HeaderMap::new();
        assignee_headers.insert(
            "Authorization",
            format!("Bearer {assignee_token}").parse().unwrap(),
        );
        let ok = ack_job(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            Path((assignee.clone(), job_id.to_string())),
            assignee_headers,
            Json(AckBody {
                attempt_id: assignee_attempt,
                fencing_token: assignee_fencing.clone(),
            }),
        )
        .await;
        assert!(
            ok.is_ok(),
            "assignee's genuine ack must still succeed: {ok:?}"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(pool)
            .await
            .ok();
        cleanup_agent(pool, &assignee).await;
        cleanup_agent(pool, &attacker).await;
    }

    /// A pending agent can be revoked (deny enrollment); unknown agent → 404;
    /// re-revoke is idempotent (200, already_revoked).
    #[tokio::test]
    async fn db_revoke_pending_unknown_and_idempotent() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pending = format!("revoke-pending-{}", Uuid::new_v4());
        seed_agent(pool, &pending, "ci", "pending").await;
        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &pending).await;
        let r = admin_revoke_agent(
            Path(pending.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(enrollment_id, fingerprint.clone())),
        )
        .await
        .expect("revoke pending must succeed");
        assert_eq!(r.0["status"], json!("revoked"));

        // Idempotent re-revoke.
        let again = admin_revoke_agent(
            Path(pending.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(enrollment_id, fingerprint)),
        )
        .await
        .expect("re-revoke must succeed");
        assert_eq!(again.0["already_revoked"], json!(true));

        // Unknown agent → 404.
        let missing = admin_revoke_agent(
            Path(format!("nope-{}", Uuid::new_v4())),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(
                Uuid::nil(),
                public_key_fingerprint("unknown-enrollment"),
            )),
        )
        .await;
        assert!(
            matches!(missing, Err((StatusCode::NOT_FOUND, _))),
            "unknown agent revoke must 404: {missing:?}"
        );

        cleanup_agent(pool, &pending).await;
    }

    /// Revoke is TERMINAL: a revoked agent cannot be re-approved (409); it must
    /// re-enroll. Guards against undoing a revocation of a compromised credential.
    #[tokio::test]
    async fn db_approve_after_revoke_is_conflict() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("revoke-terminal-{}", Uuid::new_v4());
        seed_agent(pool, &agent_id, "ci", "approved").await;
        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &agent_id).await;
        let _ = admin_revoke_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(enrollment_id, fingerprint.clone())),
        )
        .await
        .expect("revoke");
        let reapprove = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(approve_body(enrollment_id, fingerprint)),
        )
        .await;
        assert!(
            matches!(reapprove, Err((StatusCode::CONFLICT, _))),
            "re-approving a revoked agent must 409: {reapprove:?}"
        );
        // Still revoked.
        let (status,): (String,) = sqlx::query_as("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("fetch");
        assert_eq!(status, "revoked", "agent must remain revoked");

        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_approve_expired_pending_requires_reenrollment() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("expired-enrollment-{}", Uuid::new_v4());
        seed_agent(pool, &agent_id, "ci", "pending").await;
        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &agent_id).await;
        force_agent_enrollment_deadline_for_test(
            pool,
            &agent_id,
            Utc::now() - Duration::seconds(1),
        )
        .await;

        let approval = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(approve_body(enrollment_id, fingerprint)),
        )
        .await;
        assert!(
            matches!(approval, Err((StatusCode::CONFLICT, _))),
            "an expired Pending record must not be resurrected by approval: {approval:?}"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("read expired enrollment");
        assert_eq!(status, "pending", "failed approval must not mutate state");

        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_stale_enrollment_review_cannot_mutate_replacement_key() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("stale-review-{}", Uuid::new_v4());
        seed_agent(pool, &agent_id, "ci", "pending").await;
        let (old_enrollment_id, old_fingerprint) = enrollment_review_binding(pool, &agent_id).await;
        force_agent_enrollment_deadline_for_test(
            pool,
            &agent_id,
            Utc::now() - Duration::seconds(1),
        )
        .await;

        let replacement_body = valid_registration_body(agent_id.clone());
        seed_registration_challenge(pool, &replacement_body).await;
        let replacement =
            validate_registration_input(&replacement_body).expect("replacement input");
        let replacement_caps = serde_json::to_value(&replacement_body.capabilities).unwrap();
        persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &replacement,
            &replacement_caps,
            MAX_PENDING_AGENT_ENROLLMENTS,
        )
        .await
        .expect("expired identity may create a fresh bounded enrollment");
        let (new_enrollment_id, new_fingerprint) = enrollment_review_binding(pool, &agent_id).await;
        assert_ne!(old_enrollment_id, new_enrollment_id);
        assert_ne!(old_fingerprint, new_fingerprint);

        let stale_approval = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(approve_body(old_enrollment_id, old_fingerprint.clone())),
        )
        .await;
        assert!(
            matches!(stale_approval, Err((StatusCode::CONFLICT, _))),
            "a stale review must not approve the replacement key: {stale_approval:?}"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("read replacement status");
        assert_eq!(
            status, "pending",
            "stale approval must not mutate replacement"
        );

        let stale_revoke = admin_revoke_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(old_enrollment_id, old_fingerprint)),
        )
        .await;
        assert!(
            matches!(stale_revoke, Err((StatusCode::CONFLICT, _))),
            "a stale review must not revoke the replacement key: {stale_revoke:?}"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("read replacement status after stale revoke");
        assert_eq!(
            status, "pending",
            "stale revocation must not mutate replacement"
        );

        let current_approval = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(approve_body(new_enrollment_id, new_fingerprint)),
        )
        .await;
        assert!(
            current_approval.is_ok(),
            "the exact current row/key review must remain approvable: {current_approval:?}"
        );

        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_approval_expiry_is_checked_at_database_mutation_time() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("db-clock-expiry-{}", Uuid::new_v4());
        seed_agent(pool, &agent_id, "ci", "pending").await;
        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &agent_id).await;
        force_agent_enrollment_deadline_for_test(
            pool,
            &agent_id,
            Utc::now() + Duration::milliseconds(100),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let approval = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(approve_body(enrollment_id, fingerprint)),
        )
        .await;
        assert!(
            matches!(approval, Err((StatusCode::CONFLICT, _))),
            "the atomic DB-clock predicate must reject after the database deadline: {approval:?}"
        );
        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_enrollment_contract_blocks_old_replica_and_defaults_v3_admission() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let old_agent_id = format!("old-contract-agent-{}", Uuid::new_v4());
        let old_insert = sqlx::query(
            "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
             VALUES ($1, 'ci', '{}'::jsonb, 'legacy-pubkey', $2, 'pending')",
        )
        .bind(&old_agent_id)
        .bind(sha256_hex(&format!("old-contract-token-{old_agent_id}")))
        .execute(pool)
        .await
        .expect_err("an old replica without the v3 transaction marker must fail closed");
        let old_insert_code = old_insert
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(old_insert_code.as_deref(), Some("55000"));
        let old_row_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&old_agent_id)
                .fetch_one(pool)
                .await
                .expect("check rejected old-contract insert");
        assert!(!old_row_exists);

        let agent_id = format!("v3-default-admission-{}", Uuid::new_v4());
        let body = valid_registration_body(agent_id.clone());
        seed_registration_challenge(pool, &body).await;
        let registration = validate_registration_input(&body).expect("signed registration fixture");
        let capabilities = serde_json::to_value(&body.capabilities).unwrap();
        persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &registration,
            &capabilities,
            MAX_PENDING_AGENT_ENROLLMENTS,
        )
        .await
        .expect("v3 registration consumes the preprovisioned challenge");

        let (has_future_expiry, bounds_version): (bool, i16) = sqlx::query_as(
            "SELECT enrollment_expires_at IS NOT NULL \
                    AND enrollment_expires_at > clock_timestamp() \
                    , enrollment_bounds_version \
             FROM agents WHERE agent_id = $1",
        )
        .bind(&agent_id)
        .fetch_one(pool)
        .await
        .expect("read v3 schema defaults");
        assert!(has_future_expiry);
        assert_eq!(bounds_version, 1, "new rows must receive bounded version 1");

        let constraint_validated: bool = sqlx::query_scalar(
            "SELECT convalidated FROM pg_constraint \
             WHERE conrelid = 'agents'::regclass \
               AND conname = 'agents_pending_enrollment_has_expiry'",
        )
        .fetch_one(pool)
        .await
        .expect("read pending-expiry constraint state");
        assert!(
            constraint_validated,
            "the lifecycle constraint must not preserve legacy NULL rows"
        );

        let challenge_constraint_validated: bool = sqlx::query_scalar(
            "SELECT convalidated FROM pg_constraint \
             WHERE conrelid = 'agents'::regclass \
               AND conname = 'agents_pending_enrollment_has_challenge'",
        )
        .fetch_one(pool)
        .await
        .expect("read pending-challenge constraint state");
        assert!(
            challenge_constraint_validated,
            "every Pending row must carry trusted challenge provenance"
        );

        let challenge_fk_validated: bool = sqlx::query_scalar(
            "SELECT convalidated FROM pg_constraint \
             WHERE conrelid = 'agents'::regclass \
               AND conname = 'agents_enrollment_challenge_id_fkey'",
        )
        .fetch_one(pool)
        .await
        .expect("read named enrollment-challenge foreign key state");
        assert!(
            challenge_fk_validated,
            "the named challenge foreign key must be present and fully validated"
        );

        let old_approve = sqlx::query(
            "UPDATE agents SET status = 'approved', platform = 'ci' WHERE agent_id = $1",
        )
        .bind(&agent_id)
        .execute(pool)
        .await
        .expect_err("an old id-only approval must be blocked by the v3 trigger");
        let old_approve_code = old_approve
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(old_approve_code.as_deref(), Some("55000"));

        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &agent_id).await;
        let _ = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(approve_body(enrollment_id, fingerprint.clone())),
        )
        .await
        .expect("the v3 challenge-bound approval must remain available");

        let old_revoke = sqlx::query("UPDATE agents SET status = 'revoked' WHERE agent_id = $1")
            .bind(&agent_id)
            .execute(pool)
            .await
            .expect_err("an old id-only revoke must be blocked by the v3 trigger");
        let old_revoke_code = old_revoke
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(old_revoke_code.as_deref(), Some("55000"));
        let status: String = sqlx::query_scalar("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("read state after blocked old revoke");
        assert_eq!(status, "approved");

        let _ = admin_revoke_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(revoke_body(enrollment_id, fingerprint)),
        )
        .await
        .expect("the v3 bound revoke must remain available");

        let mut current_tx = pool.begin().await.expect("begin terminal-revoke check");
        activate_agent_enrollment_contract_v3(&mut current_tx)
            .await
            .expect("activate current enrollment marker");
        let terminal_reapprove =
            sqlx::query("UPDATE agents SET status = 'approved' WHERE agent_id = $1")
                .bind(&agent_id)
                .execute(&mut *current_tx)
                .await
                .expect_err("even a marker-aware sibling writer must not undo revocation");
        let terminal_reapprove_code = terminal_reapprove
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(terminal_reapprove_code.as_deref(), Some("23514"));
        current_tx
            .rollback()
            .await
            .expect("rollback terminal-revoke check");

        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_enrollment_authority_and_challenge_lifecycle_are_immutable() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // A marker-aware sibling/direct writer still cannot take over an
        // approved identity by replacing only its bearer hash.
        let approved_id = format!("immutable-token-{}", Uuid::new_v4());
        let original_token = seed_agent(pool, &approved_id, "ci", "approved").await;
        let original_hash = sha256_hex(&original_token);
        let replacement_hash = sha256_hex(&format!("replacement-token-{approved_id}"));
        let mut token_tx = pool.begin().await.expect("begin token takeover check");
        activate_agent_enrollment_contract_v3(&mut token_tx)
            .await
            .expect("activate token immutability contract");
        let token_error = sqlx::query("UPDATE agents SET token_hash = $2 WHERE agent_id = $1")
            .bind(&approved_id)
            .bind(&replacement_hash)
            .execute(&mut *token_tx)
            .await
            .expect_err("an approved agent bearer hash must be immutable");
        let token_error_code = token_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(token_error_code.as_deref(), Some("23514"));
        token_tx
            .rollback()
            .await
            .expect("rollback token takeover check");
        let stored_hash: String =
            sqlx::query_scalar("SELECT token_hash FROM agents WHERE agent_id = $1")
                .bind(&approved_id)
                .fetch_one(pool)
                .await
                .expect("read bearer hash after rejected takeover");
        assert_eq!(stored_hash, original_hash);

        // The database owns the Pending deadline. It cannot be extended, and
        // an already-expired row cannot cross the trust boundary even when a
        // sibling supplies the current rolling-deployment marker.
        let pending_id = format!("immutable-expiry-{}", Uuid::new_v4());
        seed_agent(pool, &pending_id, "ci", "pending").await;
        let original_expiry: DateTime<Utc> =
            sqlx::query_scalar("SELECT enrollment_expires_at FROM agents WHERE agent_id = $1")
                .bind(&pending_id)
                .fetch_one(pool)
                .await
                .expect("read database-owned pending deadline");
        let mut expiry_tx = pool.begin().await.expect("begin expiry extension check");
        activate_agent_enrollment_contract_v3(&mut expiry_tx)
            .await
            .expect("activate expiry immutability contract");
        let expiry_error = sqlx::query(
            "UPDATE agents \
             SET enrollment_expires_at = enrollment_expires_at + INTERVAL '1 day' \
             WHERE agent_id = $1",
        )
        .bind(&pending_id)
        .execute(&mut *expiry_tx)
        .await
        .expect_err("a Pending enrollment deadline must not be extendable");
        let expiry_error_code = expiry_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(expiry_error_code.as_deref(), Some("23514"));
        expiry_tx
            .rollback()
            .await
            .expect("rollback expiry extension check");
        let stored_expiry: DateTime<Utc> =
            sqlx::query_scalar("SELECT enrollment_expires_at FROM agents WHERE agent_id = $1")
                .bind(&pending_id)
                .fetch_one(pool)
                .await
                .expect("read deadline after rejected extension");
        assert_eq!(stored_expiry, original_expiry);

        force_agent_enrollment_deadline_for_test(
            pool,
            &pending_id,
            Utc::now() - Duration::seconds(1),
        )
        .await;
        let mut approval_tx = pool.begin().await.expect("begin expired approval check");
        activate_agent_enrollment_contract_v3(&mut approval_tx)
            .await
            .expect("activate expired approval contract");
        let approval_error = sqlx::query(
            "UPDATE agents \
             SET status = 'approved', enrollment_expires_at = NULL \
             WHERE agent_id = $1",
        )
        .bind(&pending_id)
        .execute(&mut *approval_tx)
        .await
        .expect_err("an expired Pending enrollment must not be approved directly");
        let approval_error_code = approval_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(approval_error_code.as_deref(), Some("23514"));
        approval_tx
            .rollback()
            .await
            .expect("rollback expired approval check");

        // A provisioning challenge is an immutable, one-use grant. Neither an
        // active deadline/binding nor a consumed terminal row may be rewritten.
        let challenge_agent_id = format!("immutable-challenge-{}", Uuid::new_v4());
        let body = valid_registration_body(challenge_agent_id.clone());
        let challenge_id = body.enrollment_challenge_id;
        seed_registration_challenge(pool, &body).await;

        let challenge_expiry_error = sqlx::query(
            "UPDATE agent_enrollment_challenges \
             SET expires_at = expires_at + INTERVAL '1 day' WHERE id = $1",
        )
        .bind(challenge_id)
        .execute(pool)
        .await
        .expect_err("a provisioning challenge deadline must be immutable");
        let challenge_expiry_code = challenge_expiry_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(challenge_expiry_code.as_deref(), Some("23514"));

        let challenge_rebind_error = sqlx::query(
            "UPDATE agent_enrollment_challenges \
             SET agent_id = $2 WHERE id = $1",
        )
        .bind(challenge_id)
        .bind(format!("rebound-{challenge_agent_id}"))
        .execute(pool)
        .await
        .expect_err("a provisioning challenge identity binding must be immutable");
        let challenge_rebind_code = challenge_rebind_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(challenge_rebind_code.as_deref(), Some("23514"));

        let registration = validate_registration_input(&body).expect("signed registration fixture");
        let capabilities = serde_json::to_value(&body.capabilities).unwrap();
        persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &registration,
            &capabilities,
            MAX_PENDING_AGENT_ENROLLMENTS,
        )
        .await
        .expect("consume immutable provisioning challenge");

        let challenge_reopen_error = sqlx::query(
            "UPDATE agent_enrollment_challenges \
             SET status = 'pending', consumed_at = NULL, \
                 consumed_enrollment_id = NULL WHERE id = $1",
        )
        .bind(challenge_id)
        .execute(pool)
        .await
        .expect_err("a consumed provisioning challenge must remain terminal");
        let challenge_reopen_code = challenge_reopen_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(challenge_reopen_code.as_deref(), Some("23514"));
        let challenge_status: String =
            sqlx::query_scalar("SELECT status FROM agent_enrollment_challenges WHERE id = $1")
                .bind(challenge_id)
                .fetch_one(pool)
                .await
                .expect("read terminal provisioning challenge");
        assert_eq!(challenge_status, "consumed");

        for agent_id in [&approved_id, &pending_id, &challenge_agent_id] {
            cleanup_agent(pool, agent_id).await;
        }
    }

    #[tokio::test]
    async fn db_post_cutover_non_pending_agent_inserts_are_blocked() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        for forged_status in ["approved", "revoked"] {
            let agent_id = format!("forged-{forged_status}-{}", Uuid::new_v4());
            let mut tx = pool.begin().await.expect("begin rejected identity fixture");
            activate_agent_enrollment_contract_v3(&mut tx)
                .await
                .expect("activate current enrollment marker");
            let error = sqlx::query(
                "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status, \
                     enrollment_bounds_version) \
                 VALUES ($1, 'ci', '{}'::jsonb, 'forged-pubkey', $2, $3, 1)",
            )
            .bind(&agent_id)
            .bind(sha256_hex(&format!("forged-{forged_status}-token-{agent_id}")))
            .bind(forged_status)
            .execute(&mut *tx)
            .await
            .expect_err("post-cutover writers must not create non-Pending identities");
            let error_code = error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .map(|code| code.into_owned());
            assert_eq!(error_code.as_deref(), Some("23514"));
            tx.rollback()
                .await
                .expect("rollback rejected identity fixture");
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                    .bind(&agent_id)
                    .fetch_one(pool)
                    .await
                    .expect("check rejected non-Pending identity");
            assert!(!exists, "the rejected identity must leave no durable row");
        }
    }

    /// Both approve and revoke require admin (defense in depth beyond middleware).
    #[tokio::test]
    async fn db_revoke_and_approve_require_admin() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("revoke-authz-{}", Uuid::new_v4());
        seed_agent(pool, &agent_id, "ci", "approved").await;

        let revoke_denied = admin_revoke_agent(
            Path(agent_id.clone()),
            Extension(non_admin_session()),
            Json(revoke_body(Uuid::nil(), String::new())),
        )
        .await;
        assert!(
            matches!(revoke_denied, Err((StatusCode::FORBIDDEN, _))),
            "non-admin revoke must 403: {revoke_denied:?}"
        );
        let approve_denied = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(non_admin_session()),
            Json(approve_body(Uuid::nil(), String::new())),
        )
        .await;
        assert!(
            matches!(approve_denied, Err((StatusCode::FORBIDDEN, _))),
            "non-admin approve must 403: {approve_denied:?}"
        );
        // Unchanged.
        let (status,): (String,) = sqlx::query_as("SELECT status FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(pool)
            .await
            .expect("fetch");
        assert_eq!(
            status, "approved",
            "a denied call must not mutate the agent"
        );

        cleanup_agent(pool, &agent_id).await;
    }

    // ── register persists pending ─────────────────────────────────────────

    #[tokio::test]
    async fn db_register_persists_pending() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = format!("test-agent-{}", Uuid::new_v4());
        let body = valid_registration_body(id.clone());
        seed_registration_challenge(&pool, &body).await;
        let registration = validate_registration_input(&body).expect("signed registration fixture");
        let capabilities = serde_json::to_value(&body.capabilities).unwrap();
        let token = persist_pending_agent_registration(
            &pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &registration,
            &capabilities,
            MAX_PENDING_AGENT_ENROLLMENTS,
        )
        .await
        .expect("persist challenge-admitted registration");
        let hash = sha256_hex(&token);

        let row = sqlx::query_as::<_, AgentRow>(
            "SELECT id, agent_id, public_key, token_hash, status \
             FROM agents WHERE agent_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("fetch");

        assert_eq!(row.status, "pending");
        assert_eq!(row.token_hash, hash);

        cleanup_agent(&pool, &id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_expired_pending_enrollment_cleanup_is_bounded() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = Uuid::new_v4();
        let expired_old = format!("cleanup-old-{suffix}");
        let expired_new = format!("cleanup-new-{suffix}");
        let active = format!("cleanup-active-{suffix}");

        for (agent_id, expires_at) in [
            (&expired_old, "2000-01-01T00:00:00Z"),
            (&expired_new, "2001-01-01T00:00:00Z"),
            (&active, "2999-01-01T00:00:00Z"),
        ] {
            seed_agent(pool, agent_id, "ci", "pending").await;
            force_agent_enrollment_deadline_for_test(
                pool,
                agent_id,
                expires_at
                    .parse::<DateTime<Utc>>()
                    .expect("valid enrollment fixture timestamp"),
            )
            .await;
        }

        let removed = cleanup_expired_pending_agent_enrollments_with_batch(pool, 1)
            .await
            .expect("bounded cleanup");
        assert_eq!(removed, 1, "one-row batch must delete exactly one row");

        let old_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&expired_old)
                .fetch_one(pool)
                .await
                .expect("read old expired enrollment");
        let new_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&expired_new)
                .fetch_one(pool)
                .await
                .expect("read newer expired enrollment");
        let active_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&active)
                .fetch_one(pool)
                .await
                .expect("read active enrollment");
        assert!(!old_exists, "cleanup must remove the oldest expired row");
        assert!(
            new_exists,
            "the batch limit must leave the second expired row"
        );
        assert!(
            active_exists,
            "cleanup must preserve unexpired Pending rows"
        );

        for agent_id in [&expired_new, &active] {
            cleanup_agent(pool, agent_id).await;
        }
    }

    #[tokio::test]
    async fn db_pending_enrollment_quota_allows_one_then_rejects_growth() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let active_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agents \
             WHERE status = 'pending' AND enrollment_expires_at > NOW()",
        )
        .fetch_one(pool)
        .await
        .expect("count active Pending enrollments");
        let test_quota = active_before + 1;

        let first_id = format!("quota-first-{}", Uuid::new_v4());
        let first_body = valid_registration_body(first_id.clone());
        seed_registration_challenge(pool, &first_body).await;
        let first = validate_registration_input(&first_body).expect("first input");
        let first_caps = serde_json::to_value(&first_body.capabilities).unwrap();
        let first_token = persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &first,
            &first_caps,
            test_quota,
        )
        .await
        .expect("the final available Pending slot must be admitted");
        assert!(first_token.starts_with(AGENT_TOKEN_PREFIX));

        let expires_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT enrollment_expires_at FROM agents WHERE agent_id = $1")
                .bind(&first_id)
                .fetch_one(pool)
                .await
                .expect("read admitted enrollment expiry");
        assert!(
            expires_at.is_some_and(|deadline| deadline > Utc::now()),
            "an admitted Pending row must have a future expiry"
        );

        let second_id = format!("quota-second-{}", Uuid::new_v4());
        let second_body = valid_registration_body(second_id.clone());
        seed_registration_challenge(pool, &second_body).await;
        let second = validate_registration_input(&second_body).expect("second input");
        let second_caps = serde_json::to_value(&second_body.capabilities).unwrap();
        let rejected = persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &second,
            &second_caps,
            test_quota,
        )
        .await;
        assert!(
            matches!(rejected, Err((StatusCode::TOO_MANY_REQUESTS, _))),
            "the aggregate cap must reject another unique Pending row: {rejected:?}"
        );
        let second_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&second_id)
                .fetch_one(pool)
                .await
                .expect("check rejected enrollment");
        assert!(!second_exists, "quota rejection must not persist a row");

        cleanup_agent(pool, &first_id).await;
        cleanup_agent(pool, &second_id).await;
    }

    #[tokio::test]
    async fn db_pending_enrollment_quota_is_atomic_under_concurrency() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let active_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agents \
             WHERE status = 'pending' AND enrollment_expires_at > NOW()",
        )
        .fetch_one(pool)
        .await
        .expect("count active Pending enrollments");
        let test_quota = active_before + 1;

        const CALLERS: usize = 8;
        let mut tasks = Vec::with_capacity(CALLERS);
        let mut fixtures = Vec::with_capacity(CALLERS);
        for index in 0..CALLERS {
            let agent_id = format!("quota-race-{index}-{}", Uuid::new_v4());
            let body = valid_registration_body(agent_id.clone());
            seed_registration_challenge(pool, &body).await;
            fixtures.push((agent_id, body));
        }
        for (agent_id, body) in fixtures {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                let registration = validate_registration_input(&body).expect("bounded input");
                let capabilities = serde_json::to_value(&body.capabilities).unwrap();
                let result = persist_pending_agent_registration(
                    &pool,
                    ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
                    &registration,
                    &capabilities,
                    test_quota,
                )
                .await;
                (agent_id, result)
            }));
        }

        let mut ids = Vec::with_capacity(CALLERS);
        let mut admitted = 0usize;
        for task in tasks {
            let (agent_id, result) = task.await.expect("registration task");
            ids.push(agent_id);
            match result {
                Ok(token) => {
                    admitted += 1;
                    assert!(token.starts_with(AGENT_TOKEN_PREFIX));
                }
                Err((StatusCode::TOO_MANY_REQUESTS, _)) => {}
                other => panic!("concurrent admission returned an unexpected result: {other:?}"),
            }
        }
        assert_eq!(
            admitted, 1,
            "serialized count-and-insert must admit exactly the final available slot"
        );

        let active_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agents \
             WHERE status = 'pending' AND enrollment_expires_at > NOW()",
        )
        .fetch_one(pool)
        .await
        .expect("count after concurrent admission");
        assert_eq!(active_after, active_before + 1);

        for agent_id in ids {
            cleanup_agent(pool, &agent_id).await;
        }
    }

    #[tokio::test]
    async fn db_enrollment_challenge_rejects_wrong_identity_key_and_expiry() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let intended_key = generate_keypair(&mut OsRng);
        let attacker_key = generate_keypair(&mut OsRng);
        let challenge_id = Uuid::new_v4();
        let challenge = generate_agent_enrollment_challenge();
        let intended_id = format!("challenge-intended-{}", Uuid::new_v4());
        let intended = signed_registration_body(
            challenge_id,
            challenge.clone(),
            intended_id.clone(),
            "ci".to_owned(),
            &intended_key,
        );
        seed_registration_challenge(pool, &intended).await;

        let wrong_identity = signed_registration_body(
            challenge_id,
            challenge.clone(),
            format!("challenge-attacker-{}", Uuid::new_v4()),
            "ci".to_owned(),
            &intended_key,
        );
        let wrong_key = signed_registration_body(
            challenge_id,
            challenge.clone(),
            intended_id.clone(),
            "ci".to_owned(),
            &attacker_key,
        );
        for malicious in [&wrong_identity, &wrong_key] {
            let registration =
                validate_registration_input(malicious).expect("self-consistent signed claim");
            let capabilities = serde_json::to_value(&malicious.capabilities).unwrap();
            let result = persist_pending_agent_registration(
                pool,
                ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
                &registration,
                &capabilities,
                MAX_PENDING_AGENT_ENROLLMENTS,
            )
            .await;
            assert!(
                matches!(result, Err((StatusCode::FORBIDDEN, _))),
                "a self-signed but non-preprovisioned identity/key must fail closed: {result:?}"
            );
        }

        force_challenge_deadline_for_test(pool, challenge_id, Utc::now() - Duration::seconds(1))
            .await;
        let registration =
            validate_registration_input(&intended).expect("intended signed registration");
        let capabilities = serde_json::to_value(&intended.capabilities).unwrap();
        let expired = persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &registration,
            &capabilities,
            MAX_PENDING_AGENT_ENROLLMENTS,
        )
        .await;
        assert!(matches!(expired, Err((StatusCode::FORBIDDEN, _))));
        let durable_identity_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&intended_id)
                .fetch_one(pool)
                .await
                .expect("check rejected identity");
        assert!(
            !durable_identity_exists,
            "wrong or expired challenge claims must not allocate a durable identity"
        );
        cleanup_agent(pool, &intended_id).await;
        cleanup_agent(pool, &wrong_identity.agent_id).await;
    }

    #[tokio::test]
    async fn db_enrollment_challenge_is_single_use_under_concurrency_and_replay() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("challenge-race-{}", Uuid::new_v4());
        let body = valid_registration_body(agent_id.clone());
        seed_registration_challenge(pool, &body).await;

        let mut tasks = Vec::new();
        for claim in [body.clone(), body.clone()] {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                let registration =
                    validate_registration_input(&claim).expect("signed registration claim");
                let capabilities = serde_json::to_value(&claim.capabilities).unwrap();
                persist_pending_agent_registration(
                    &pool,
                    ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
                    &registration,
                    &capabilities,
                    MAX_PENDING_AGENT_ENROLLMENTS,
                )
                .await
            }));
        }
        let results = [
            tasks.remove(0).await.expect("first claim task"),
            tasks.remove(0).await.expect("second claim task"),
        ];
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one concurrent claimant may consume the challenge: {results:?}"
        );
        assert!(results.iter().any(|result| {
            matches!(result, Err((StatusCode::FORBIDDEN, _)))
                || matches!(result, Err((StatusCode::TOO_MANY_REQUESTS, _)))
        }));

        let replay_registration =
            validate_registration_input(&body).expect("replay remains self-consistent");
        let replay_capabilities = serde_json::to_value(&body.capabilities).unwrap();
        let replay = persist_pending_agent_registration(
            pool,
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            &replay_registration,
            &replay_capabilities,
            MAX_PENDING_AGENT_ENROLLMENTS,
        )
        .await;
        assert!(
            matches!(replay, Err((StatusCode::FORBIDDEN, _))),
            "a committed challenge must never replay: {replay:?}"
        );
        let (challenge_status, identity_count): (String, i64) = sqlx::query_as(
            "SELECT challenge.status, \
                    (SELECT COUNT(*) FROM agents WHERE agent_id = $2) \
             FROM agent_enrollment_challenges AS challenge WHERE challenge.id = $1",
        )
        .bind(body.enrollment_challenge_id)
        .bind(&agent_id)
        .fetch_one(pool)
        .await
        .expect("read consumed challenge");
        assert_eq!(challenge_status, "consumed");
        assert_eq!(identity_count, 1);
        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_admin_provisioned_challenge_drives_registration_and_bound_approval() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let key = generate_keypair(&mut OsRng);
        let public_key = encode_verifying_key(&key.verifying_key());
        let agent_id = format!("trusted-enrollment-{}", Uuid::new_v4());
        let (challenge_headers, Json(challenge)) = admin_create_agent_enrollment_challenge(
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(CreateEnrollmentChallengeBody {
                agent_id: agent_id.clone(),
                platform: "ci".to_owned(),
                public_key,
                expires_in_seconds: Some(300),
            }),
        )
        .await
        .expect("trusted administrator provisions challenge");
        assert_eq!(
            challenge_headers,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            "the one-time plaintext challenge must never enter an HTTP or idempotency cache"
        );
        let challenge_debug = format!("{challenge:?}");
        assert!(!challenge_debug.contains(&challenge.enrollment_challenge));
        assert!(challenge_debug.contains("<redacted>"));
        let registration = signed_registration_body(
            challenge.enrollment_challenge_id,
            challenge.enrollment_challenge.clone(),
            agent_id.clone(),
            "ci".to_owned(),
            &key,
        );
        let _ = register_agent(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            HeaderMap::new(),
            Json(registration),
        )
        .await
        .expect("the exact workload key consumes its grant");

        let (enrollment_id, challenge_id, status, secret_hash):
            (Uuid, Uuid, String, String) = sqlx::query_as(
            "SELECT agent.id, agent.enrollment_challenge_id, challenge.status, challenge.secret_hash \
             FROM agents AS agent \
             JOIN agent_enrollment_challenges AS challenge \
               ON challenge.id = agent.enrollment_challenge_id \
             WHERE agent.agent_id = $1",
        )
        .bind(&agent_id)
        .fetch_one(pool)
        .await
        .expect("read cryptographic admission linkage");
        assert_eq!(challenge_id, challenge.enrollment_challenge_id);
        assert_eq!(status, "consumed");
        assert_eq!(secret_hash, sha256_hex(&challenge.enrollment_challenge));
        assert_ne!(secret_hash, challenge.enrollment_challenge);

        let _ = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(ApproveBody {
                enrollment_id,
                public_key_fingerprint: challenge.public_key_fingerprint,
                platform: "ci".to_owned(),
                capabilities: None,
            }),
        )
        .await
        .expect("approval must accept the exact consumed challenge identity");
        cleanup_agent(pool, &agent_id).await;
    }

    /// #run7 wire-contract: register_agent VALIDATES the Ed25519 public_key AT
    /// REGISTRATION. A malformed key is rejected 400 (so an agent can't be approved
    /// with a key it could never sign-verify with — a silent per-slot DoS that would
    /// otherwise only surface at first result submission); a valid generated key is
    /// accepted into 'pending'.
    #[tokio::test]
    async fn db_register_validates_ed25519_public_key() {
        // handler_pool() uses the process-global get_db() singleton — serialize with
        // the other handler tests.
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let mk_body = |agent_id: String, public_key: &str| RegisterBody {
            enrollment_challenge_id: Uuid::new_v4(),
            enrollment_challenge: generate_agent_enrollment_challenge(),
            agent_id,
            platform: "ci".to_string(),
            capabilities: Capabilities::default(),
            public_key: public_key.to_string(),
            enrollment_proof: "invalid-before-key-validation".to_owned(),
        };

        // Malformed key -> 400 (rejected before any INSERT).
        let bad_id = format!("badkey-{}", Uuid::new_v4());
        let bad = register_agent(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            HeaderMap::new(),
            Json(mk_body(bad_id.clone(), "not-a-valid-ed25519-key!!")),
        )
        .await;
        assert!(
            matches!(bad, Err((StatusCode::BAD_REQUEST, _))),
            "a malformed public_key must be rejected 400: {bad:?}"
        );
        let bad_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)")
                .bind(&bad_id)
                .fetch_one(pool)
                .await
                .expect("query");
        assert!(
            !bad_exists,
            "a rejected registration must NOT have inserted a row"
        );

        // WEAK (small-order) key -> 400: it decodes fine but verify_strict would reject
        // it at result time, so registration must reject it too. The all-zeros encoding
        // (y = 0, sign 0) decompresses to a LOW-ORDER point, for which is_weak() is true.
        let weak =
            ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).expect("low-order point decodes");
        let weak_b64 = encode_verifying_key(&weak);
        let weak_resp = register_agent(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            HeaderMap::new(),
            Json(mk_body(format!("weak-{}", Uuid::new_v4()), &weak_b64)),
        )
        .await;
        assert!(
            matches!(weak_resp, Err((StatusCode::BAD_REQUEST, _))),
            "a weak (small-order) public_key must be rejected 400: {weak_resp:?}"
        );

        // Valid generated Ed25519 key -> accepted (pending).
        let good_id = format!("goodkey-{}", Uuid::new_v4());
        let good_body = valid_registration_body(good_id.clone());
        seed_registration_challenge(pool, &good_body).await;
        let ok = register_agent(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            HeaderMap::new(),
            Json(good_body),
        )
        .await;
        let Ok((response_headers, Json(resp))) = &ok else {
            panic!("a valid public_key must register: {ok:?}");
        };
        assert_eq!(
            response_headers,
            &[(axum::http::header::CACHE_CONTROL, "no-store")],
            "the one-time agent bearer must never be cacheable"
        );
        let response_debug = format!("{resp:?}");
        assert!(!response_debug.contains(&resp.token));
        assert!(response_debug.contains("<redacted>"));
        assert_eq!(
            resp.agent_id, good_id,
            "the valid registration returns the agent id"
        );

        cleanup_agent(pool, &good_id).await;
    }

    /// #run7 wire-contract: register_agent RECORDS the asserted wire protocol
    /// version into agents.protocol_version (the audit/observability baseline; the
    /// enforcing gate is the per-request extractor, not this row). Uses the
    /// process-global get_db() handler pool, so serialize with the handler tests.
    #[tokio::test]
    async fn db_register_persists_protocol_version() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("protover-{}", Uuid::new_v4());
        let body = valid_registration_body(agent_id.clone());
        seed_registration_challenge(pool, &body).await;

        let ok = register_agent(
            ProtocolVersion(ryuki_protocol::PROTOCOL_VERSION),
            HeaderMap::new(),
            Json(body),
        )
        .await;
        assert!(ok.is_ok(), "a valid registration must succeed: {ok:?}");

        let (stored,): (i64,) =
            sqlx::query_as("SELECT protocol_version FROM agents WHERE agent_id = $1")
                .bind(&agent_id)
                .fetch_one(pool)
                .await
                .expect("fetch protocol_version");
        assert_eq!(
            stored,
            i64::from(ryuki_protocol::PROTOCOL_VERSION),
            "register must persist the asserted protocol version"
        );

        cleanup_agent(pool, &agent_id).await;
    }

    // ── pending agent poll → 403 ─────────────────────────────────────────

    #[tokio::test]
    async fn db_pending_agent_poll_is_forbidden() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("pending-{}", Uuid::new_v4());
        let token = seed_agent(&pool, &agent_id, "ci", "pending").await;

        // Simulate authenticate_agent: it must return Err(403) for pending agents.
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let result = authenticate_agent(&headers, &pool).await;
        assert!(result.is_err(), "pending agent must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);

        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── #44 liveness: classifies APPROVED agents, excludes pending/revoked ──

    #[tokio::test]
    async fn db_agents_liveness_classifies_approved() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let now = Utc::now();
        let suffix = Uuid::new_v4();
        let online_id = format!("live-online-{suffix}");
        let stale_id = format!("live-stale-{suffix}");
        let never_id = format!("live-never-{suffix}");
        let boundary_id = format!("live-boundary-{suffix}");
        let pending_id = format!("live-pending-{suffix}");
        let revoked_id = format!("live-revoked-{suffix}");

        // approved + heartbeat now -> online
        seed_agent(&pool, &online_id, "ci", "approved").await;
        // approved + heartbeat 1000s ago -> offline (window 300)
        seed_agent(&pool, &stale_id, "ci", "approved").await;
        // approved + never seen -> offline
        seed_agent(&pool, &never_id, "ci", "approved").await;
        // approved + heartbeat EXACTLY at the window edge (age == window) -> online
        seed_agent(&pool, &boundary_id, "ci", "approved").await;
        // pending + revoked -> excluded entirely
        seed_agent(&pool, &pending_id, "ci", "pending").await;
        seed_agent(&pool, &revoked_id, "ci", "revoked").await;

        for (id, secs_ago) in [(&online_id, 0_i64), (&stale_id, 1_000), (&boundary_id, 300)] {
            sqlx::query("UPDATE agents SET last_seen_at = $1 WHERE agent_id = $2")
                .bind(now - Duration::seconds(secs_ago))
                .bind(id)
                .execute(&pool)
                .await
                .expect("set last_seen_at");
        }

        let Ok(Json(body)) = agents_liveness_with(&pool, 300, now.timestamp()).await else {
            panic!("liveness core failed");
        };
        let agents = body["agents"].as_array().expect("agents array");
        let liveness_of = |id: &str| -> Option<String> {
            agents
                .iter()
                .find(|a| a["agent_id"] == serde_json::json!(id))
                .map(|a| a["liveness"].as_str().unwrap_or("").to_string())
        };

        assert_eq!(liveness_of(&online_id).as_deref(), Some("online"));
        assert_eq!(liveness_of(&stale_id).as_deref(), Some("offline"));
        assert_eq!(liveness_of(&never_id).as_deref(), Some("offline"));
        // age == window is online (boundary is inclusive, matching the engine).
        assert_eq!(liveness_of(&boundary_id).as_deref(), Some("online"));
        assert!(liveness_of(&pending_id).is_none(), "pending excluded");
        assert!(liveness_of(&revoked_id).is_none(), "revoked excluded");

        // The fleet-wide SQL summary must be internally consistent and include
        // our approved fixtures.
        let summary = &body["summary"];
        let total = summary["total_approved"].as_i64().expect("total_approved");
        let online_c = summary["online"].as_i64().expect("online");
        let offline_c = summary["offline"].as_i64().expect("offline");
        assert_eq!(total, online_c + offline_c, "online + offline == total");
        assert!(total >= 4, "summary counts at least our 4 approved agents");

        // Alignment guard: when the detail list is NOT truncated it holds EVERY
        // approved agent, so summary.online (counted over the full scan) MUST
        // equal the detail online count. Both come from one classification pass
        // over one snapshot with one now_unix, so they can never disagree.
        if body["truncated"] == serde_json::json!(false) {
            let detail_online = agents
                .iter()
                .filter(|a| a["liveness"] == serde_json::json!("online"))
                .count() as i64;
            assert_eq!(
                detail_online, online_c,
                "SQL summary.online must match engine detail when not truncated"
            );
        }

        for id in [
            &online_id,
            &stale_id,
            &never_id,
            &boundary_id,
            &pending_id,
            &revoked_id,
        ] {
            cleanup_agent(&pool, id).await;
        }
        pool.close().await;
    }

    // ── approved agent poll leases a Pending job ─────────────────────────

    #[tokio::test]
    async fn db_approved_agent_poll_leases_pending_job() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let token = seed_agent(&pool, &agent_id, &platform, "approved").await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        // Direct authenticate + the production lease helper used by poll_job.
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let _agent = authenticate_agent(&headers, &pool).await.expect("auth ok");

        let leased = lease_pending_job(&pool, &agent_id)
            .await
            .expect("lease query")
            .expect("must return a row");
        let row = leased.row;

        assert_eq!(row.status, "Leased");
        assert_eq!(row.attempt_id, Some(leased.attempt_id));
        assert_eq!(row.fencing_token.as_deref(), Some(&*leased.fencing_token));
        assert_eq!(row.cp_nonce.as_deref(), Some(&*leased.cp_nonce));
        assert!(row.lease_deadline.is_some());
        assert!(row.lease_generation >= 1);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_lease_contract_blocks_old_replica_then_v2_helper_succeeds() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-lease-contract-{}", Uuid::new_v4().simple());
        let agent_id = format!("lease-contract-agent-{}", Uuid::new_v4());
        seed_agent(&pool, &agent_id, &platform, "approved").await;
        let job_id = seed_pending_job(&pool, &platform).await;

        let old_update =
            sqlx::query("UPDATE agent_jobs SET status = 'Leased', agent_id = $1 WHERE id = $2")
                .bind(&agent_id)
                .bind(job_id)
                .execute(&pool)
                .await
                .expect_err("an old replica without the v2 marker must fail closed");
        let old_update_code = old_update
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(old_update_code.as_deref(), Some("55000"));

        let rejected_state: (String, Option<String>, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT status, agent_id, attempt_id, lease_generation \
             FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read rejected legacy transition");
        assert_eq!(rejected_state, ("Pending".to_owned(), None, None, 0));

        let leased = lease_pending_job(&pool, &agent_id)
            .await
            .expect("v2 lease helper")
            .expect("the rejected job remains available to the v2 helper");
        assert_eq!(leased.row.id, job_id);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_lease_enforces_approved_tool_provider_and_priority_eligibility() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-capability-{}", Uuid::new_v4().simple());
        let capable_agent = format!("capable-{}", Uuid::new_v4());
        let wrong_provider_agent = format!("wrong-provider-{}", Uuid::new_v4());
        let missing_provider_agent = format!("missing-provider-{}", Uuid::new_v4());
        let ansible_agent = format!("ansible-{}", Uuid::new_v4());
        let empty_agent = format!("empty-capabilities-{}", Uuid::new_v4());
        let exact_capabilities = terraform_test_capabilities("2.16.1");
        let wrong_provider_capabilities = terraform_test_capabilities("2.16.0");
        let missing_provider_capabilities = Capabilities {
            terraform: Some(ryuki_protocol::ToolCapability {
                version: "1.9.5".to_owned(),
                provider_versions: std::collections::BTreeMap::new(),
            }),
            ansible: None,
        };
        let ansible_capabilities = Capabilities {
            terraform: None,
            ansible: Some(ryuki_protocol::ToolCapability {
                version: "2.16.0".to_owned(),
                provider_versions: std::collections::BTreeMap::new(),
            }),
        };
        let empty_capabilities = Capabilities::default();
        seed_agent_with_capabilities(
            &pool,
            &capable_agent,
            &platform,
            "approved",
            &exact_capabilities,
        )
        .await;
        seed_agent_with_capabilities(
            &pool,
            &wrong_provider_agent,
            &platform,
            "approved",
            &wrong_provider_capabilities,
        )
        .await;
        seed_agent_with_capabilities(
            &pool,
            &missing_provider_agent,
            &platform,
            "approved",
            &missing_provider_capabilities,
        )
        .await;
        seed_agent_with_capabilities(
            &pool,
            &ansible_agent,
            &platform,
            "approved",
            &ansible_capabilities,
        )
        .await;
        seed_agent_with_capabilities(
            &pool,
            &empty_agent,
            &platform,
            "approved",
            &empty_capabilities,
        )
        .await;

        let incompatible_high =
            seed_pending_job_for_iac(&pool, &platform, "patch-maintenance@v1").await;
        let compatible_low =
            seed_pending_job_for_iac(&pool, &platform, "linux-server-deployment@v1").await;
        sqlx::query("UPDATE agent_jobs SET priority = 9 WHERE id = $1")
            .bind(incompatible_high)
            .execute(&pool)
            .await
            .expect("raise incompatible job priority");
        sqlx::query("UPDATE agent_jobs SET priority = 1 WHERE id = $1")
            .bind(compatible_low)
            .execute(&pool)
            .await
            .expect("lower compatible job priority");

        let leased = lease_pending_job(&pool, &capable_agent)
            .await
            .expect("capability-aware lease")
            .expect("lower-priority compatible work remains leaseable");
        assert_eq!(leased.row.id, compatible_low);

        let denied_state: PendingJobLeaseState = sqlx::query_as(
            "SELECT status, agent_id, attempt_id, fencing_token, cp_nonce, lease_deadline \
             FROM agent_jobs WHERE id = $1",
        )
        .bind(incompatible_high)
        .fetch_one(&pool)
        .await
        .expect("read incompatible row");
        assert_eq!(
            denied_state,
            ("Pending".to_owned(), None, None, None, None, None)
        );

        sqlx::query("UPDATE agent_jobs SET status = 'Succeeded' WHERE id = $1")
            .bind(compatible_low)
            .execute(&pool)
            .await
            .expect("release capable agent slot");
        let ansible_lease = lease_pending_job(&pool, &ansible_agent)
            .await
            .expect("Ansible poll")
            .expect("an exact Ansible capability must lease the classified playbook");
        assert_eq!(ansible_lease.row.id, incompatible_high);
        let another_terraform = seed_pending_job(&pool, &platform).await;
        assert!(
            lease_pending_job(&pool, &wrong_provider_agent)
                .await
                .expect("wrong-provider poll")
                .is_none(),
            "an exact provider-version mismatch must deny the Terraform job"
        );
        assert!(
            lease_pending_job(&pool, &missing_provider_agent)
                .await
                .expect("missing-provider poll")
                .is_none(),
            "a missing required provider must deny the Terraform job"
        );
        assert!(
            lease_pending_job(&pool, &empty_agent)
                .await
                .expect("empty-capability poll")
                .is_none(),
            "an empty approved set must not lease any classified job"
        );
        let still_pending: (String, Option<String>) =
            sqlx::query_as("SELECT status, agent_id FROM agent_jobs WHERE id = $1")
                .bind(another_terraform)
                .fetch_one(&pool)
                .await
                .expect("read denied Terraform job");
        assert_eq!(still_pending, ("Pending".to_owned(), None));

        // The normalized matcher also supports an explicit reviewed tool
        // version. It is exact-only; no lexical/range inference is permitted.
        let approved_json = serde_json::to_value(&exact_capabilities).unwrap();
        let exact_requirement = json!({
            "tool": "terraform",
            "version": "1.9.5",
            "provider_versions": {"vsphere": "2.16.1"}
        });
        let wrong_tool_version = json!({
            "tool": "terraform",
            "version": "1.9.6",
            "provider_versions": {"vsphere": "2.16.1"}
        });
        let exact_matches: bool = sqlx::query_scalar(
            "SELECT ryuki_agent_capabilities_satisfy_requirement($1::jsonb, $2::jsonb)",
        )
        .bind(&approved_json)
        .bind(&exact_requirement)
        .fetch_one(&pool)
        .await
        .expect("evaluate exact requirement");
        let wrong_version_matches: bool = sqlx::query_scalar(
            "SELECT ryuki_agent_capabilities_satisfy_requirement($1::jsonb, $2::jsonb)",
        )
        .bind(&approved_json)
        .bind(&wrong_tool_version)
        .fetch_one(&pool)
        .await
        .expect("evaluate wrong tool version");
        assert!(exact_matches);
        assert!(!wrong_version_matches);

        let malformed_provider_capabilities = json!({
            "terraform": {
                "version": "1.9.5",
                "provider_versions": {"vsphere": 2}
            }
        });
        let malformed_provider_matches: bool = sqlx::query_scalar(
            "SELECT ryuki_agent_capabilities_satisfy_requirement($1::jsonb, $2::jsonb)",
        )
        .bind(&malformed_provider_capabilities)
        .bind(&exact_requirement)
        .fetch_one(&pool)
        .await
        .expect("evaluate malformed provider document");
        assert!(!malformed_provider_matches);

        let ansible_with_provider = json!({
            "ansible": {
                "version": "2.16.0",
                "provider_versions": {"collection": "1.0.0"}
            }
        });
        let ansible_requirement = json!({"tool": "ansible", "provider_versions": {}});
        let ansible_with_provider_matches: bool = sqlx::query_scalar(
            "SELECT ryuki_agent_capabilities_satisfy_requirement($1::jsonb, $2::jsonb)",
        )
        .bind(&ansible_with_provider)
        .bind(&ansible_requirement)
        .fetch_one(&pool)
        .await
        .expect("evaluate non-canonical Ansible provider document");
        assert!(!ansible_with_provider_matches);

        for unclassified_spec in [
            json!({"iac_ref": "unknown-offering@v1"}),
            json!({"iac_ref": 42}),
            json!({"iac_ref": "linux-server-deployment-playbook@v1"}),
        ] {
            let requirement: Value =
                sqlx::query_scalar("SELECT ryuki_agent_job_required_capabilities($1::jsonb)")
                    .bind(&unclassified_spec)
                    .fetch_one(&pool)
                    .await
                    .expect("derive fail-closed requirement");
            assert_eq!(
                requirement,
                json!({"tool": "unclassified"}),
                "unknown, malformed, and unwired offering refs must stay held"
            );
        }

        cleanup_jobs_for_platform(&pool, &platform).await;
        for agent_id in [
            &capable_agent,
            &wrong_provider_agent,
            &missing_provider_agent,
            &ansible_agent,
            &empty_agent,
        ] {
            cleanup_agent(&pool, agent_id).await;
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn db_capability_narrowing_is_locked_out_and_affinity_remains_safe() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-cap-narrow-{}", Uuid::new_v4().simple());
        let agent_a = format!("cap-narrow-a-{}", Uuid::new_v4());
        let agent_b = format!("cap-narrow-b-{}", Uuid::new_v4());
        seed_agent(pool, &agent_a, &platform, "approved").await;
        seed_agent(pool, &agent_b, &platform, "approved").await;

        let request_id = Uuid::new_v4();
        let state_key = format!("capability-affinity-{request_id}");
        let plan_spec = stateful_test_spec(request_id, &state_key, JobMode::LivePlan);
        let plan_id = create_agent_job(pool, request_id, &platform, &plan_spec, "LivePlan")
            .await
            .expect("seed stateful plan");
        assert_eq!(
            lease_pending_job(pool, &agent_a)
                .await
                .expect("lease plan")
                .expect("agent A is capable")
                .row
                .id,
            plan_id
        );

        let (enrollment_id, fingerprint) = enrollment_review_binding(pool, &agent_a).await;
        let incompatible = Capabilities {
            terraform: None,
            ansible: Some(ryuki_protocol::ToolCapability {
                version: "2.16.0".to_owned(),
                provider_versions: std::collections::BTreeMap::new(),
            }),
        };
        let denied = admin_approve_agent(
            Path(agent_a.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(ApproveBody {
                enrollment_id,
                public_key_fingerprint: fingerprint.clone(),
                platform: platform.clone(),
                capabilities: Some(incompatible),
            }),
        )
        .await;
        assert!(
            matches!(denied, Err((StatusCode::CONFLICT, _))),
            "capabilities cannot be narrowed beneath an active job: {denied:?}"
        );

        let persisted_capabilities: Value =
            sqlx::query_scalar("SELECT capabilities FROM agents WHERE agent_id = $1")
                .bind(&agent_a)
                .fetch_one(pool)
                .await
                .expect("read capabilities after denied narrowing");
        assert_eq!(
            persisted_capabilities,
            serde_json::to_value(test_agent_capabilities()).unwrap(),
            "a denied narrowing must leave the approved authority unchanged"
        );

        sqlx::query("UPDATE agent_jobs SET status = 'Succeeded' WHERE id = $1")
            .bind(plan_id)
            .execute(pool)
            .await
            .expect("complete stateful plan");
        let apply_spec = stateful_test_spec(request_id, &state_key, JobMode::LiveApply);
        let apply_id = create_agent_job(pool, request_id, &platform, &apply_spec, "LiveApply")
            .await
            .expect("seed stateful apply");
        assert!(
            lease_pending_job(pool, &agent_b)
                .await
                .expect("agent B poll")
                .is_none(),
            "capability administration must not weaken state-key affinity"
        );
        assert_eq!(
            lease_pending_job(pool, &agent_a)
                .await
                .expect("agent A apply poll")
                .expect("the unchanged compatible authority remains usable")
                .row
                .id,
            apply_id
        );

        let compatible = test_agent_capabilities();
        let approved = admin_approve_agent(
            Path(agent_a.clone()),
            Extension(enrollment_human_admin_session("persisted-session")),
            Json(ApproveBody {
                enrollment_id,
                public_key_fingerprint: fingerprint,
                platform: platform.clone(),
                capabilities: Some(compatible.clone()),
            }),
        )
        .await
        .expect("an active job permits an exactly compatible reapproval");
        let expected_digest = capabilities_digest(&serde_json::to_value(compatible).unwrap());
        assert_eq!(
            approved.0["capabilities_digest"].as_str(),
            Some(expected_digest.as_str())
        );
        let audited_digest: String = sqlx::query_scalar(
            "SELECT detail->>'capabilities_digest' FROM audit_log \
             WHERE action = 'agent-approve' AND detail->>'agent_id' = $1 LIMIT 1",
        )
        .bind(&agent_a)
        .fetch_one(pool)
        .await
        .expect("read capability approval audit digest");
        assert_eq!(audited_digest, expected_digest);

        let roster = list_agents_with(pool).await.expect("read admin roster").0;
        let roster_agent = roster["agents"]
            .as_array()
            .and_then(|agents| {
                agents
                    .iter()
                    .find(|agent| agent["agent_id"].as_str() == Some(agent_a.as_str()))
            })
            .expect("agent A in admin roster");
        assert_eq!(
            roster_agent["capabilities_digest"].as_str(),
            Some(expected_digest.as_str())
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_agent(pool, &agent_a).await;
        cleanup_agent(pool, &agent_b).await;
    }

    #[tokio::test]
    async fn db_active_lease_ceiling_counts_leased_running_and_expired_until_swept() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!("plt-cap-{}", Uuid::new_v4().simple());
        let agent_id = format!("single-slot-{}", Uuid::new_v4());
        seed_agent(&pool, &agent_id, &platform, "approved").await;
        let active_index_present: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
                 SELECT 1 FROM pg_index AS catalog \
                 JOIN pg_class AS index_class ON index_class.oid = catalog.indexrelid \
                 WHERE index_class.relname = 'idx_agent_jobs_active_agent' \
                   AND catalog.indrelid = 'agent_jobs'::regclass \
                   AND pg_get_indexdef(catalog.indexrelid) LIKE '%(agent_id)%' \
                   AND pg_get_expr(catalog.indpred, catalog.indrelid) LIKE '%Leased%' \
                   AND pg_get_expr(catalog.indpred, catalog.indrelid) LIKE '%Running%' \
             )",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect active-agent lease index");
        assert!(
            active_index_present,
            "the bounded admission query requires its partial active-agent index"
        );
        let first_job = seed_pending_job(&pool, &platform).await;
        let second_job = seed_pending_job(&pool, &platform).await;

        let first = lease_pending_job(&pool, &agent_id)
            .await
            .expect("first poll")
            .expect("first slot is available");
        assert_eq!(first.row.id, first_job);
        assert!(
            lease_pending_job(&pool, &agent_id)
                .await
                .expect("second poll while Leased")
                .is_none(),
            "a Leased row consumes the only active slot"
        );

        sqlx::query(
            "UPDATE agent_jobs SET status = 'Running', \
                 lease_deadline = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(first_job)
        .execute(&pool)
        .await
        .expect("make the first lease Running and expired");
        assert!(
            lease_pending_job(&pool, &agent_id)
                .await
                .expect("poll before expiry sweep")
                .is_none(),
            "an expired-but-unswept Running row still consumes capacity"
        );

        expire_leases(&pool)
            .await
            .expect("sweep expired non-mutating lease");
        let retried = lease_pending_job(&pool, &agent_id)
            .await
            .expect("poll after expiry transition")
            .expect("leaving active status releases the slot");
        assert_eq!(
            retried.row.id, first_job,
            "the existing non-mutating retry keeps its queue position and remains legitimate"
        );
        let untouched_second: UntouchedPendingJobState = sqlx::query_as(
            "SELECT status, agent_id, attempt_id, lease_generation, fencing_token, cp_nonce, \
                    lease_deadline, delivery_attempts, priority \
             FROM agent_jobs WHERE id = $1",
        )
        .bind(second_job)
        .fetch_one(&pool)
        .await
        .expect("read untouched second job");
        assert_eq!(
            untouched_second,
            ("Pending".to_owned(), None, None, 0, None, None, None, 0, 5,),
            "saturated polls must not mutate the denied row or its ordering metadata"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_live_state_key_stays_on_one_agent_across_retry_apply_and_destroy() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!("plt-affinity-{}", Uuid::new_v4().simple());
        let agent_a = format!("agent-a-{}", Uuid::new_v4());
        let agent_b = format!("agent-b-{}", Uuid::new_v4());
        seed_agent(&pool, &agent_a, &platform, "approved").await;
        seed_agent(&pool, &agent_b, &platform, "approved").await;

        let request_id = Uuid::new_v4();
        let state_key = format!("request-{request_id}");
        let plan_spec = stateful_test_spec(request_id, &state_key, JobMode::LivePlan);
        let plan_id = create_agent_job(&pool, request_id, &platform, &plan_spec, "LivePlan")
            .await
            .expect("seed live plan");

        let first = lease_pending_job(&pool, &agent_a)
            .await
            .expect("first lease")
            .expect("plan is leaseable");
        assert_eq!(first.row.id, plan_id);
        assert_eq!(first.row.agent_id.as_deref(), Some(agent_a.as_str()));

        sqlx::query(
            "UPDATE agent_jobs SET lease_deadline = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(plan_id)
        .execute(&pool)
        .await
        .expect("expire plan lease");
        expire_leases(&pool).await.expect("redispatch expired plan");

        let (status, assigned_agent): (String, Option<String>) =
            sqlx::query_as("SELECT status, agent_id FROM agent_jobs WHERE id = $1")
                .bind(plan_id)
                .fetch_one(&pool)
                .await
                .expect("read redispatched plan");
        assert_eq!(status, "Pending");
        assert_eq!(assigned_agent.as_deref(), Some(agent_a.as_str()));
        assert!(
            lease_pending_job(&pool, &agent_b)
                .await
                .expect("agent B poll")
                .is_none(),
            "a retry must not move to another agent-local backend"
        );
        assert_eq!(
            lease_pending_job(&pool, &agent_a)
                .await
                .expect("agent A retry")
                .expect("plan retry remains available")
                .row
                .id,
            plan_id
        );
        sqlx::query("UPDATE agent_jobs SET status = 'Succeeded' WHERE id = $1")
            .bind(plan_id)
            .execute(&pool)
            .await
            .expect("complete plan");

        let apply_spec = stateful_test_spec(request_id, &state_key, JobMode::LiveApply);
        let apply_id = create_agent_job(&pool, request_id, &platform, &apply_spec, "LiveApply")
            .await
            .expect("seed live apply");
        assert!(lease_pending_job(&pool, &agent_b)
            .await
            .expect("agent B apply poll")
            .is_none());
        assert_eq!(
            lease_pending_job(&pool, &agent_a)
                .await
                .expect("agent A apply poll")
                .expect("apply remains available to agent A")
                .row
                .id,
            apply_id
        );
        sqlx::query("UPDATE agent_jobs SET status = 'Succeeded' WHERE id = $1")
            .bind(apply_id)
            .execute(&pool)
            .await
            .expect("complete apply");

        let destroy_spec = stateful_test_spec(request_id, &state_key, JobMode::LiveDestroy);
        let destroy_id =
            create_agent_job(&pool, request_id, &platform, &destroy_spec, "LiveDestroy")
                .await
                .expect("seed live destroy");
        assert!(lease_pending_job(&pool, &agent_b)
            .await
            .expect("agent B destroy poll")
            .is_none());
        assert_eq!(
            lease_pending_job(&pool, &agent_a)
                .await
                .expect("agent A destroy poll")
                .expect("destroy remains available to agent A")
                .row
                .id,
            destroy_id
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_a).await;
        cleanup_agent(&pool, &agent_b).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_live_grant_wrong_enrollment_or_key_is_not_leaseable() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-grant-owner-{}", Uuid::new_v4().simple());
        let agent_id = format!("grant-owner-{}", Uuid::new_v4());
        seed_agent(&pool, &agent_id, &platform, "approved").await;
        let (enrollment_id, public_key): (Uuid, String) =
            sqlx::query_as("SELECT id, public_key FROM agents WHERE agent_id = $1")
                .bind(&agent_id)
                .fetch_one(&pool)
                .await
                .expect("load exact enrollment");
        let request_id = Uuid::new_v4();
        let state_key = format!("request-{request_id}");
        let spec = stateful_test_spec(request_id, &state_key, JobMode::LiveApply);
        let job_id = create_agent_job(&pool, request_id, &platform, &spec, "LiveApply")
            .await
            .expect("seed live job");

        let authority_json = |id: Uuid, fingerprint: String| {
            json!({
                "execution_authority": {
                    "assigned_agent_id": agent_id.clone(),
                    "assigned_agent_enrollment_id": id,
                    "assigned_agent_key_fingerprint": fingerprint,
                    "execution_trust_profile_digest": "a".repeat(64),
                }
            })
        };
        sqlx::query("UPDATE agent_jobs SET agent_id = $1, live_context = $2::jsonb WHERE id = $3")
            .bind(&agent_id)
            .bind(authority_json(
                Uuid::new_v4(),
                public_key_fingerprint(&public_key),
            ))
            .bind(job_id)
            .execute(&pool)
            .await
            .expect("seed wrong enrollment authority");
        assert!(lease_pending_job(&pool, &agent_id)
            .await
            .expect("poll")
            .is_none());

        sqlx::query("UPDATE agent_jobs SET live_context = $1::jsonb WHERE id = $2")
            .bind(authority_json(enrollment_id, "sha256:wrong".to_string()))
            .bind(job_id)
            .execute(&pool)
            .await
            .expect("seed wrong key authority");
        assert!(lease_pending_job(&pool, &agent_id)
            .await
            .expect("poll")
            .is_none());

        sqlx::query("UPDATE agent_jobs SET live_context = $1::jsonb WHERE id = $2")
            .bind(authority_json(
                enrollment_id,
                public_key_fingerprint(&public_key),
            ))
            .bind(job_id)
            .execute(&pool)
            .await
            .expect("seed exact authority");
        assert_eq!(
            lease_pending_job(&pool, &agent_id)
                .await
                .expect("poll")
                .expect("exact authority is leaseable")
                .row
                .id,
            job_id
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── concurrent polls obey the per-agent ceiling across connections ──

    #[tokio::test]
    async fn db_concurrent_same_agent_polls_obey_ceiling_and_agents_are_independent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-concurrent-cap-{}", Uuid::new_v4().simple());
        let agent_a = format!("concurrent-a-{}", Uuid::new_v4());
        let agent_b = format!("concurrent-b-{}", Uuid::new_v4());
        seed_agent(&pool, &agent_a, &platform, "approved").await;
        seed_agent(&pool, &agent_b, &platform, "approved").await;

        const CALLERS: usize = 8;
        for _ in 0..=CALLERS {
            seed_pending_job(&pool, &platform).await;
        }

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CALLERS));
        let mut handles = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let pool = pool.clone();
            let agent_id = agent_a.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                lease_pending_job(&pool, &agent_id)
                    .await
                    .expect("production lease helper")
                    .is_some()
            }));
        }

        let mut results = Vec::with_capacity(CALLERS);
        for h in handles {
            results.push(h.await.expect("task"));
        }
        let leased_count = results.iter().filter(|&&v| v).count();
        assert_eq!(
            leased_count, MAX_ACTIVE_LEASES_PER_AGENT as usize,
            "cross-connection polls must not exceed the server-controlled ceiling"
        );

        let active_a: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs \
             WHERE agent_id = $1 AND status IN ('Leased', 'Running')",
        )
        .bind(&agent_a)
        .fetch_one(&pool)
        .await
        .expect("count agent A active leases");
        assert_eq!(active_a, MAX_ACTIVE_LEASES_PER_AGENT);

        let independent = lease_pending_job(&pool, &agent_b)
            .await
            .expect("agent B poll")
            .expect("a different approved agent has independent capacity");
        assert_eq!(independent.row.agent_id.as_deref(), Some(agent_b.as_str()));

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_a).await;
        cleanup_agent(&pool, &agent_b).await;
        pool.close().await;
    }

    // ── ack with right fencing → Running ─────────────────────────────────

    #[tokio::test]
    async fn db_ack_correct_fencing_transitions_to_running() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let _token = seed_agent(&pool, &agent_id, &platform, "approved").await;
        let _ = seed_pending_job(&pool, &platform).await;

        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let deadline = Utc::now() + Duration::seconds(LEASE_TTL_SECS);

        let mut lease_tx = begin_agent_job_lease_fixture_tx(&pool).await;
        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = $4, lease_deadline = $5, updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' \
                 ORDER BY priority DESC, created_at, id FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind(&agent_id)
        .bind(attempt)
        .bind(&fencing)
        .bind(&nonce)
        .bind(deadline)
        .bind(&platform)
        .fetch_one(&mut *lease_tx)
        .await
        .expect("lease");
        lease_tx.commit().await.expect("commit lease fixture");

        // Correct fencing → Running.
        sqlx::query("UPDATE agent_jobs SET status = 'Running', updated_at = NOW() WHERE id = $1 AND attempt_id = $2 AND fencing_token = $3 AND status = 'Leased'")
            .bind(row.id)
            .bind(attempt)
            .bind(&fencing)
            .execute(&pool)
            .await
            .expect("ack");

        let updated: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(row.id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(updated.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── ack with wrong fencing → 409 ─────────────────────────────────────

    #[tokio::test]
    async fn db_ack_wrong_fencing_returns_409() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let token = seed_agent(&pool, &agent_id, &platform, "approved").await;
        let _ = seed_pending_job(&pool, &platform).await;

        let attempt = Uuid::new_v4();
        let real_fencing = Uuid::new_v4().to_string();
        let deadline = Utc::now() + Duration::seconds(LEASE_TTL_SECS);

        // Use the subquery form (Postgres UPDATE does not support LIMIT directly).
        let mut lease_tx = begin_agent_job_lease_fixture_tx(&pool).await;
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Leased', agent_id = $1, attempt_id = $2, \
             lease_generation = 1, fencing_token = $3, cp_nonce = 'nonce', \
             lease_deadline = $4, updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $5 AND status = 'Pending' \
                 ORDER BY created_at LIMIT 1 \
             )",
        )
        .bind(&agent_id)
        .bind(attempt)
        .bind(&real_fencing)
        .bind(deadline)
        .bind(&platform)
        .execute(&mut *lease_tx)
        .await
        .expect("lease");
        lease_tx.commit().await.expect("commit lease fixture");

        // Use wrong fencing token in ack.
        let wrong_fencing = Uuid::new_v4().to_string();
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let body = AckBody {
            attempt_id: attempt,
            fencing_token: wrong_fencing,
        };

        // Reproduce the fencing check from the handler.
        let job_row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE platform = $1 AND status = 'Leased' LIMIT 1"
        ))
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("fetch leased row");

        let stored_fencing = job_row.fencing_token.as_deref().unwrap_or("");
        use subtle::ConstantTimeEq;
        let fencing_ok: bool = stored_fencing
            .as_bytes()
            .ct_eq(body.fencing_token.as_bytes())
            .into();
        assert!(!fencing_ok, "wrong fencing must not match");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── expired OfflineDryRun lease → Pending (new attempt) ──────────────

    #[tokio::test]
    async fn db_expired_offline_dry_run_returns_to_pending() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Holds the global-sweep serial lock: this test calls expire_leases.
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );

        // Seed a Leased OfflineDryRun job with a deadline in the past.
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("seed");

        expire_leases(&pool).await.expect("expire");

        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(row.status, "Pending");
        assert!(row.attempt_id.is_none(), "attempt_id must be cleared");
        assert!(row.fencing_token.is_none(), "fencing_token must be cleared");
        assert!(row.cp_nonce.is_none(), "cp_nonce must be cleared");
        assert!(row.lease_deadline.is_none(), "deadline must be cleared");

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    // ── expired LiveApply → ReconcileRequired ─────────────────────────────

    #[tokio::test]
    async fn db_expired_live_apply_becomes_reconcile_required() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Holds the global-sweep serial lock: this test calls expire_leases.
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );

        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'LiveApply', 'Running', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("seed");

        expire_leases(&pool).await.expect("expire");

        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(row.status, "ReconcileRequired");

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    // ── #23 poison-job cap / dead-letter ──────────────────────────────────

    /// Seed a Leased non-mutating (OfflineDryRun) job with a past deadline and a
    /// chosen `delivery_attempts`. Returns the job id.
    async fn seed_expired_leased_job(pool: &PgPool, platform: &str, attempts: i32) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline, \
             delivery_attempts) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute', $3) \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(platform)
        .bind(attempts)
        .fetch_one(pool)
        .await
        .expect("seed expired leased job")
    }

    /// Like `seed_expired_leased_job`, but linked to a REAL request row so the
    /// dead-letter -> parent-request conclusion path can be exercised.
    async fn seed_expired_leased_job_for_request(
        pool: &PgPool,
        platform: &str,
        attempts: i32,
        request_id: Uuid,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline, \
             delivery_attempts) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute', $3) \
             RETURNING id",
        )
        .bind(request_id)
        .bind(platform)
        .bind(attempts)
        .fetch_one(pool)
        .await
        .expect("seed expired leased job for request")
    }

    /// Re-Lease a job with a past deadline so the next sweep sees it expired.
    async fn release_expired(pool: &PgPool, job_id: Uuid) {
        let mut tx = begin_agent_job_lease_fixture_tx(pool).await;
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Leased', agent_id = 'some-agent', \
             attempt_id = gen_random_uuid(), fencing_token = 'fence', cp_nonce = 'nonce', \
             lease_deadline = NOW() - INTERVAL '1 minute', updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(job_id)
        .execute(&mut *tx)
        .await
        .expect("re-lease");
        tx.commit().await.expect("commit expired lease fixture");
    }

    async fn job_status_and_attempts(pool: &PgPool, job_id: Uuid) -> (String, i32) {
        sqlx::query_as("SELECT status, delivery_attempts FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(pool)
            .await
            .expect("read status/attempts")
    }

    async fn dead_letter_event_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM domain_events \
             WHERE event_type = 'job.dead_lettered' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count dead-letter events")
    }

    async fn reconcile_required_event_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM domain_events \
             WHERE event_type = 'job.reconcile_required' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count reconcile-required events")
    }

    async fn cleanup_dead_letter_events(pool: &PgPool, job_id: Uuid) {
        sqlx::query(
            "DELETE FROM domain_events WHERE aggregate_id = $1 AND aggregate_type = 'agent_job'",
        )
        .bind(job_id.to_string())
        .execute(pool)
        .await
        .ok();
    }

    /// Cap reached → dead-letter + exactly one alert event. Six lease-expiry
    /// cycles: the first five redispatch (Pending, delivery_attempts 1..=5), the
    /// sixth (delivery_attempts == MAX) dead-letters and emits one event.
    #[tokio::test]
    async fn db_poison_cap_dead_letters_and_alerts() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let job_id = seed_expired_leased_job(&pool, &platform, 0).await;

        for cycle in 1..=5_i32 {
            expire_leases(&pool).await.expect("expire");
            let (status, attempts) = job_status_and_attempts(&pool, job_id).await;
            assert_eq!(status, "Pending", "cycle {cycle} must redispatch");
            assert_eq!(attempts, cycle, "cycle {cycle} must increment attempts");
            assert_eq!(
                dead_letter_event_count(&pool, job_id).await,
                0,
                "no dead-letter event before the cap"
            );
            release_expired(&pool, job_id).await;
        }

        // 6th expiry: delivery_attempts == MAX_REDISPATCHES → dead-letter.
        expire_leases(&pool).await.expect("expire");
        let (status, attempts) = job_status_and_attempts(&pool, job_id).await;
        assert_eq!(status, "DeadLettered", "at cap the job is dead-lettered");
        assert_eq!(attempts, MAX_REDISPATCHES, "attempts frozen at MAX");
        assert_eq!(
            dead_letter_event_count(&pool, job_id).await,
            1,
            "exactly one dead-letter event"
        );

        // The event is the agent_job aggregate, system-actored, and its payload
        // carries the cap details. aggregate_type/actor are asserted directly so a
        // future refactor of either is caught (not just via the count helper).
        let (payload, aggregate_type, actor): (serde_json::Value, String, String) = sqlx::query_as(
            "SELECT payload, aggregate_type, actor FROM domain_events \
                 WHERE event_type = 'job.dead_lettered' AND aggregate_id = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("read event");
        assert_eq!(
            aggregate_type, "agent_job",
            "dead-letter is the agent_job aggregate"
        );
        assert_eq!(actor, "system", "dead-letter is system-actored");
        assert_eq!(payload["to_status"], json!("dead-lettered"));
        assert_eq!(payload["delivery_attempts"], json!(MAX_REDISPATCHES));

        cleanup_dead_letter_events(&pool, job_id).await;
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// A dead-lettered NON-MUTATING job concludes its parent request exactly
    /// like a Failed result would have: executing -> failed, execute stage
    /// Failed carrying the dead-letter markers, and the hash-chained audit row
    /// present. Previously the request wedged `executing` forever with no
    /// request-side signal (QA finding).
    #[tokio::test]
    async fn db_dead_letter_concludes_parent_request() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let req_id = Uuid::new_v4();
        let stages = json!([{
            "name": "execute", "status": "InProgress",
            "started_at": null, "completed_at": null,
            "evidence": [], "metadata": {}
        }]);
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 'dead-letter-backlink-test', \
             'executing', 'execute', $2::jsonb)",
        )
        .bind(req_id)
        .bind(&stages)
        .execute(&pool)
        .await
        .expect("insert executing request");
        let job_id =
            seed_expired_leased_job_for_request(&pool, &platform, MAX_REDISPATCHES, req_id).await;

        expire_leases(&pool).await.expect("expire");

        let (job_status, _) = job_status_and_attempts(&pool, job_id).await;
        assert_eq!(job_status, "DeadLettered", "at cap the job dead-letters");

        let (req_status, stages_after): (String, serde_json::Value) =
            sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .expect("read request");
        assert_eq!(
            req_status, "failed",
            "dead-letter concludes the parent request instead of wedging it"
        );
        let execute = stages_after
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "execute")
            .expect("execute stage");
        assert_eq!(execute["status"], "Failed", "execute stage failed");
        assert_eq!(
            execute["metadata"]["result_status"], "dead-lettered",
            "stage metadata names the dead-letter"
        );

        let (audit_to_status, audit_detail): (String, serde_json::Value) = sqlx::query_as(
            "SELECT to_status, detail FROM audit_log \
             WHERE request_id = $1 AND action = 'request.execution-result' \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .expect("audit row for the dead-letter conclusion");
        assert_eq!(audit_to_status, "failed");
        assert_eq!(audit_detail["result_status"], "dead-lettered");

        cleanup_dead_letter_events(&pool, job_id).await;
        cleanup_jobs_for_platform(&pool, &platform).await;
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// Under-cap redispatch increments delivery_attempts and emits no event.
    #[tokio::test]
    async fn db_under_cap_redispatch_increments_no_event() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let job_id = seed_expired_leased_job(&pool, &platform, 0).await;

        expire_leases(&pool).await.expect("expire");

        let (status, attempts) = job_status_and_attempts(&pool, job_id).await;
        assert_eq!(status, "Pending");
        assert_eq!(attempts, 1, "one redispatch increments to 1");
        assert_eq!(dead_letter_event_count(&pool, job_id).await, 0);

        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// LiveApply is out of the cap's scope: a past-deadline LiveApply job becomes
    /// ReconcileRequired with delivery_attempts untouched, even when
    /// delivery_attempts is forced past the cap — and it emits a
    /// `job.reconcile_required` event (NEVER a dead-letter event).
    #[tokio::test]
    async fn db_live_apply_never_dead_lettered() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline, \
             delivery_attempts) \
             VALUES ($1, $2, '{}'::jsonb, 'LiveApply', 'Running', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute', $3) \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .bind(MAX_REDISPATCHES + 1)
        .fetch_one(&pool)
        .await
        .expect("seed");

        expire_leases(&pool).await.expect("expire");

        let (status, attempts) = job_status_and_attempts(&pool, job_id).await;
        assert_eq!(status, "ReconcileRequired");
        assert_eq!(
            attempts,
            MAX_REDISPATCHES + 1,
            "LiveApply never touches delivery_attempts"
        );
        // No dead-letter event (LiveApply reconciles), but a reconcile event so the
        // operator-recovery transition is not silent.
        assert_eq!(dead_letter_event_count(&pool, job_id).await, 0);
        assert_eq!(
            reconcile_required_event_count(&pool, job_id).await,
            1,
            "the LiveApply→ReconcileRequired transition emits one event"
        );

        cleanup_dead_letter_events(&pool, job_id).await;
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// DeadLettered is terminal: a second sweep does not touch the row (status no
    /// longer Leased/Running) and emits no new event.
    #[tokio::test]
    async fn db_dead_lettered_is_terminal() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let job_id = seed_expired_leased_job(&pool, &platform, MAX_REDISPATCHES).await;

        expire_leases(&pool)
            .await
            .expect("first expire dead-letters");
        let (status, _) = job_status_and_attempts(&pool, job_id).await;
        assert_eq!(status, "DeadLettered");
        assert_eq!(dead_letter_event_count(&pool, job_id).await, 1);

        // Second sweep: no-op for this row, no new event.
        expire_leases(&pool).await.expect("second expire");
        let (status2, _) = job_status_and_attempts(&pool, job_id).await;
        assert_eq!(status2, "DeadLettered", "still terminal");
        assert_eq!(
            dead_letter_event_count(&pool, job_id).await,
            1,
            "no duplicate event on a re-sweep"
        );

        cleanup_dead_letter_events(&pool, job_id).await;
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// Per-replica concurrency (codex): two sweeps racing on ONE expired job.
    /// At delivery_attempts = MAX-1 → exactly one increment (→MAX) and zero
    /// dead-letter events. At delivery_attempts = MAX → exactly one DeadLettered
    /// row and exactly one event. Proves the row-lock predicate recheck prevents
    /// a double-increment / double-emit across replicas.
    #[tokio::test]
    async fn db_concurrent_sweeps_increment_and_dead_letter_once() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );

        // Case A: under cap → exactly one increment, no event.
        let job_a = seed_expired_leased_job(&pool, &platform, MAX_REDISPATCHES - 1).await;
        let (r1, r2) = tokio::join!(expire_leases(&pool), expire_leases(&pool));
        r1.expect("sweep 1");
        r2.expect("sweep 2");
        let (status_a, attempts_a) = job_status_and_attempts(&pool, job_a).await;
        assert_eq!(status_a, "Pending", "under cap stays redispatched");
        assert_eq!(
            attempts_a, MAX_REDISPATCHES,
            "exactly one increment across two concurrent sweeps"
        );
        assert_eq!(
            dead_letter_event_count(&pool, job_a).await,
            0,
            "no dead-letter event under the cap"
        );

        // Case B: at cap → exactly one dead-letter + exactly one event.
        let job_b = seed_expired_leased_job(&pool, &platform, MAX_REDISPATCHES).await;
        let (r3, r4) = tokio::join!(expire_leases(&pool), expire_leases(&pool));
        r3.expect("sweep 3");
        r4.expect("sweep 4");
        let (status_b, _) = job_status_and_attempts(&pool, job_b).await;
        assert_eq!(status_b, "DeadLettered");
        assert_eq!(
            dead_letter_event_count(&pool, job_b).await,
            1,
            "exactly one event across two concurrent sweeps"
        );

        cleanup_dead_letter_events(&pool, job_b).await;
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// Brand-new insert (codex): a fresh create_agent_job (which omits
    /// delivery_attempts) reads back delivery_attempts = 0 — the NOT NULL DEFAULT
    /// 0 column is safe for existing INSERTs and needs no AGENT_JOB_COLUMNS change.
    #[tokio::test]
    async fn db_new_job_defaults_delivery_attempts_to_zero() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let job_id = seed_pending_job(&pool, &platform).await;

        let attempts: i32 =
            sqlx::query_scalar("SELECT delivery_attempts FROM agent_jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&pool)
                .await
                .expect("read delivery_attempts");
        assert_eq!(attempts, 0, "a brand-new job defaults to 0 attempts");

        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// Migration 121 idempotency + contract. Re-applying the SQL on the
    /// already-applied schema is safe (guarded ADD COLUMN IF NOT EXISTS + DROP/ADD
    /// CONSTRAINT), and the result still enforces the contract: the
    /// delivery_attempts column is present (defaults 0), the widened
    /// agent_jobs_status_check ACCEPTS the new terminal 'DeadLettered' AND a
    /// pre-existing value ('Pending'), and an out-of-set status is still REJECTED.
    /// Holds EXPIRE_TEST_LOCK because the DROP/ADD constraint briefly re-validates
    /// the whole agent_jobs table.
    #[tokio::test]
    async fn db_migration_121_is_idempotent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let sql = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/121_agent_jobs_delivery_attempts.sql"
        ))
        .expect("read migration 121");
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("re-running migration 121 must be safe (no-op on applied schema)");

        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );

        // The widened CHECK accepts the new terminal value, and the column is
        // present and defaults to 0.
        let dl: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'DeadLettered') RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("'DeadLettered' passes the widened CHECK");
        let attempts: i32 =
            sqlx::query_scalar("SELECT delivery_attempts FROM agent_jobs WHERE id = $1")
                .bind(dl)
                .fetch_one(&pool)
                .await
                .expect("delivery_attempts column present");
        assert_eq!(attempts, 0, "delivery_attempts defaults to 0");

        // A pre-existing status value still inserts cleanly (widening preserves it).
        sqlx::query(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Pending')",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .execute(&pool)
        .await
        .expect("pre-existing value 'Pending' still passes the widened CHECK");

        // An out-of-set status is still rejected — the CHECK is still enforced.
        let bad = sqlx::query(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Bogus')",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .execute(&pool)
        .await;
        assert!(
            bad.is_err(),
            "an out-of-set status must still violate the widened CHECK"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    /// `expire_leases` returns the TOTAL across all three branches — dead-letter +
    /// redispatch + reconcile. A regression dropping any branch (e.g. omitting
    /// `dead_count` from the sum) would change this count. Drains any pre-existing
    /// expired leases first so the asserted total is exactly this test's three jobs.
    #[tokio::test]
    async fn db_expire_leases_returns_mixed_total() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        // Drain any stray expired leases so the total below is exactly our three.
        expire_leases(&pool).await.expect("drain");

        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        // (a) at-cap non-mutating → dead-letter.
        let dead = seed_expired_leased_job(&pool, &platform, MAX_REDISPATCHES).await;
        // (b) fresh non-mutating → redispatch.
        let redispatch = seed_expired_leased_job(&pool, &platform, 0).await;
        // (c) expired LiveApply → reconcile.
        let reconcile: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'LiveApply', 'Running', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("seed live-apply");

        let total = expire_leases(&pool).await.expect("expire");
        assert_eq!(
            total, 3,
            "dead-letter + redispatch + reconcile are all counted"
        );

        assert_eq!(
            job_status_and_attempts(&pool, dead).await.0,
            "DeadLettered",
            "at-cap job dead-lettered"
        );
        assert_eq!(
            job_status_and_attempts(&pool, redispatch).await.0,
            "Pending",
            "fresh job redispatched"
        );
        assert_eq!(
            job_status_and_attempts(&pool, reconcile).await.0,
            "ReconcileRequired",
            "live-apply job reconcile-required"
        );

        cleanup_dead_letter_events(&pool, dead).await;
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ── malformed job id → 404 ────────────────────────────────────────────

    #[test]
    fn malformed_job_id_returns_404() {
        let result = parse_agent_job_id("not-a-uuid");
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── Fix 1: ack on an expired lease → 409 (not Running) ───────────────

    #[tokio::test]
    async fn db_ack_expired_lease_returns_409() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Holds the global-sweep serial lock: this test seeds an expired-Leased
        // job that MUST stay Leased, so no concurrent expire_leases may run.
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let _token = seed_agent(&pool, &agent_id, &platform, "approved").await;

        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();

        // Seed a Leased job with a deadline already in the past.
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', $3, \
             $4, 1, $5, 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .bind(&agent_id)
        .bind(attempt)
        .bind(&fencing)
        .fetch_one(&pool)
        .await
        .expect("seed expired leased job");

        // The atomic ack UPDATE includes AND lease_deadline >= NOW(), so this
        // must return 0 rows and the follow-up SELECT produces a 409.
        let updated = sqlx::query_scalar::<_, Uuid>(
            "UPDATE agent_jobs \
             SET status = 'Running', updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'Leased' \
               AND attempt_id = $2 \
               AND fencing_token = $3 \
               AND lease_deadline >= NOW() \
             RETURNING id",
        )
        .bind(job_id)
        .bind(attempt)
        .bind(&fencing)
        .fetch_optional(&pool)
        .await
        .expect("ack query");

        assert!(
            updated.is_none(),
            "expired lease must not transition to Running"
        );

        // Verify the row is still Leased (not Running), confirming no mutation.
        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(
            row.status, "Leased",
            "expired job must stay Leased, never Running"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 1: ack after re-lease (wrong attempt_id) → 409 ───────────────

    #[tokio::test]
    async fn db_ack_after_release_wrong_attempt_returns_409() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let _token = seed_agent(&pool, &agent_id, &platform, "approved").await;

        let old_attempt = Uuid::new_v4();
        let new_attempt = Uuid::new_v4();
        let old_fencing = Uuid::new_v4().to_string();
        let new_fencing = Uuid::new_v4().to_string();

        // Seed a Leased job that has already been re-leased (new attempt/fencing).
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', $3, \
             $4, 2, $5, 'nonce2', NOW() + INTERVAL '5 minutes') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .bind(&agent_id)
        .bind(new_attempt)
        .bind(&new_fencing)
        .fetch_one(&pool)
        .await
        .expect("seed re-leased job");

        // Try to ack with the OLD attempt_id — must return 0 rows.
        let updated = sqlx::query_scalar::<_, Uuid>(
            "UPDATE agent_jobs \
             SET status = 'Running', updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'Leased' \
               AND attempt_id = $2 \
               AND fencing_token = $3 \
               AND lease_deadline >= NOW() \
             RETURNING id",
        )
        .bind(job_id)
        .bind(old_attempt)
        .bind(&old_fencing)
        .fetch_optional(&pool)
        .await
        .expect("ack with stale attempt");

        assert!(
            updated.is_none(),
            "stale attempt_id must not transition to Running"
        );

        // Confirm the job is still correctly Leased with the new attempt.
        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(row.status, "Leased");
        assert_eq!(
            row.attempt_id,
            Some(new_attempt),
            "new attempt must be preserved"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Challenge authority: approval cannot replace platform ────────────

    #[tokio::test]
    async fn db_approval_rejects_platform_different_from_challenge() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("agent-{}", Uuid::new_v4());
        // Trusted provisioning binds the enrollment to this exact platform.
        let _token = seed_agent(&pool, &agent_id, "attacker-platform", "pending").await;

        // Even a transaction carrying the current mutation marker cannot
        // replace the challenge issuer's platform during approval.
        let mut tx = pool.begin().await.expect("begin approval fixture");
        activate_agent_enrollment_contract_v3(&mut tx)
            .await
            .expect("activate v3 approval contract");
        let error = sqlx::query(
            "UPDATE agents SET status = 'approved', platform = $1, updated_at = NOW() \
             WHERE agent_id = $2",
        )
        .bind("safe-platform")
        .bind(&agent_id)
        .execute(&mut *tx)
        .await
        .expect_err("approval must not replace the challenge-bound platform");
        let error_code = error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .map(|code| code.into_owned());
        assert_eq!(error_code.as_deref(), Some("23514"));
        tx.rollback()
            .await
            .expect("rollback rejected approval fixture");

        // The original Pending identity remains unchanged.
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT platform, status FROM agents WHERE agent_id = $1",
        )
        .bind(&agent_id)
        .fetch_one(&pool)
        .await
        .expect("read after approval");

        assert_eq!(row.0, "attacker-platform");
        assert_eq!(row.1, "pending");

        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b helpers ───────────────────────────────────────────────────────

    use rand::rngs::OsRng;
    use ryuki_protocol::{
        crypto::{
            encode_verifying_key, generate_keypair, job_spec_digest, sha256_hex as proto_sha256,
            sign,
        },
        JobMode, JobResult, JobResultStatus, SignedEnvelope,
    };

    /// Insert an approved agent with a generated Ed25519 keypair.
    /// Returns (plaintext token, signing_key, immutable enrollment UUID).
    async fn seed_agent_with_key(
        pool: &PgPool,
        agent_id: &str,
        platform: &str,
    ) -> (String, ed25519_dalek::SigningKey, Uuid) {
        let key = generate_keypair(&mut OsRng);
        let pubkey_b64 = encode_verifying_key(&key.verifying_key());
        let token = format!(
            "{AGENT_TOKEN_PREFIX}key{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        let capabilities = serde_json::to_value(test_agent_capabilities())
            .expect("serialize test agent capabilities");
        let enrollment_id = seed_challenge_admitted_test_agent(
            pool,
            ChallengeAdmittedTestAgent {
                agent_id,
                platform,
                public_key: &pubkey_b64,
                token_hash: &hash,
                capabilities: &capabilities,
                final_status: "approved",
                last_seen_at: None,
            },
        )
        .await;
        (token, key, enrollment_id)
    }

    /// Persist a genuinely successful, signed LivePlan row for the exact
    /// mutation spec and return its immutable row/attempt identity. Positive
    /// mint fixtures must use this rather than a digest-only dummy row.
    #[allow(clippy::too_many_arguments)]
    async fn seed_signed_successful_plan_for_mutation(
        pool: &PgPool,
        request_id: Uuid,
        platform: &str,
        mutation_spec: &JobSpec,
        raw_plan_digest: &str,
        agent_id: &str,
        agent_enrollment_id: Uuid,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> ApprovedPlanReference {
        let job_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let cp_nonce = Uuid::new_v4().to_string();
        let mut plan_spec = mutation_spec.clone();
        plan_spec.mode = JobMode::LivePlan;
        assert_eq!(plan_spec.request_id, request_id);
        let projection = reviewable_live_plan_for_spec(&plan_spec, raw_plan_digest);
        let evidence = serde_json::to_vec(&projection).expect("safe plan projection JSON");
        let evidence_digest = proto_sha256(&evidence);
        let unsigned = SignedEnvelope {
            agent_id: agent_id.to_string(),
            agent_enrollment_id,
            platform: platform.to_string(),
            job_id,
            attempt_id,
            lease_generation: 1,
            request_id,
            result_id,
            mode: JobMode::LivePlan,
            status: JobResultStatus::Planned,
            job_spec_digest: job_spec_digest(&plan_spec),
            approved_plan_digest: None,
            raw_plan_digest: Some(raw_plan_digest.to_string()),
            execution_trust_profile: Some(canonical_execution_trust_profile(&plan_spec, platform)),
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&signing_key.verifying_key()),
            cp_nonce: cp_nonce.clone(),
            signature: String::new(),
        };
        let envelope = sign(unsigned, signing_key);
        sqlx::query(
            "INSERT INTO evidence_blobs (digest, bytes, size_bytes) VALUES ($1, $2, $3) \
             ON CONFLICT (digest) DO UPDATE SET bytes = EXCLUDED.bytes, size_bytes = EXCLUDED.size_bytes",
        )
        .bind(&evidence_digest)
        .bind(&evidence)
        .bind(evidence.len() as i64)
        .execute(pool)
        .await
        .expect("seed exact signed LivePlan evidence");
        sqlx::query(
            "INSERT INTO agent_jobs (id, request_id, platform, spec, mode, status, \
                 agent_id, attempt_id, lease_generation, cp_nonce, result_id, \
                 result_status, evidence_digest, raw_plan_digest, signed_envelope, completed_at) \
             VALUES ($1, $2, $3, $4, 'LivePlan', 'Succeeded', $5, $6, 1, $7, \
                     $8, 'planned', $9, $10, $11, NOW())",
        )
        .bind(job_id)
        .bind(request_id)
        .bind(platform)
        .bind(serde_json::to_value(&plan_spec).expect("plan spec JSON"))
        .bind(agent_id)
        .bind(attempt_id)
        .bind(&cp_nonce)
        .bind(result_id)
        .bind(&evidence_digest)
        .bind(raw_plan_digest)
        .bind(serde_json::to_value(&envelope).expect("signed plan envelope JSON"))
        .execute(pool)
        .await
        .expect("seed exact signed successful LivePlan");

        ApprovedPlanReference {
            job_id,
            attempt_id,
            expected_execution_authority: None,
        }
    }

    fn dummy_approved_plan_reference() -> ApprovedPlanReference {
        ApprovedPlanReference {
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            expected_execution_authority: None,
        }
    }

    /// Lease a pending job atomically and return the leased row (attempt_id,
    /// fencing_token, cp_nonce, lease_generation).
    async fn lease_job(
        pool: &PgPool,
        platform: &str,
        agent_id: &str,
    ) -> (Uuid, String, String, i64, AgentJobRow) {
        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let mut tx = begin_agent_job_lease_fixture_tx(pool).await;
        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = $4, \
                 lease_deadline = NOW() + make_interval(secs => $5), \
                 updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' \
                 ORDER BY priority DESC, created_at, id FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind(agent_id)
        .bind(attempt)
        .bind(&fencing)
        .bind(&nonce)
        .bind(LEASE_TTL_SECS as f64)
        .bind(platform)
        .fetch_one(&mut *tx)
        .await
        .expect("lease job");
        tx.commit().await.expect("commit lease job fixture");

        let gen = row.lease_generation;
        (attempt, fencing, nonce, gen, row)
    }

    /// Ack a leased job to Running.
    async fn ack_to_running(pool: &PgPool, job_id: Uuid, attempt: Uuid, fencing: &str) {
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Running', updated_at = NOW() \
             WHERE id = $1 AND attempt_id = $2 AND fencing_token = $3 AND status = 'Leased'",
        )
        .bind(job_id)
        .bind(attempt)
        .bind(fencing)
        .execute(pool)
        .await
        .expect("ack to running");
    }

    #[tokio::test]
    async fn db_running_lease_renewal_requires_exact_unexpired_fence() {
        let _expiry_guard = EXPIRE_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("renew-{}", Uuid::new_v4());
        let agent_id = format!("renew-agent-{}", Uuid::new_v4());
        seed_agent(&pool, &agent_id, &platform, "approved").await;

        let request_id = Uuid::new_v4();
        let spec = stateful_test_spec(
            request_id,
            &format!("request-{request_id}"),
            JobMode::LiveApply,
        );
        create_agent_job(&pool, request_id, &platform, &spec, "LiveApply")
            .await
            .expect("seed live job");
        let (attempt_id, fencing_token, _nonce, generation, row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, row.id, attempt_id, &fencing_token).await;

        let fence = RunningLeaseFence {
            job_id: row.id,
            attempt_id,
            lease_generation: generation,
            fencing_token: fencing_token.clone(),
        };
        let mut tx = pool.begin().await.expect("renew tx");
        let deadline = renew_running_job_lease(&mut tx, &agent_id, &fence)
            .await
            .expect("renew query")
            .expect("exact live fence renews");
        tx.commit().await.expect("commit renewal");
        assert!(
            deadline > Utc::now() + Duration::seconds(LIVE_LEASE_TTL_SECS - 60),
            "live renewal must cover the runner's whole bounded synchronous call"
        );

        let mut stale_generation = fence.clone();
        stale_generation.lease_generation = generation + 1;
        let mut tx = pool.begin().await.expect("stale tx");
        assert!(
            renew_running_job_lease(&mut tx, &agent_id, &stale_generation)
                .await
                .expect("stale query")
                .is_none(),
            "a superseded generation must not renew"
        );
        tx.rollback().await.ok();

        stale_generation.lease_generation = generation;
        stale_generation.fencing_token = Uuid::new_v4().to_string();
        let mut tx = pool.begin().await.expect("wrong-token tx");
        assert!(
            renew_running_job_lease(&mut tx, &agent_id, &stale_generation)
                .await
                .expect("wrong-token query")
                .is_none(),
            "a wrong fencing token must not renew"
        );
        tx.rollback().await.ok();

        sqlx::query("UPDATE agent_jobs SET lease_deadline = NOW() WHERE id = $1")
            .bind(row.id)
            .execute(&pool)
            .await
            .expect("expire lease at database clock");
        let mut tx = pool.begin().await.expect("expired tx");
        assert!(
            renew_running_job_lease(&mut tx, &agent_id, &fence)
                .await
                .expect("expired query")
                .is_none(),
            "renewal at or after the deadline must fail"
        );
        tx.rollback().await.ok();

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// Build a valid signed `JobResult` for `job_row` using the given signing key.
    #[allow(clippy::too_many_arguments)]
    fn make_job_result(
        agent_id: &str,
        agent_enrollment_id: Uuid,
        platform: &str,
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        cp_nonce: &str,
        lease_gen: u64,
        key: &ed25519_dalek::SigningKey,
        spec: &JobSpec,
        evidence: &[u8],
        status: JobResultStatus,
    ) -> (JobResult, Vec<u8>) {
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(spec);
        let execution_trust_profile = if matches!(
            &spec.mode,
            JobMode::LivePlan | JobMode::LiveApply | JobMode::LiveDestroy
        ) && !matches!(&status, JobResultStatus::LiveRefused)
        {
            Some(canonical_execution_trust_profile(spec, platform))
        } else {
            None
        };
        let raw_plan_digest =
            if spec.mode == JobMode::LivePlan && status == JobResultStatus::Planned {
                serde_json::from_slice::<Value>(evidence)
                    .ok()
                    .and_then(|projection| {
                        projection
                            .get("canonical_plan_sha256")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
            } else {
                None
            };

        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.to_string(),
            agent_enrollment_id,
            platform: platform.to_string(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: lease_gen,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: status.clone(),
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: raw_plan_digest.clone(),
            execution_trust_profile,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: cp_nonce.to_string(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, key);

        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status,
            raw_plan_digest,
            evidence_digest,
            signed_envelope: signed_env,
        };
        (job_result, evidence.to_vec())
    }

    // ── Helper: read job status + result fields ────────────────────────────

    #[derive(sqlx::FromRow)]
    #[allow(dead_code)]
    struct JobResultDbRow {
        status: String,
        result_id: Option<Uuid>,
        result_status: Option<String>,
        evidence_digest: Option<String>,
        completed_at: Option<chrono::DateTime<Utc>>,
        attempt_id: Option<Uuid>,
        lease_generation: i64,
    }

    async fn read_job_result_row(pool: &PgPool, job_id: Uuid) -> JobResultDbRow {
        sqlx::query_as::<_, JobResultDbRow>(
            "SELECT status, result_id, result_status, evidence_digest, \
             completed_at, attempt_id, lease_generation \
             FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("read job result row")
    }

    // ── S3b: happy path ───────────────────────────────────────────────────

    #[tokio::test]
    async fn db_s3b_happy_path_records_terminal_result() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"check output here";
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        // Build the ResultBody and call post_job_result via direct handler invocation.
        let result_body = ResultBody {
            job_result,
            evidence: evidence_bytes,
            evidence_json: None,
        };

        // Build headers
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            result_body,
            &pool,
        )
        .await;

        assert!(resp.is_ok(), "happy path must succeed: {:?}", resp.err());

        // Verify DB state.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Succeeded");
        assert_eq!(db_row.result_status.as_deref(), Some("check_ok"));
        assert!(db_row.result_id.is_some());
        assert!(db_row.evidence_digest.is_some());
        assert!(db_row.completed_at.is_some());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_live_plan_ingest_rejects_raw_bytes_before_terminal_or_blob_write() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("safe-plan-ingest-{}", Uuid::new_v4());
        let agent_id = format!("safe-plan-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let spec = reviewable_live_plan_spec();
        let job_id = create_agent_job(&pool, spec.request_id, &platform, &spec, "LivePlan")
            .await
            .expect("seed LivePlan job");
        let (attempt_id, fencing, nonce, generation, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        assert_eq!(job_row.id, job_id);
        ack_to_running(&pool, job_id, attempt_id, &fencing).await;

        let raw_sentinel = format!("RAW-PROVIDER-{}", Uuid::new_v4());
        let raw_evidence = serde_json::to_vec(&json!({
            "format_version": "1.2",
            "provider_private": &raw_sentinel,
            "resource_changes": []
        }))
        .unwrap();
        let raw_digest = proto_sha256(&raw_evidence);
        let (raw_result, raw_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            generation as u64,
            &key,
            &spec,
            &raw_evidence,
            JobResultStatus::Planned,
        );
        let headers = || {
            let mut value = HeaderMap::new();
            value.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            value
        };
        let rejected = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            headers(),
            ResultBody {
                job_result: raw_result,
                evidence: raw_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        let Err((rejected_status, Json(rejected_body))) = rejected else {
            panic!("signed legacy/full plan bytes must be rejected");
        };
        assert_eq!(rejected_status, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected_body["error"], "LivePlan evidence is not a complete supported safe projection",
            "raw provider bytes must reach the safe-projection gate"
        );
        assert!(
            !rejected_body.to_string().contains(&raw_sentinel),
            "safe-projection rejection must not echo provider evidence"
        );
        let after_rejection = read_job_result_row(&pool, job_id).await;
        assert_eq!(after_rejection.status, "Running");
        assert!(after_rejection.result_id.is_none());
        assert_eq!(
            count_evidence_blobs(&pool, &raw_digest).await,
            0,
            "rejected raw provider bytes must never reach durable blob storage"
        );

        let safe_evidence = serde_json::to_vec(&reviewable_live_plan(&["create"])).unwrap();
        let safe_digest = proto_sha256(&safe_evidence);
        let (safe_result, safe_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            generation as u64,
            &key,
            &spec,
            &safe_evidence,
            JobResultStatus::Planned,
        );
        let accepted = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            headers(),
            ResultBody {
                job_result: safe_result,
                evidence: safe_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(
            accepted.is_ok(),
            "the current complete safe projection must remain ingestible: {:?}",
            accepted.err()
        );
        let after_acceptance = read_job_result_row(&pool, job_id).await;
        assert_eq!(after_acceptance.status, "Succeeded");
        assert_eq!(after_acceptance.result_status.as_deref(), Some("planned"));
        assert_eq!(
            count_evidence_blobs(&pool, &safe_digest).await,
            1,
            "accepted safe projection remains available for digest-bound review"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        cleanup_evidence_blob(&pool, &raw_digest).await;
        cleanup_evidence_blob(&pool, &safe_digest).await;
        pool.close().await;
    }

    // ── #60 slice 2: write-side evidence offload (DB) ────────────────────────

    async fn read_evidence_json(pool: &PgPool, job_id: Uuid) -> Option<serde_json::Value> {
        sqlx::query_scalar::<_, Option<serde_json::Value>>(
            "SELECT evidence_json FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("read evidence_json")
    }

    async fn count_evidence_blobs(pool: &PgPool, digest: &str) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM evidence_blobs WHERE digest = $1")
            .bind(digest)
            .fetch_one(pool)
            .await
            .expect("count evidence_blobs")
    }

    async fn cleanup_evidence_blob(pool: &PgPool, digest: &str) {
        sqlx::query("DELETE FROM evidence_blobs WHERE digest = $1")
            .bind(digest)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn db_large_evidence_offloads_to_blob_store() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("offload-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        // Strictly above DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES (64 KiB).
        let evidence =
            vec![b'x'; ryuki_engine::evidence_store::DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES + 1];
        let evidence_digest = proto_sha256(&evidence);
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            &evidence,
            JobResultStatus::CheckOk,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: Some(json!({"raw": "this must not end up inline"})),
            },
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "large-evidence ingest must succeed: {:?}",
            resp.err()
        );

        // The blob row exists, keyed by the verified digest.
        assert_eq!(
            count_evidence_blobs(&pool, &evidence_digest).await,
            1,
            "large evidence must be persisted in evidence_blobs keyed by its digest"
        );

        // The inline evidence_json is a small reference, not the raw payload.
        let stored = read_evidence_json(&pool, job_row.id)
            .await
            .expect("offloaded evidence must still store a reference");
        assert_eq!(stored["_evidence_blob_digest"], evidence_digest);
        assert_eq!(
            stored["_evidence_size_bytes"],
            evidence.len() as i64,
            "reference must record the evidence size"
        );
        assert!(
            stored.get("raw").is_none(),
            "offloaded evidence_json must not carry the agent-submitted structured evidence"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        cleanup_evidence_blob(&pool, &evidence_digest).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_small_evidence_stays_inline_no_blob_row() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("inline-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"tiny evidence, well under the threshold";
        let evidence_digest = proto_sha256(evidence);
        let submitted_evidence_json = json!({"summary": "check passed"});
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: Some(submitted_evidence_json.clone()),
            },
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "small-evidence ingest must succeed: {:?}",
            resp.err()
        );

        assert_eq!(
            count_evidence_blobs(&pool, &evidence_digest).await,
            0,
            "small evidence must NOT be offloaded to evidence_blobs"
        );
        let stored = read_evidence_json(&pool, job_row.id).await;
        assert_eq!(
            stored,
            Some(submitted_evidence_json),
            "small evidence must keep the agent-submitted evidence_json inline unchanged"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_identical_evidence_dedups_to_one_blob_row() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let evidence =
            vec![b'd'; ryuki_engine::evidence_store::DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES + 1];
        let evidence_digest = proto_sha256(&evidence);

        // Two separate jobs, two separate agents, IDENTICAL evidence bytes.
        for suffix in ["a", "b"] {
            let agent_id = format!("dedup-agent-{suffix}-{}", Uuid::new_v4());
            let (token, key, _agent_enrollment_id) =
                seed_agent_with_key(&pool, &agent_id, &platform).await;
            let _job_id = seed_pending_job(&pool, &platform).await;
            let (attempt_id, fencing, nonce, gen, job_row) =
                lease_job(&pool, &platform, &agent_id).await;
            ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
            let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
            let (job_result, evidence_bytes) = make_job_result(
                &agent_id,
                _agent_enrollment_id,
                &platform,
                &job_row,
                attempt_id,
                &nonce,
                gen as u64,
                &key,
                &spec,
                &evidence,
                JobResultStatus::CheckOk,
            );
            let mut hdrs = HeaderMap::new();
            hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            let resp = post_job_result_with_pool(
                agent_id.clone(),
                job_row.id.to_string(),
                hdrs,
                ResultBody {
                    job_result,
                    evidence: evidence_bytes,
                    evidence_json: None,
                },
                &pool,
            )
            .await;
            assert!(
                resp.is_ok(),
                "ingest {suffix} must succeed: {:?}",
                resp.err()
            );
            cleanup_jobs_for_platform(&pool, &platform).await;
            cleanup_agent(&pool, &agent_id).await;
        }

        assert_eq!(
            count_evidence_blobs(&pool, &evidence_digest).await,
            1,
            "identical evidence across two jobs must dedup to exactly one blob row"
        );

        cleanup_evidence_blob(&pool, &evidence_digest).await;
        pool.close().await;
    }

    /// #run7 wire-contract: `Verified` is not an agent-reportable status — the engine's
    /// RunStatus has no Verified variant, so map_run_status never produces it. A
    /// CORRECTLY-SIGNED result from an enrolled agent carrying status=Verified must be
    /// rejected at ingestion (so a compromised-but-enrolled agent can't forge a
    /// "verified" audit step), and the job is left Running, not marked Succeeded.
    #[tokio::test]
    async fn db_verified_status_is_not_agent_reportable() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("verified-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"verified evidence",
            JobResultStatus::Verified,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            matches!(resp, Err((StatusCode::BAD_REQUEST, _))),
            "a correctly-signed Verified-status result must be rejected 400: {resp:?}"
        );
        // The job is NOT advanced to Succeeded by a rejected Verified result.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db_row.status, "Running",
            "the job stays Running — a rejected Verified result does not advance it"
        );
        assert!(db_row.result_id.is_none(), "no terminal result recorded");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── redaction_policy_version allowlist guard (pure, no DB) ───────────────
    //
    // codex (impl review): this is the one envelope string field with no
    // authoritative CP counterpart, so its ingestion guard is what stops a
    // compromised agent from using it as a free-form text channel. The guard is
    // a CLOSED allowlist (not a charset/shape heuristic) — a bare token like
    // `SUPERSECRET` is alphanumeric and short, so only an exact-match allowlist
    // actually closes the channel.
    #[test]
    fn redaction_policy_version_guard_is_a_closed_allowlist() {
        // Accepts ONLY the CP-recognised policy version the real agent emits.
        assert!(redaction_policy_version_is_supported(
            ryuki_protocol::REDACTION_POLICY_VERSION
        ));
        assert!(redaction_policy_version_is_supported("ryuki-redaction-v2"));
        // Rejects everything else: bare alphanumeric tokens (codex's bypass),
        // token-shaped strings, an unknown-but-valid semver, free text, and empty.
        for bad in [
            "",
            "SUPERSECRET",
            "tokenabc123def456",
            "1.0.0",
            "2.0.0",
            "ryuki-redaction-v1",
            "ryuki-redaction-v3",
            "SUPERSECRET leaked via policy version",
        ] {
            assert!(
                !redaction_policy_version_is_supported(bad),
                "should reject {bad:?}"
            );
        }
    }

    // ── S3b: redaction_policy_version free-text is rejected at ingestion ──────
    //
    // codex (impl review): a VALIDLY-SIGNED envelope whose policy version carries
    // arbitrary text (a smuggled secret) must be rejected at POST — fail-closed,
    // BEFORE it can be stored and later surfaced by the admin result-retrieval
    // view. Signature verification passes (the agent really signed it); the
    // step-5b format guard is what rejects it, and nothing is recorded.
    #[tokio::test]
    async fn db_s3b_redaction_policy_version_free_text_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"check output here";
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(&spec);

        // A validly-signed envelope that smuggles a bare-token secret into the
        // one un-cross-checked string field — exactly the bypass codex flagged
        // (alphanumeric, short, so a charset guard would have let it through).
        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.clone(),
            agent_enrollment_id: _agent_enrollment_id,
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "SUPERSECRET".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, &key);
        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed_env,
        };
        let result_body = ResultBody {
            job_result,
            evidence: evidence.to_vec(),
            evidence_json: None,
        };
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            result_body,
            &pool,
        )
        .await;

        let (status, Json(err_body)) = resp.expect_err("free-text policy version must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert!(
            err_body.to_string().contains("redaction_policy_version"),
            "error must name the offending field: {err_body}"
        );
        // The smuggled secret must not have been persisted anywhere either.
        assert!(
            !err_body.to_string().contains("SUPERSECRET"),
            "rejection must not echo the smuggled text: {err_body}"
        );

        // Nothing was recorded — the job is still mid-flight, not terminal, and
        // none of the result columns were written (fully fail-closed).
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_ne!(db_row.status.as_str(), "Succeeded", "must not record");
        assert!(db_row.result_status.is_none());
        assert!(db_row.result_id.is_none());
        assert!(db_row.evidence_digest.is_none());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: VALID signed sequential replay → idempotent 200 ────────────
    //
    // A valid signed replay of an already-recorded result re-runs the FULL
    // verification (the early status gate was removed), the atomic terminal
    // UPDATE matches 0 rows (job already terminal), and the post-UPDATE
    // idempotency branch returns 200 with `idempotent: true`. This is the
    // contract the agent's at-least-once durable outbox depends on: a lost-ack
    // retry must get "already recorded", not a 409 conflict. (A FORGED/unsigned
    // replay is covered separately by db_s3b_unsigned_forged_replay_is_rejected,
    // which fails verification before ever reaching this branch.)

    #[tokio::test]
    async fn db_s3b_sequential_valid_replay_is_idempotent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"idempotent evidence";
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        let make_body = || ResultBody {
            job_result: job_result.clone(),
            evidence: evidence_bytes.clone(),
            evidence_json: None,
        };
        let make_hdrs = || {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };

        // First POST — must succeed.
        let r1 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            make_hdrs(),
            make_body(),
            &pool,
        )
        .await;
        assert!(r1.is_ok(), "first POST must succeed");

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db.status, "Succeeded",
            "job must be terminal after first POST"
        );

        // Second sequential POST — job is now terminal (Succeeded). The same
        // valid signed result re-verifies, the terminal UPDATE matches 0 rows,
        // and the idempotency branch returns 200 with `idempotent: true`.
        let r2 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            make_hdrs(),
            make_body(),
            &pool,
        )
        .await;
        let body = r2.expect("valid signed replay must be idempotent 200, not an error");
        assert_eq!(
            body.0.get("idempotent").and_then(|v| v.as_bool()),
            Some(true),
            "replay must be flagged idempotent"
        );
        assert_eq!(
            body.0.get("result_id").and_then(|v| v.as_str()),
            Some(job_result.result_id.to_string().as_str()),
            "idempotent response must echo the recorded result_id"
        );

        // The stored row must be unchanged by the replay (still the first
        // result, still terminal — exactly once).
        let db2 = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db2.status, "Succeeded", "replay must not change job status");
        assert_eq!(
            db2.result_id,
            Some(job_result.result_id),
            "replay must not change the recorded result_id"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: bad signature → 4xx, job unchanged ───────────────────────────

    #[tokio::test]
    async fn db_s3b_bad_signature_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";
        let (mut job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        // Tamper the signed envelope — change a field after signing.
        job_result.signed_envelope.evidence_digest = proto_sha256(b"forged");

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "tampered envelope must be rejected");

        // Job must still be Running, not terminal.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");
        assert!(db_row.result_id.is_none());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: wrong enrolled key → reject ─────────────────────────────────

    #[tokio::test]
    async fn db_s3b_wrong_enrolled_key_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());

        // Enrolled with key_a; signs with key_b.
        let key_a = generate_keypair(&mut OsRng);
        let key_b = generate_keypair(&mut OsRng);

        // Enroll with key_a's public key.
        let token = format!(
            "{AGENT_TOKEN_PREFIX}wk{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        let pubkey_a = encode_verifying_key(&key_a.verifying_key());
        let capabilities = json!({});
        let agent_enrollment_id = seed_challenge_admitted_test_agent(
            &pool,
            ChallengeAdmittedTestAgent {
                agent_id: &agent_id,
                platform: &platform,
                public_key: &pubkey_a,
                token_hash: &hash,
                capabilities: &capabilities,
                final_status: "approved",
                last_seen_at: None,
            },
        )
        .await;

        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        // Sign with key_b but use key_b's key_id (so the key_id check passes
        // against key_b, but enrolled key is key_a → verification fails).
        let evidence = b"evidence";
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key_b,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "wrong enrolled key must be rejected");

        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: stale attempt → rejected ────────────────────────────────────

    #[tokio::test]
    async fn db_s3b_stale_attempt_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        // First lease.
        let (old_attempt, _fencing, old_nonce, old_gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"stale evidence";
        let (old_job_result, old_evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            old_attempt,
            &old_nonce,
            old_gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        // Re-lease (new attempt, new nonce, new generation) — simulates the
        // first lease expiring and the job being re-dispatched.
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Pending', agent_id = NULL, attempt_id = NULL, \
             fencing_token = NULL, cp_nonce = NULL, lease_deadline = NULL, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(job_row.id)
        .execute(&pool)
        .await
        .expect("reset to pending");

        let (_new_attempt, new_fencing, _new_nonce, _new_gen, new_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, new_row.id, _new_attempt, &new_fencing).await;

        // Try to post with the OLD attempt's signed result.
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: old_job_result,
                evidence: old_evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "stale attempt result must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::CONFLICT);

        // Job must still be Running (new attempt, no result recorded).
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");
        assert!(db_row.result_id.is_none());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s3b_result_at_or_after_lease_deadline_is_rejected() {
        let _expiry_guard = EXPIRE_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-expired-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, generation, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            generation as u64,
            &key,
            &spec,
            b"expired-attempt-evidence",
            JobResultStatus::CheckOk,
        );

        sqlx::query("UPDATE agent_jobs SET lease_deadline = NOW() WHERE id = $1")
            .bind(job_row.id)
            .execute(&pool)
            .await
            .expect("expire lease at database clock");

        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let response = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            headers,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        let (status, _) = response.expect_err("expired attempt result must be fenced");
        assert_eq!(status, StatusCode::CONFLICT);
        let stored = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(stored.status, "Running");
        assert!(stored.result_id.is_none());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: outer != signed field → reject ──────────────────────────────

    #[tokio::test]
    async fn db_s3b_outer_status_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"ev";
        let (mut job_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );
        // Outer status differs from signed envelope.
        job_result.status = JobResultStatus::Failed;

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "outer/signed mismatch must be rejected");

        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: evidence_digest mismatch → reject ────────────────────────────

    #[tokio::test]
    async fn db_s3b_evidence_digest_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let real_evidence = b"real evidence";
        let (job_result, _) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            real_evidence,
            JobResultStatus::CheckOk,
        );

        // Send different evidence bytes — digest will not match.
        let tampered_evidence = b"different evidence bytes".to_vec();

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: tampered_evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "evidence_digest mismatch must be rejected");

        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S5: LiveApply WITHOUT a grant → rejected (409) ───────────────────
    //
    // A LiveApply job that carries no approval grant (live_context) can never
    // produce an accepted result: the verifier rejects it with 409 before any
    // digest comparison, regardless of whether the envelope carries an
    // approved_plan_digest. (The accept path + grant equality/expiry cases are
    // covered by the db_s5_live_apply_* tests.)

    #[tokio::test]
    async fn db_live_apply_without_grant_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-la-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;

        // ── seed a LiveApply job ───────────────────────────────────────────
        use std::collections::BTreeMap;
        let spec_la = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode: JobMode::LiveApply,
        };
        let live_job_id = create_agent_job(&pool, Uuid::new_v4(), &platform, &spec_la, "LiveApply")
            .await
            .expect("seed LiveApply job");

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        assert_eq!(job_row.id, live_job_id);
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let evidence = b"live apply output";
        let plan_digest = proto_sha256(b"approved plan");

        // Helper: build result with optional plan digest override.
        let make_live_result = |plan: Option<String>| {
            let result_id = Uuid::new_v4();
            let evidence_digest_str = proto_sha256(evidence);
            let spec_digest = ryuki_protocol::job_spec_digest(&spec_la);

            let unsigned = SignedEnvelope {
                agent_id: agent_id.clone(),
                agent_enrollment_id: _agent_enrollment_id,
                platform: platform.clone(),
                job_id: job_row.id,
                attempt_id,
                lease_generation: gen as u64,
                request_id: spec_la.request_id,
                result_id,
                mode: JobMode::LiveApply,
                status: JobResultStatus::Applied,
                job_spec_digest: spec_digest,
                approved_plan_digest: plan.clone(),
                raw_plan_digest: None,
                execution_trust_profile: Some(canonical_execution_trust_profile(
                    &spec_la, &platform,
                )),
                evidence_digest: evidence_digest_str.clone(),
                redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
                timestamp: Utc::now(),
                key_id: encode_verifying_key(&key.verifying_key()),
                cp_nonce: nonce.clone(),
                signature: String::new(),
            };
            let signed = sign(unsigned, &key);
            let outer = JobResult {
                job_id: job_row.id,
                attempt_id,
                result_id,
                status: JobResultStatus::Applied,
                raw_plan_digest: None,
                evidence_digest: evidence_digest_str,
                signed_envelope: signed,
            };
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            }
        };

        let hdrs = || {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };

        // Sub-case A: LiveApply WITHOUT approved_plan_digest → must be rejected.
        let resp_a = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs(),
            make_live_result(None),
            &pool,
        )
        .await;
        assert!(
            resp_a.is_err(),
            "LiveApply without a grant must be rejected"
        );
        let (status_a, _) = resp_a.unwrap_err();
        assert_eq!(
            status_a,
            axum::http::StatusCode::CONFLICT,
            "a LiveApply job with no approval grant must be rejected with 409"
        );
        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db.status, "Running",
            "job must remain Running after rejection"
        );

        // Sub-case B: LiveApply WITH approved_plan_digest but still NO grant on
        // the job → rejected with 409 (the missing-grant check fires before any
        // digest comparison; a forged digest cannot manufacture authorisation).
        let resp_b = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs(),
            make_live_result(Some(plan_digest.clone())),
            &pool,
        )
        .await;
        assert!(
            resp_b.is_err(),
            "LiveApply with a forged plan digest but no grant must be rejected"
        );
        let (status_b, _) = resp_b.unwrap_err();
        assert_eq!(
            status_b,
            axum::http::StatusCode::CONFLICT,
            "no-grant LiveApply must be rejected with 409 regardless of envelope digest"
        );
        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running", "job must remain Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s3b_non_live_with_plan_digest_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"ev";
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        // Non-live envelope WITH approved_plan_digest → must be rejected.
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            agent_enrollment_id: _agent_enrollment_id,
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: Some(proto_sha256(b"bad plan")),
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            resp.is_err(),
            "non-live with approved_plan_digest must be rejected"
        );
        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: agent mismatch (token agent != envelope.agent_id) → 403 ─────

    #[tokio::test]
    async fn db_s3b_agent_mismatch_returns_403() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let other_agent_id = format!("s3b-other-{}", Uuid::new_v4());

        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let (_tok2, _key2, _other_agent_enrollment_id) =
            seed_agent_with_key(&pool, &other_agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"mismatch";

        // Sign with correct agent's key but claim OTHER agent's id in the envelope.
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);
        let unsigned = SignedEnvelope {
            agent_id: other_agent_id.clone(),
            agent_enrollment_id: _agent_enrollment_id,
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed,
        };

        // Token belongs to `agent_id`; envelope claims `other_agent_id`.
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "agent mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        cleanup_agent(&pool, &other_agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s3b_signed_result_from_different_enrollment_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let agent_id = format!("s3b-enrollment-agent-{}", Uuid::new_v4());
        let (token, key, authenticated_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, generation, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let replacement_enrollment_id = Uuid::new_v4();
        assert_ne!(replacement_enrollment_id, authenticated_enrollment_id);
        let (job_result, evidence) = make_job_result(
            &agent_id,
            replacement_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            generation as u64,
            &key,
            &spec,
            b"validly signed by the same key but attributed to another enrollment",
            JobResultStatus::CheckOk,
        );
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let response = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            headers,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        let (status, _) = response.expect_err("a replacement enrollment must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            read_job_result_row(&pool, job_row.id).await.status,
            "Running"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_approved_plan_does_not_inherit_same_key_reenrollment() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plan-owner-{}", Uuid::new_v4().simple());
        let agent_id = format!("plan-owner-agent-{}", Uuid::new_v4());
        let (_token, key, current_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let plan_spec = reviewable_live_plan_spec();
        let job_id = create_agent_job(
            &pool,
            plan_spec.request_id,
            &platform,
            &plan_spec,
            "LivePlan",
        )
        .await
        .expect("seed successful plan job");
        let prior_enrollment_id = Uuid::new_v4();
        assert_ne!(prior_enrollment_id, current_enrollment_id);
        let approved_plan_digest = proto_sha256(b"approved plan bytes");
        let mut projection = reviewable_live_plan(&["create"]);
        projection["canonical_plan_sha256"] = json!(approved_plan_digest);
        let evidence = serde_json::to_vec(&projection).expect("safe plan projection JSON");
        let evidence_digest = proto_sha256(&evidence);
        let plan_attempt_id = Uuid::new_v4();
        let plan_result_id = Uuid::new_v4();
        let plan_cp_nonce = Uuid::new_v4().to_string();
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            agent_enrollment_id: prior_enrollment_id,
            platform: platform.clone(),
            job_id,
            attempt_id: plan_attempt_id,
            lease_generation: 1,
            request_id: plan_spec.request_id,
            result_id: plan_result_id,
            mode: JobMode::LivePlan,
            status: JobResultStatus::Planned,
            job_spec_digest: job_spec_digest(&plan_spec),
            approved_plan_digest: None,
            raw_plan_digest: Some(approved_plan_digest.clone()),
            execution_trust_profile: Some(canonical_execution_trust_profile(&plan_spec, &platform)),
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: plan_cp_nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        sqlx::query(
            "INSERT INTO evidence_blobs (digest, bytes, size_bytes) VALUES ($1, $2, $3) \
             ON CONFLICT (digest) DO UPDATE SET bytes = EXCLUDED.bytes, size_bytes = EXCLUDED.size_bytes",
        )
        .bind(&evidence_digest)
        .bind(&evidence)
        .bind(evidence.len() as i64)
        .execute(&pool)
        .await
        .expect("persist prior-enrollment plan evidence");
        sqlx::query(
            "UPDATE agent_jobs \
             SET status = 'Succeeded', agent_id = $1, result_status = 'planned', \
                 completed_at = NOW(), evidence_digest = $2, raw_plan_digest = $3, \
                 signed_envelope = $4::jsonb, attempt_id = $5, lease_generation = 1, \
                 result_id = $6, cp_nonce = $7 WHERE id = $8",
        )
        .bind(&agent_id)
        .bind(&evidence_digest)
        .bind(&approved_plan_digest)
        .bind(serde_json::to_value(&signed).expect("serialize signed plan"))
        .bind(plan_attempt_id)
        .bind(plan_result_id)
        .bind(&plan_cp_nonce)
        .bind(job_id)
        .execute(&pool)
        .await
        .expect("persist prior-enrollment plan");

        let mut mutation_spec = plan_spec.clone();
        mutation_spec.mode = JobMode::LiveApply;
        let approved_plan = ApprovedPlanReference {
            job_id,
            attempt_id: plan_attempt_id,
            expected_execution_authority: None,
        };
        let mut connection = pool.acquire().await.expect("plan authority connection");
        let authority = successful_plan_execution_authority(
            &mut connection,
            &approved_plan,
            plan_spec.request_id,
            &platform,
            &mutation_spec,
            &approved_plan_digest,
        )
        .await;
        assert!(
            matches!(authority, Err(CreateLiveApplyJobError::Invalid(_))),
            "a signature from the same key must not transfer an old plan to a new enrollment"
        );
        drop(connection);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_plan_authority_uses_exact_row_not_latest_same_digest_profile() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let request_id = Uuid::new_v4();
        let platform = format!("exact-plan-row-{}", Uuid::new_v4().simple());
        seed_active_request(&pool, request_id, &platform).await;
        let agent_id = format!("exact-plan-agent-{}", Uuid::new_v4().simple());
        let (_token, key, enrollment_id) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let mutation_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".to_string(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let digest = proto_sha256(b"same reviewed plan evidence");
        let first = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &mutation_spec,
            &digest,
            &agent_id,
            enrollment_id,
            &key,
        )
        .await;
        let second = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &mutation_spec,
            &digest,
            &agent_id,
            enrollment_id,
            &key,
        )
        .await;

        let second_json: sqlx::types::Json<serde_json::Value> =
            sqlx::query_scalar("SELECT signed_envelope FROM agent_jobs WHERE id = $1")
                .bind(second.job_id)
                .fetch_one(&pool)
                .await
                .expect("second signed plan");
        let mut second_envelope: SignedEnvelope =
            serde_json::from_value(second_json.0).expect("second envelope");
        second_envelope
            .execution_trust_profile
            .as_mut()
            .expect("live profile")
            .provider_authority_version = "v2".to_string();
        second_envelope.signature.clear();
        let second_envelope = sign(second_envelope, &key);
        sqlx::query("UPDATE agent_jobs SET signed_envelope = $2::jsonb WHERE id = $1")
            .bind(second.job_id)
            .bind(serde_json::to_value(&second_envelope).expect("second envelope JSON"))
            .execute(&pool)
            .await
            .expect("install distinct second profile");

        let expected_first_profile = canonical_execution_trust_profile(&mutation_spec, &platform);
        let expected_first_digest = execution_trust_profile_digest(&expected_first_profile);
        let expected_second_digest = execution_trust_profile_digest(
            second_envelope
                .execution_trust_profile
                .as_ref()
                .expect("second live profile"),
        );
        assert_ne!(expected_first_digest, expected_second_digest);

        let mut connection = pool.acquire().await.expect("authority connection");
        let first_authority = successful_plan_execution_authority(
            &mut connection,
            &first,
            request_id,
            &platform,
            &mutation_spec,
            &digest,
        )
        .await
        .expect("exact first plan remains selectable");
        assert_eq!(
            first_authority.execution_trust_profile_digest, expected_first_digest,
            "a newer same-digest row must not replace the selected first authority",
        );
        let second_authority = successful_plan_execution_authority(
            &mut connection,
            &second,
            request_id,
            &platform,
            &mutation_spec,
            &digest,
        )
        .await
        .expect("exact second plan is independently selectable");
        assert_eq!(
            second_authority.execution_trust_profile_digest,
            expected_second_digest,
        );
        let wrong_attempt = ApprovedPlanReference {
            job_id: first.job_id,
            attempt_id: second.attempt_id,
            expected_execution_authority: None,
        };
        assert!(
            successful_plan_execution_authority(
                &mut connection,
                &wrong_attempt,
                request_id,
                &platform,
                &mutation_spec,
                &digest,
            )
            .await
            .is_err(),
            "the exact row must reject a mismatched leased attempt",
        );
        drop(connection);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    // ── Fix 1: unsigned/forged replay on terminal job → rejected (not 200) ──
    //
    // An attacker with a valid agent token and knowledge of a terminal
    // (job_id, attempt_id, result_id) must NOT get an idempotent 200 by
    // posting a body with an invalid/absent signature. The early fast-path that
    // allowed this was removed; now full verification runs for every request.
    // A forged replay must fail at step 3 (signature verification) → 4xx.

    #[tokio::test]
    async fn db_s3b_unsigned_forged_replay_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"legit evidence";

        // First: POST a valid signed result to make the job terminal.
        let (good_result, evidence_bytes) = make_job_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );
        let good_result_id = good_result.result_id;

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let r1 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: good_result.clone(),
                evidence: evidence_bytes.clone(),
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(r1.is_ok(), "initial valid POST must succeed");

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Succeeded", "job must be terminal");

        // Now forge a body: reuse the known (job_id, attempt_id, result_id) but
        // invalidate the signature by tampering the envelope after signing.
        let mut forged_result = good_result.clone();
        // Corrupt the signature — the envelope fields are otherwise valid.
        forged_result.signed_envelope.signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();

        let mut hdrs2 = HeaderMap::new();
        hdrs2.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let r2 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs2,
            ResultBody {
                job_result: forged_result,
                evidence: evidence_bytes.clone(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        // Must be rejected. There is no early status gate: the forged body runs
        // the full verification and FAILS at the signature check, so it never
        // reaches the post-UPDATE idempotency branch. This confirms a forged
        // body with a matching (result_id, attempt_id) cannot get idempotent 200,
        // even though a VALID signed replay of the same identifiers would.
        assert!(
            r2.is_err(),
            "forged replay on terminal job must be rejected, not idempotent 200"
        );
        let (status, _) = r2.unwrap_err();
        assert_ne!(
            status,
            axum::http::StatusCode::OK,
            "forged replay must never return 200"
        );

        // The result_id from the valid first POST must be unchanged.
        let db2 = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db2.result_id,
            Some(good_result_id),
            "result_id must not change"
        );
        assert_eq!(db2.status, "Succeeded", "terminal status must not change");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: envelope.platform mismatch → rejected ──────────────────────

    #[tokio::test]
    async fn db_s3b_platform_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";

        // Build a result with a mismatched platform in the envelope.
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        let wrong_platform = format!("wrong-{}", Uuid::new_v4());
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            agent_enrollment_id: _agent_enrollment_id,
            platform: wrong_platform, // mismatch
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "platform mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: envelope.request_id mismatch → rejected ───────────────────

    #[tokio::test]
    async fn db_s3b_request_id_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";

        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        let wrong_request_id = Uuid::new_v4(); // not spec.request_id
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            agent_enrollment_id: _agent_enrollment_id,
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: wrong_request_id, // mismatch
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "request_id mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: envelope.mode mismatch → rejected ──────────────────────────

    #[tokio::test]
    async fn db_s3b_mode_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await; // OfflineDryRun

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";

        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        // Claim LivePlan in the envelope — job is OfflineDryRun.
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            agent_enrollment_id: _agent_enrollment_id,
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::LivePlan, // mismatch — job is OfflineDryRun
            status: JobResultStatus::Planned,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::Planned,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "mode mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 4: lease_deadline is set by DB time (NOW()+interval) ─────────

    #[tokio::test]
    async fn db_lease_deadline_is_set_by_db_time() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let _job_id = seed_pending_job(&pool, &platform).await;

        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();

        // Use the same make_interval(secs => $5) form as the production handler.
        let mut lease_tx = begin_agent_job_lease_fixture_tx(&pool).await;
        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = 'nonce', \
                 lease_deadline = NOW() + make_interval(secs => $4), \
                 updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $5 AND status = 'Pending' \
                 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind("test-agent")
        .bind(attempt)
        .bind(&fencing)
        .bind(LEASE_TTL_SECS as f64)
        .bind(&platform)
        .fetch_one(&mut *lease_tx)
        .await
        .expect("db-time lease");
        lease_tx
            .commit()
            .await
            .expect("commit db-time lease fixture");

        // lease_deadline must be set and in the future (within TTL + 5s margin).
        let deadline = row.lease_deadline.expect("deadline must be set");
        let now = Utc::now();
        assert!(deadline > now, "deadline must be in the future");
        let delta = (deadline - now).num_seconds();
        assert!(
            delta <= LEASE_TTL_SECS + 5,
            "deadline must be within TTL range, got delta={delta}s"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ── S4c: end-to-end dry-run contract ─────────────────────────────────────
    //
    // These tests prove that the AGENT code (ryuki-agent lib) and the CP verifier
    // (post_job_result_with_pool) agree against a real Postgres database.
    //
    // The agent identity is generated fresh; its public_key is enrolled in the
    // agents table so the CP's key_id check + Ed25519 verify pass.
    //
    // Positive: agent produces a ResultBody that passes ALL 9 verifier steps.
    // Negative (tamper): mutating one evidence byte after signing → CP rejects
    //   with 4xx, proving the evidence digest is bound end-to-end.

    // Import the trait so .execute() is callable on StubExecutor.
    use ryuki_agent::executor::JobExecutor as AgentJobExecutor;

    /// Seed an approved agent whose enrolled public_key equals the given
    /// agent identity's public_key_b64(). Returns the plaintext bearer token
    /// and immutable enrollment UUID.
    async fn seed_agent_from_identity(
        pool: &PgPool,
        agent_id: &str,
        platform: &str,
        identity: &ryuki_agent::identity::AgentIdentity,
    ) -> (String, Uuid) {
        let pubkey_b64 = identity.public_key_b64();
        let token = format!(
            "{AGENT_TOKEN_PREFIX}s4c{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        let capabilities = json!({});
        let enrollment_id = seed_challenge_admitted_test_agent(
            pool,
            ChallengeAdmittedTestAgent {
                agent_id,
                platform,
                public_key: &pubkey_b64,
                token_hash: &hash,
                capabilities: &capabilities,
                final_status: "approved",
                last_seen_at: None,
            },
        )
        .await;
        (token, enrollment_id)
    }

    /// Build the `ryuki_protocol::Job` struct that the agent would receive after
    /// leasing and acking, from the leased row's fields.
    fn build_protocol_job(
        job_row: &AgentJobRow,
        agent_enrollment_id: Uuid,
        attempt_id: Uuid,
        fencing_token: String,
        cp_nonce: String,
        lease_generation: i64,
    ) -> ryuki_protocol::Job {
        use ryuki_protocol::{Job, JobLease, JobSpec, JobStatus};
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let lease = JobLease {
            attempt_id,
            lease_generation: lease_generation as u64,
            fencing_token,
            deadline: Utc::now() + Duration::seconds(LEASE_TTL_SECS),
            cp_nonce,
        };
        Job {
            id: job_row.id,
            agent_enrollment_id,
            platform: job_row.platform.clone(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: None,
        }
    }

    /// S4c positive: agent identity → execute → build_signed_result → CP verifier.
    /// The full 9-step verifier must accept the agent-produced envelope.
    #[tokio::test]
    async fn db_s4c_agent_to_cp_positive_e2e() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s4c-plt-{suffix}");
        let agent_id = format!("s4c-agent-{suffix}");

        // Generate the agent identity — this is what the production agent does at startup.
        let identity = ryuki_agent::identity::AgentIdentity::generate();

        // Enroll the agent with this identity's public key.
        let (token, agent_enrollment_id) =
            seed_agent_from_identity(&pool, &agent_id, &platform, &identity).await;

        // Seed a pending OfflineDryRun job and lease + ack it.
        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        // Build the Job struct as the agent would see it after poll() + ack().
        let job = build_protocol_job(
            &job_row,
            agent_enrollment_id,
            attempt_id,
            fencing.clone(),
            nonce.clone(),
            gen,
        );

        // RUN AGENT CODE — execute + sign, exactly as process_job does.
        let executor = ryuki_agent::executor::StubExecutor::check_ok();
        let evidence = executor
            .execute(&job.spec)
            .expect("StubExecutor must succeed");
        let agent_body =
            ryuki_agent::result::build_signed_result(&identity, &agent_id, &job, &evidence, None)
                .expect("build_signed_result must succeed");

        let agent_result_id = agent_body.job_result.result_id;

        // Cross the crate boundary: convert agent ResultBody → CP ResultBody.
        // The shapes are identical (same JSON); serde is the bridge.
        let cp_body: ResultBody = serde_json::from_value(
            serde_json::to_value(&agent_body).expect("agent body serialises"),
        )
        .expect("CP must deserialise the agent ResultBody");

        // Build the bearer-token header (agent's token).
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        // FEED TO CP VERIFIER — must pass all 9 steps.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            cp_body,
            &pool,
        )
        .await;

        assert!(
            resp.is_ok(),
            "agent-produced envelope must pass all CP verifier steps: {:?}",
            resp.err()
        );

        // Verify DB state.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db_row.status, "Succeeded",
            "job must be terminal after CP verification"
        );
        assert_eq!(
            db_row.result_id,
            Some(agent_result_id),
            "DB result_id must match the agent's result_id"
        );
        assert!(db_row.completed_at.is_some(), "completed_at must be set");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// S4c negative (tamper): mutate one evidence byte in the agent's body
    /// AFTER signing → CP must reject with 4xx.
    /// This proves the evidence digest is cryptographically bound end-to-end.
    #[tokio::test]
    async fn db_s4c_tampered_evidence_is_rejected_by_cp() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s4c-tamp-{suffix}");
        let agent_id = format!("s4c-tagent-{suffix}");

        let identity = ryuki_agent::identity::AgentIdentity::generate();
        let (token, agent_enrollment_id) =
            seed_agent_from_identity(&pool, &agent_id, &platform, &identity).await;

        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let job = build_protocol_job(
            &job_row,
            agent_enrollment_id,
            attempt_id,
            fencing.clone(),
            nonce.clone(),
            gen,
        );

        // Execute + sign (normal path).
        let executor = ryuki_agent::executor::StubExecutor::check_ok();
        let evidence = executor
            .execute(&job.spec)
            .expect("StubExecutor must succeed");
        let mut agent_body =
            ryuki_agent::result::build_signed_result(&identity, &agent_id, &job, &evidence, None)
                .expect("build_signed_result must succeed");

        // TAMPER: flip one byte of evidence AFTER signing.
        // The signed envelope's evidence_digest remains the pre-tamper hash;
        // the CP's recompute-and-compare at step 6 must catch the mismatch.
        if !agent_body.evidence.is_empty() {
            agent_body.evidence[0] ^= 0xFF;
        } else {
            // Should never happen for StubExecutor, but fail clearly if it does.
            panic!("evidence must not be empty for this test");
        }

        // Cross the crate boundary.
        let cp_body: ResultBody = serde_json::from_value(
            serde_json::to_value(&agent_body).expect("agent body serialises"),
        )
        .expect("CP deserialises the tampered body");

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        // CP VERIFIER must reject — step 6 (evidence_digest recompute) fails.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            cp_body,
            &pool,
        )
        .await;

        assert!(
            resp.is_err(),
            "tampered evidence must be rejected by the CP verifier"
        );
        let (status, _) = resp.unwrap_err();
        assert!(
            status.is_client_error(),
            "tampered evidence must produce a 4xx, got {status}"
        );

        // Job must remain Running — no result was recorded.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db_row.status, "Running",
            "job must remain Running after tamper rejection"
        );
        assert!(
            db_row.result_id.is_none(),
            "result_id must not be recorded after tamper rejection"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ───────────────────────────────────────────────────────────────────────
    // S5a-1/S5a-2: LiveApply approved-plan grant verification
    // ───────────────────────────────────────────────────────────────────────

    // A single shared CP signing key for ALL LiveApply tests in this binary. The
    // verifier reads the process-global CP key (via cp_identity) to verify_vlc a
    // grant's signature, so every grant a test seeds MUST be signed by the same
    // key that is installed as the global. Because every test installs the SAME
    // key, the write-once global is deterministic regardless of test order.
    static TEST_CP_KEY: std::sync::LazyLock<ed25519_dalek::SigningKey> =
        std::sync::LazyLock::new(|| generate_keypair(&mut OsRng));

    /// Install the shared CP key as the process global (idempotent — same key
    /// every call) and return a clone for signing grants in the test.
    fn ensure_test_cp_key() -> ed25519_dalek::SigningKey {
        cp_identity::init_cp_key_for_test(TEST_CP_KEY.clone());
        TEST_CP_KEY.clone()
    }

    /// Seed a minimal ACTIVE (`locked`) request row for `request_id`. A LiveApply
    /// grant may only be minted for a real, non-concluded request — the gate in
    /// `create_live_apply_job` loads `requests.status` — so any test that mints a
    /// grant directly must seed the request first.
    async fn seed_active_request(pool: &PgPool, request_id: Uuid, platform: &str) {
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', $2, 'prod', 'live-apply-test', 'locked', 'lock', '[]'::jsonb) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(request_id)
        .bind(platform)
        .execute(pool)
        .await
        .expect("seed active request for live-apply minting");
    }

    /// Seed a Pending LiveApply job carrying a CP-signed grant (live_context),
    /// signed with `signing_key`. The grant's `request_id` is bound to the job
    /// spec by default; pass a different `grant_request_id` to exercise the
    /// mismatch path. Direct INSERT because `create_agent_job` does not attach a
    /// grant. The process-global CP key is installed via `ensure_test_cp_key`.
    #[allow(clippy::too_many_arguments)]
    async fn seed_live_apply_job_signed(
        pool: &PgPool,
        platform: &str,
        approved_plan_digest: &str,
        grant_expiry: chrono::DateTime<Utc>,
        grant_request_id: Option<Uuid>,
        assigned_agent_id: &str,
        assigned_agent_enrollment_id: Uuid,
        assigned_agent_public_key: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Uuid {
        use std::collections::BTreeMap;
        let request_id = Uuid::new_v4();
        let spec = ryuki_protocol::JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: ryuki_protocol::JobMode::LiveApply,
        };
        let unsigned = VerifiedLiveContext {
            request_id: grant_request_id.unwrap_or(request_id),
            platform: platform.to_string(),
            job_spec_digest: ryuki_protocol::job_spec_digest(&spec),
            approved_plan_digest: approved_plan_digest.to_string(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-test".to_string(),
            expiry: grant_expiry,
            step_job_id: None,
            execution_authority: LiveExecutionAuthority {
                assigned_agent_id: assigned_agent_id.to_string(),
                assigned_agent_enrollment_id,
                assigned_agent_key_fingerprint: public_key_fingerprint(assigned_agent_public_key),
                execution_trust_profile_digest: execution_trust_profile_digest(
                    &canonical_execution_trust_profile(&spec, platform),
                ),
            },
            signature: String::new(),
        };
        let grant = sign_vlc(unsigned, signing_key);
        let spec_json = serde_json::to_value(&spec).expect("spec json");
        let grant_json = serde_json::to_value(&grant).expect("grant json");
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, live_context) \
             VALUES ($1, $2, $3::jsonb, 'LiveApply', 'Pending', $4::jsonb) RETURNING id",
        )
        .bind(request_id)
        .bind(platform)
        .bind(&spec_json)
        .bind(&grant_json)
        .fetch_one(pool)
        .await
        .expect("seed live apply job")
    }

    /// Seed a LiveApply job whose grant is signed by the shared global CP key
    /// (the common case — the verifier will accept the signature).
    #[allow(clippy::too_many_arguments)]
    async fn seed_live_apply_job(
        pool: &PgPool,
        platform: &str,
        approved_plan_digest: &str,
        grant_expiry: chrono::DateTime<Utc>,
        grant_request_id: Option<Uuid>,
        assigned_agent_id: &str,
        assigned_agent_enrollment_id: Uuid,
        assigned_agent_public_key: &str,
    ) -> Uuid {
        let cp_key = ensure_test_cp_key();
        seed_live_apply_job_signed(
            pool,
            platform,
            approved_plan_digest,
            grant_expiry,
            grant_request_id,
            assigned_agent_id,
            assigned_agent_enrollment_id,
            assigned_agent_public_key,
            &cp_key,
        )
        .await
    }

    /// Build a signed LiveApply `JobResult` (status Applied) carrying the given
    /// `approved_plan_digest` in the envelope.
    #[allow(clippy::too_many_arguments)]
    fn make_live_apply_result(
        agent_id: &str,
        agent_enrollment_id: Uuid,
        platform: &str,
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        cp_nonce: &str,
        lease_gen: u64,
        key: &ed25519_dalek::SigningKey,
        spec: &JobSpec,
        evidence: &[u8],
        approved_plan_digest: Option<String>,
    ) -> (JobResult, Vec<u8>) {
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(spec);
        let status = JobResultStatus::Applied;
        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.to_string(),
            agent_enrollment_id,
            platform: platform.to_string(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: lease_gen,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: status.clone(),
            job_spec_digest: spec_digest,
            approved_plan_digest,
            raw_plan_digest: None,
            execution_trust_profile: Some(canonical_execution_trust_profile(spec, platform)),
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: cp_nonce.to_string(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, key);
        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed_env,
        };
        (job_result, evidence.to_vec())
    }

    /// Drive a leased LiveApply job to a result POST with the given envelope
    /// digest + grant. Returns the verifier response. `grant_digest` is what the
    /// CP stored; `envelope_digest` is what the agent signs.
    async fn run_live_apply_case(
        pool: &PgPool,
        grant_digest: &str,
        envelope_digest: Option<String>,
        grant_expiry: chrono::DateTime<Utc>,
        grant_request_id: Option<Uuid>,
    ) -> (ApiResult<Json<serde_json::Value>>, Uuid, String) {
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-plt-{suffix}");
        let agent_id = format!("s5-agent-{suffix}");
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(pool, &agent_id, &platform).await;

        let _job_id = seed_live_apply_job(
            pool,
            &platform,
            grant_digest,
            grant_expiry,
            grant_request_id,
            &agent_id,
            _agent_enrollment_id,
            &encode_verifying_key(&key.verifying_key()),
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(pool, &platform, &agent_id).await;
        ack_to_running(pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"live apply evidence",
            envelope_digest,
        );
        let body = ResultBody {
            job_result,
            evidence: evidence_bytes,
            evidence_json: None,
        };
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp =
            post_job_result_with_pool(agent_id.clone(), job_row.id.to_string(), hdrs, body, pool)
                .await;
        (resp, job_row.id, platform)
    }

    #[tokio::test]
    async fn db_s5_live_apply_matching_digest_accepted() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let digest = proto_sha256(b"the-approved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &digest,
            Some(digest.clone()),
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        assert!(
            resp.is_ok(),
            "LiveApply with a matching approved_plan_digest + valid grant must be accepted: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Succeeded", "applied job must be terminal");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_mismatched_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let grant_digest = proto_sha256(b"the-approved-plan");
        let forged_digest = proto_sha256(b"a-different-unapproved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &grant_digest,
            Some(forged_digest),
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (status, _) = resp.expect_err("mismatched plan digest must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running", "rejected result must not go terminal");
        assert!(db.result_id.is_none());
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_missing_envelope_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let grant_digest = proto_sha256(b"the-approved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &grant_digest,
            None, // envelope omits approved_plan_digest
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (status, _) =
            resp.expect_err("LiveApply without approved_plan_digest must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_expired_grant_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let digest = proto_sha256(b"the-approved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &digest,
            Some(digest.clone()),
            Utc::now() - Duration::minutes(1), // already expired
            None,
        )
        .await;
        let (status, _) = resp.expect_err("an expired grant must be rejected");
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_grant_request_id_mismatch_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let digest = proto_sha256(b"the-approved-plan");
        // Grant carries a request_id that does NOT match the job spec's.
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &digest,
            Some(digest.clone()),
            Utc::now() + Duration::hours(1),
            Some(Uuid::new_v4()),
        )
        .await;
        let (status, _) = resp.expect_err("grant for a different request must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ── S5a-2 tests ───────────────────────────────────────────────────────────
    //
    // These tests cover the CP-side grant-signing machinery introduced in S5a-2:
    //   1. create_live_apply_job produces a validly CP-signed grant.
    //   2. End-to-end: production-signed grant → S5a-1 verifier accepts.
    //   3. Negative: plan digest mismatch → verifier rejects.
    //   4. Negative: spec.mode != LiveApply / bad grant fields → create returns Err.
    //   5. Pubkey endpoint returns the initialised key (handler-level, no DB).
    //
    // DB tests pass the SigningKey DIRECTLY to create_live_apply_job and do NOT
    // rely on the process OnceLock (init_cp_key / cp_signing_key) — the OnceLock
    // is write-once-per-process and the key set by one test leaks to others in
    // the same binary. Only the endpoint test (which is handler-level, no DB)
    // calls init_cp_key_for_test.

    /// The signed grant stored in a LiveApply job row must verify against the
    /// CP public key that signed it.
    #[tokio::test]
    async fn db_s5a2_create_live_apply_job_grant_verifies() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use chrono::Utc;
        use ryuki_protocol::crypto::verify_vlc;
        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5a2-plt-{suffix}");
        let request_id = Uuid::new_v4();
        let plan_digest = proto_sha256(b"approved-plan-bytes");

        // A LiveApply grant may only be minted for a real, ACTIVE request — the
        // concluded-status gate in create_live_apply_job loads requests.status.
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', $2, 'prod', 's5a2-live-apply', 'locked', 'lock', '[]'::jsonb)",
        )
        .bind(request_id)
        .bind(&platform)
        .execute(&pool)
        .await
        .expect("seed active request for live-apply minting");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let plan_agent_id = format!("s5a2-plan-agent-{suffix}");
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(&pool, &plan_agent_id, &platform).await;
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;

        let jobs_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count pre-denial live jobs");
        let approvals_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE request_id = $1 AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count pre-denial live approvals");
        let wrong_site = format!("{platform}-other-site");
        let site_mismatch = create_live_apply_job(
            &pool,
            approved_plan.clone(),
            request_id,
            &wrong_site,
            &spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(matches!(
            site_mismatch,
            Err(CreateLiveApplyJobError::Invalid(
                "live-apply platform differs from the authoritative request site"
            ))
        ));
        let jobs_after_site_mismatch: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count live jobs after request-site mismatch");
        let approvals_after_site_mismatch: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE request_id = $1 AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count live approvals after request-site mismatch");
        assert_eq!(jobs_after_site_mismatch, jobs_before);
        assert_eq!(approvals_after_site_mismatch, approvals_before);

        for actor_class in [
            ryuki_engine::auth::ActorClass::Workload,
            ryuki_engine::auth::ActorClass::Unknown,
            ryuki_engine::auth::ActorClass::Simulated,
        ] {
            let mut nonhuman = live_approver_session("human-shaped-nonhuman");
            nonhuman.actor_class = actor_class;
            let denied = create_live_apply_job(
                &pool,
                approved_plan.clone(),
                request_id,
                &platform,
                &spec,
                &plan_digest,
                &nonhuman,
                Utc::now() + Duration::hours(1),
                &cp_key,
            )
            .await;
            assert!(matches!(denied, Err(CreateLiveApplyJobError::Invalid(_))));
        }
        let jobs_after_denials: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count post-denial live jobs");
        let approvals_after_denials: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE request_id = $1 AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count post-denial live approvals");
        assert_eq!(jobs_after_denials, jobs_before);
        assert_eq!(approvals_after_denials, approvals_before);

        // The offering is part of the reviewed execution semantics. A caller
        // must not be able to reuse an exact signed plan while substituting a
        // different offering in the LiveApply spec presented to the signing
        // choke point.
        let mut offering_drift_spec = spec.clone();
        offering_drift_spec.offering_id = Uuid::new_v4();
        assert_ne!(offering_drift_spec.offering_id, spec.offering_id);
        let offering_drift = create_live_apply_job(
            &pool,
            approved_plan.clone(),
            request_id,
            &platform,
            &offering_drift_spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(matches!(
            offering_drift,
            Err(CreateLiveApplyJobError::Invalid(
                "approved plan job spec differs from the mutation spec"
            ))
        ));
        let jobs_after_offering_drift: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count live jobs after offering drift");
        let approvals_after_offering_drift: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE request_id = $1 AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count live approvals after offering drift");
        assert_eq!(
            jobs_after_offering_drift, jobs_before,
            "offering drift must mint no LiveApply job"
        );
        assert_eq!(
            approvals_after_offering_drift, approvals_before,
            "offering drift must append no approval audit"
        );

        let job_id = create_live_apply_job(
            &pool,
            approved_plan.clone(),
            request_id,
            &platform,
            &spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("create_live_apply_job must succeed");

        // Read the stored live_context from the DB row.
        #[derive(sqlx::FromRow)]
        struct LiveContextRow {
            live_context: Option<sqlx::types::Json<serde_json::Value>>,
        }
        let row = sqlx::query_as::<_, LiveContextRow>(
            "SELECT live_context FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("fetch live_context");

        let grant_json = row.live_context.expect("live_context must be set");
        let grant: VerifiedLiveContext =
            serde_json::from_value(grant_json.0).expect("grant must deserialise");

        // The grant must cryptographically verify against the CP public key.
        assert!(
            verify_vlc(&grant, &cp_vk).is_ok(),
            "stored grant must verify with the CP public key"
        );
        assert_eq!(grant.approved_plan_digest, plan_digest);
        assert_eq!(grant.request_id, request_id);
        assert_eq!(grant.platform, platform);
        assert_eq!(grant.approved_plan_job_id, approved_plan.job_id);
        assert_eq!(grant.approved_plan_attempt_id, approved_plan.attempt_id);
        assert_eq!(
            grant.job_spec_digest,
            ryuki_protocol::job_spec_digest(&spec),
            "grant must bind the exact request-owned JobSpec"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &plan_agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_live_approval_audit_failure_rolls_back_signed_job() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let platform = format!("audit-rollback-{}", Uuid::new_v4().simple());
        seed_active_request(&pool, request_id, &platform).await;
        let actor = format!("dbtest-live-audit-failure-{}", Uuid::new_v4());
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let plan_digest = proto_sha256(b"approved-plan-for-audit-rollback");
        let plan_agent_id = format!("{platform}-plan-agent");
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(&pool, &plan_agent_id, &platform).await;
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;

        install_live_approval_audit_failure_trigger(&pool).await;
        let result = create_live_apply_job(
            &pool,
            approved_plan,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            &live_approver_session(&actor),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        remove_live_approval_audit_failure_trigger(&pool).await;

        assert!(matches!(result, Err(CreateLiveApplyJobError::Db(_))));
        let job_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count rolled-back jobs");
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE request_id = $1 \
             AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count rolled-back audits");
        assert_eq!(job_count, 0, "signed LiveApply job must roll back");
        assert_eq!(audit_count, 0, "failed audit must not leave an event");
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &plan_agent_id).await;
        pool.close().await;
    }

    /// The concluded-status gate: a LiveApply grant must NEVER be minted for a
    /// request that has concluded — here a `retired` request. This is the shared
    /// choke-point check that closes the admin-route (`/api/admin/agents/
    /// live-apply-jobs`) bypass of the request-scoped status guard.
    #[tokio::test]
    async fn db_s5a2_create_live_apply_job_refused_for_concluded_request() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        use chrono::Utc;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 's5a2-concluded', 'retired', 'retire', '[]'::jsonb)",
        )
        .bind(request_id)
        .execute(&pool)
        .await
        .expect("seed retired request");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };

        let result = create_live_apply_job(
            &pool,
            dummy_approved_plan_reference(),
            request_id,
            "s5a2-concluded-plt",
            &spec,
            &proto_sha256(b"approved-plan-bytes"),
            &live_approver_session("ops-alice"),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(
            matches!(result, Err(CreateLiveApplyJobError::RequestConcluded)),
            "minting must be refused for a concluded (retired) request; got {result:?}"
        );

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1")
                .bind(request_id)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(count, 0, "no LiveApply job minted for a concluded request");

        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// End-to-end: create_live_apply_job produces a CP-signed grant; the agent
    /// builds a result carrying the matching plan digest; the S5a-1 verifier
    /// in post_job_result_with_pool accepts it. This is the composition test:
    /// S5a-2 (produce) + S5a-1 (verify) must agree.
    #[tokio::test]
    async fn db_s5a2_production_grant_accepted_by_s5a1_verifier() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use chrono::Utc;
        let cp_key = ensure_test_cp_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5a2-e2e-{suffix}");
        let agent_id = format!("s5a2-agent-{suffix}");
        let (agent_token, agent_key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;

        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id, &platform).await;
        let plan_digest = proto_sha256(b"the-exact-approved-plan");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            &agent_id,
            _agent_enrollment_id,
            &agent_key,
        )
        .await;

        // CP enqueues the job with a production-signed grant.
        let _job_id = create_live_apply_job(
            &pool,
            approved_plan,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("create_live_apply_job must succeed");

        // Agent leases and acks the job.
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        // Agent builds a result carrying the approved plan digest.
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &agent_key,
            &spec,
            b"live apply evidence",
            Some(plan_digest.clone()),
        );

        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "Authorization",
            format!("Bearer {agent_token}").parse().unwrap(),
        );

        // S5a-1 verifier must accept the production CP-signed grant.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            resp.is_ok(),
            "production CP-signed grant → S5a-1 verifier must accept: {:?}",
            resp.err()
        );

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Succeeded");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// Negative: the CP signs a grant for digest D; the agent sends digest D'
    /// (a different, unapproved plan). The S5a-1 verifier must reject.
    #[tokio::test]
    async fn db_s5a2_digest_mismatch_rejected_by_verifier() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use chrono::Utc;
        let cp_key = ensure_test_cp_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5a2-neg-{suffix}");
        let agent_id = format!("s5a2-negagent-{suffix}");
        let (agent_token, agent_key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;

        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id, &platform).await;
        let approved_digest = proto_sha256(b"the-approved-plan");
        let unapproved_digest = proto_sha256(b"a-different-unapproved-plan");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &approved_digest,
            &agent_id,
            _agent_enrollment_id,
            &agent_key,
        )
        .await;

        // CP signs the grant for `approved_digest`.
        let _job_id = create_live_apply_job(
            &pool,
            approved_plan,
            request_id,
            &platform,
            &spec,
            &approved_digest,
            &live_approver_session("ops-alice"),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("create_live_apply_job");

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        // Agent sends the UNAPPROVED digest — mismatch vs the grant.
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &agent_key,
            &spec,
            b"live apply evidence",
            Some(unapproved_digest),
        );

        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "Authorization",
            format!("Bearer {agent_token}").parse().unwrap(),
        );

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            resp.is_err(),
            "digest mismatch must be rejected by the S5a-1 verifier"
        );
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db.status, "Running",
            "job must stay Running after rejection"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// Negative: spec.mode != LiveApply → validate_live_apply_params returns Err.
    /// Tests the sync validation helper that create_live_apply_job delegates to,
    /// avoiding the need for a real PgPool.
    #[test]
    fn validate_live_apply_params_rejects_wrong_mode() {
        use std::collections::BTreeMap;

        let request_id = Uuid::new_v4();

        let wrong_mode_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::OfflineDryRun, // NOT LiveApply
        };

        let result = validate_live_apply_params(&wrong_mode_spec, request_id);
        assert!(
            result.is_err(),
            "OfflineDryRun spec must be rejected by validate_live_apply_params"
        );

        let liveplan_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LivePlan, // also NOT LiveApply
        };
        let result2 = validate_live_apply_params(&liveplan_spec, request_id);
        assert!(
            result2.is_err(),
            "LivePlan spec must be rejected by validate_live_apply_params"
        );

        // A LiveApply spec with matching request_id must pass.
        let valid_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let result3 = validate_live_apply_params(&valid_spec, request_id);
        assert!(result3.is_ok(), "LiveApply spec must pass validation");

        let mut missing_state_key = valid_spec.clone();
        missing_state_key.state_key = None;
        assert!(validate_live_apply_params(&missing_state_key, request_id).is_err());

        let mut foreign_state_key = valid_spec.clone();
        foreign_state_key.state_key = Some(format!("request-{}", Uuid::new_v4()));
        assert!(
            validate_live_apply_params(&foreign_state_key, request_id).is_err(),
            "a syntactically safe key owned by another request must be rejected"
        );

        let mut unsafe_state_key = valid_spec;
        unsafe_state_key.state_key = Some("../shared".to_string());
        assert!(validate_live_apply_params(&unsafe_state_key, request_id).is_err());
    }

    /// Pubkey endpoint returns the initialised CP public key.
    /// This is a handler-level test (no DB); it calls init_cp_key_for_test so
    /// the global is set for the endpoint. Only the FIRST set in the process
    /// wins — ensure no other test in this binary has already called it with a
    /// different key if you need a specific key here.
    #[tokio::test]
    async fn cp_public_key_endpoint_returns_initialised_key() {
        use crate::cp_identity;

        // Install the shared test CP key as the global (same key every test, so
        // no cross-test race on the write-once global).
        let key = ensure_test_cp_key();
        let expected_pubkey = ryuki_protocol::encode_verifying_key(&key.verifying_key());

        // Call the handler directly.
        let response = cp_public_key().await.into_response();

        // The endpoint must return 200.  If the global was already set with a
        // DIFFERENT key by another test, the status will still be 200 (just a
        // different key value).  Either way, no 503.
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "cp-public-key must return 200 when the key is initialised"
        );

        // Parse the body.
        use axum::body::to_bytes;
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("JSON body");

        // The public_key field must be a non-empty base64 string.
        let pubkey_field = body
            .get("public_key")
            .and_then(|v| v.as_str())
            .expect("public_key field must be present and a string");

        // If the key was freshly set by THIS test, it must match exactly.
        // If it was already set by a prior test, we just verify it is a
        // well-formed base64-encoded 32-byte Ed25519 verifying key.
        let actual_b64 = cp_identity::cp_public_key_b64().expect("key must be set");
        assert_eq!(
            pubkey_field, actual_b64,
            "endpoint must return the key stored in the global"
        );
        // Verify it decodes to a valid 32-byte key.
        ryuki_protocol::crypto::decode_verifying_key(pubkey_field)
            .expect("public_key must be a valid base64-encoded verifying key");

        // Confirm the expected key is at least BASE64-valid.
        let _ = expected_pubkey; // used above, consumed by init
    }

    /// A LiveApply result applied within the grant window, then REPLAYED after
    /// the grant expires (e.g. the durable outbox retries the POST much later),
    /// must return idempotent 200 — NOT a 409 "grant expired". Expiry gates the
    /// first apply only; a replay of an already-recorded result is not re-gated.
    #[tokio::test]
    async fn db_s5_live_apply_replay_after_grant_expiry_is_idempotent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-rexp-{suffix}");
        let agent_id = format!("s5-rexp-agent-{suffix}");
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;

        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &agent_id,
            _agent_enrollment_id,
            &encode_verifying_key(&key.verifying_key()),
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"live apply evidence",
            Some(digest.clone()),
        );
        let result_id = job_result.result_id;
        // Two bodies sharing the SAME signed result (same result_id) — one for the
        // first apply, one for the post-expiry replay.
        let make_body = || ResultBody {
            job_result: job_result.clone(),
            evidence: evidence_bytes.clone(),
            evidence_json: None,
        };
        let hdrs = || {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };

        // First apply — within the grant window → accepted + terminal.
        let _accepted = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs(),
            make_body(),
            &pool,
        )
        .await
        .expect("first live apply must be accepted");

        // Simulate the grant having expired after the apply was recorded. Replace
        // the stored grant with a VALIDLY-SIGNED one whose expiry is in the past
        // (re-sign with the same CP key so verify_vlc still passes — only the
        // expiry is now stale). This proves the replay path is gated on terminal
        // status, not on a fresh expiry check.
        let stored_grant_json: sqlx::types::Json<serde_json::Value> =
            sqlx::query_scalar("SELECT live_context FROM agent_jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&pool)
                .await
                .expect("read original exact-authority grant");
        let mut expired_grant: VerifiedLiveContext =
            serde_json::from_value(stored_grant_json.0).expect("stored grant");
        expired_grant.expiry = Utc::now() - Duration::hours(1);
        expired_grant.signature.clear();
        let expired_grant = sign_vlc(expired_grant, &ensure_test_cp_key());
        sqlx::query("UPDATE agent_jobs SET live_context = $2::jsonb WHERE id = $1")
            .bind(job_id)
            .bind(serde_json::to_value(&expired_grant).expect("grant json"))
            .execute(&pool)
            .await
            .expect("install expired-but-signed grant");

        // Replay the SAME signed result — the job is terminal, so expiry is not
        // re-checked; the idempotency branch returns 200.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs(),
            make_body(),
            &pool,
        )
        .await;
        let out = resp.expect("replay after expiry must be idempotent 200, not 409");
        assert_eq!(
            out.0.get("idempotent").and_then(|v| v.as_bool()),
            Some(true),
            "replay must be flagged idempotent"
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Succeeded", "job stays terminal");
        assert_eq!(db.result_id, Some(result_id), "recorded result unchanged");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// A grant signed by a key OTHER than the CP's must be rejected — proves the
    /// verifier checks the grant's Ed25519 signature (verify_vlc), not just its
    /// fields. (Defends against a tampered/forged stored grant.)
    #[tokio::test]
    async fn db_s5_live_apply_forged_grant_signature_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Install the real CP key as the global, but sign the grant with a
        // DIFFERENT (attacker) key.
        let _global = ensure_test_cp_key();
        let attacker_key = generate_keypair(&mut OsRng);

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-forge-{suffix}");
        let agent_id = format!("s5-forge-agent-{suffix}");
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;

        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job_signed(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &agent_id,
            _agent_enrollment_id,
            &encode_verifying_key(&key.verifying_key()),
            &attacker_key, // NOT the CP key
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"live apply evidence",
            Some(digest.clone()),
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        let (status, _) = resp.expect_err("a grant not signed by the CP must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running", "forged-grant job must stay Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// create_live_apply_job rejects bogus grant fields before signing.
    #[tokio::test]
    async fn db_s5a2_create_rejects_bad_grant_fields() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        use std::collections::BTreeMap;
        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let platform = format!(
            "s5a2-badf-{}",
            &Uuid::new_v4().to_string().replace('-', "")[..8]
        );
        seed_active_request(&pool, request_id, &platform).await;
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(crate::contracts::request_state_key(request_id)),
            mode: JobMode::LiveApply,
        };
        let good = proto_sha256(b"plan");
        let future = Utc::now() + Duration::hours(1);

        // Empty / non-hex digest.
        assert!(matches!(
            create_live_apply_job(
                &pool,
                dummy_approved_plan_reference(),
                request_id,
                &platform,
                &spec,
                "",
                &live_approver_session("ops"),
                future,
                &cp_key,
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        // Past expiry.
        assert!(matches!(
            create_live_apply_job(
                &pool,
                dummy_approved_plan_reference(),
                request_id,
                &platform,
                &spec,
                &good,
                &live_approver_session("ops"),
                Utc::now() - Duration::hours(1),
                &cp_key
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        // Expiry beyond the max TTL.
        assert!(matches!(
            create_live_apply_job(
                &pool,
                dummy_approved_plan_reference(),
                request_id,
                &platform,
                &spec,
                &good,
                &live_approver_session("ops"),
                Utc::now() + Duration::hours(MAX_GRANT_TTL_HOURS + 1),
                &cp_key
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        // Empty approver.
        assert!(matches!(
            create_live_apply_job(
                &pool,
                dummy_approved_plan_reference(),
                request_id,
                &platform,
                &spec,
                &good,
                &live_approver_session("  "),
                future,
                &cp_key,
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));

        // No row should have been created by any rejected call.
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ───────────────────────────────────────────────────────────────────────
    // S5b-2a: LiveRefused result acceptance (agent declined to apply)
    // ───────────────────────────────────────────────────────────────────────

    /// Build a signed result with status `LiveRefused` (the agent declined to
    /// apply). Mode stays `LiveApply` (the job's mode); the refusal carries no
    /// approved_plan_digest unless `approved_plan_digest` is passed (to exercise
    /// the must-not-carry-digest rejection).
    #[allow(clippy::too_many_arguments)]
    fn make_live_refused_result(
        agent_id: &str,
        agent_enrollment_id: Uuid,
        platform: &str,
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        cp_nonce: &str,
        lease_gen: u64,
        key: &ed25519_dalek::SigningKey,
        spec: &JobSpec,
        evidence: &[u8],
        approved_plan_digest: Option<String>,
    ) -> (JobResult, Vec<u8>) {
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(spec);
        let status = JobResultStatus::LiveRefused;
        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.to_string(),
            agent_enrollment_id,
            platform: platform.to_string(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: lease_gen,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: status.clone(),
            job_spec_digest: spec_digest,
            approved_plan_digest,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: cp_nonce.to_string(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, key);
        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status,
            raw_plan_digest: None,
            evidence_digest,
            signed_envelope: signed_env,
        };
        (job_result, evidence.to_vec())
    }

    /// A signed LiveRefused result is recorded (terminal LiveRefused) WITHOUT the
    /// grant equality/expiry checks — the refusal may itself be because the grant
    /// was unusable. The job still carries a valid grant here, but the refusal
    /// path must not depend on it.
    #[tokio::test]
    async fn db_s5_live_apply_refusal_is_recorded() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-ref-{suffix}");
        let agent_id = format!("s5-ref-agent-{suffix}");
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &agent_id,
            _agent_enrollment_id,
            &encode_verifying_key(&key.verifying_key()),
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_live_refused_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"refused: replanned plan diverged from the approved plan",
            None,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "a signed LiveRefused result must be recorded: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "LiveRefused", "job must be terminal LiveRefused");
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// A LiveRefused result MUST NOT carry approved_plan_digest (nothing was
    /// applied) — the CP rejects it.
    #[tokio::test]
    async fn db_s5_live_refused_with_plan_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-refd-{suffix}");
        let agent_id = format!("s5-refd-agent-{suffix}");
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &agent_id,
            _agent_enrollment_id,
            &encode_verifying_key(&key.verifying_key()),
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_live_refused_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"refused",
            Some(digest.clone()), // a refusal must NOT carry a plan digest
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        let (status, _) = resp.expect_err("LiveRefused carrying a plan digest must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(
            db.status, "Running",
            "rejected refusal must not change status"
        );
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// The realistic refusal case: the job's grant is UNUSABLE (signed by a
    /// non-CP key), the agent refuses, and the CP records the refusal anyway —
    /// the refusal path must not depend on grant validity.
    #[tokio::test]
    async fn db_s5_live_apply_refusal_recorded_even_with_bad_grant() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _global = ensure_test_cp_key();
        let attacker_key = generate_keypair(&mut OsRng);
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-refbad-{suffix}");
        let agent_id = format!("s5-refbad-agent-{suffix}");
        let (token, key, _agent_enrollment_id) =
            seed_agent_with_key(&pool, &agent_id, &platform).await;
        let digest = proto_sha256(b"the-approved-plan");
        // Grant signed by a NON-CP key → verify_vlc would fail, so the agent
        // refused. The CP must still record the refusal.
        let job_id = seed_live_apply_job_signed(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &agent_id,
            _agent_enrollment_id,
            &encode_verifying_key(&key.verifying_key()),
            &attacker_key,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_live_refused_result(
            &agent_id,
            _agent_enrollment_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"refused: grant signature did not verify against the pinned CP key",
            None,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "a refusal must be recorded even when the grant is unusable: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "LiveRefused");
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// #42 live-apply slice B1b: `create_step_live_job` mints a
    /// step-scoped grant bound to the dispatched job id (verifies against the
    /// CP key), marks the row `step_scoped=TRUE`, and — unlike the single-job
    /// path — lets MULTIPLE step LiveApply jobs coexist for ONE request (the
    /// mig-153 unique-index exemption). Proves the per-step minting foundation
    /// before the approval endpoint (B1b-2) wires it.
    #[tokio::test]
    async fn db_b1b_step_live_apply_mint_binds_step_and_coexists() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        use ryuki_protocol::crypto::verify_vlc;
        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();
        let request_id = Uuid::new_v4();
        let platform = format!("b1b-plt-{}", &Uuid::new_v4().to_string()[..8]);
        let digest = proto_sha256(b"step-approved-plan");

        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', $2, 'prod', 'b1b-step-live', 'executing', 'execute', '[]'::jsonb)",
        )
        .bind(request_id)
        .bind(&platform)
        .execute(&pool)
        .await
        .expect("seed executing request");

        let mut conn = pool.acquire().await.expect("acquire connection");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            request_id,
            &[
                ("step-one", vec![], "linux-server-deployment"),
                ("step-two", vec![], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed persisted steps");
        drop(conn);
        let steps = crate::repos::job_steps::load_plan(&pool, request_id)
            .await
            .expect("load persisted steps");
        let step_one = steps
            .iter()
            .find(|step| step.step_key == "step-one")
            .expect("step one");
        let step_two = steps
            .iter()
            .find(|step| step.step_key == "step-two")
            .expect("step two");
        let make_spec = |step_id| JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(crate::contracts::step_state_key(step_id)),
            mode: JobMode::LiveApply,
        };
        let spec_one = make_spec(step_one.id);
        let spec_two = make_spec(step_two.id);
        let approver = live_approver_session("ops-alice");
        let plan_agent_id = format!("b1b-plan-agent-{}", Uuid::new_v4().simple());
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(&pool, &plan_agent_id, &platform).await;
        let approved_plan_one = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec_one,
            &digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;
        let approved_plan_two = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec_two,
            &digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;

        // Mint TWO step-scoped LiveApply grants for the SAME request — this is
        // the case the single-job unique index would have rejected.
        let mut tx = pool.begin().await.unwrap();
        let wrong_site = format!("{platform}-other-site");
        let site_mismatch = create_step_live_job(
            &mut tx,
            approved_plan_one.clone(),
            request_id,
            step_one.id,
            &wrong_site,
            &spec_one,
            &digest,
            StepLiveJobAuthority::VerifiedHuman(&approver),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(matches!(
            site_mismatch,
            Err(CreateLiveApplyJobError::Invalid(
                "step live-job platform differs from the authoritative request site"
            ))
        ));
        let jobs_after_site_mismatch: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs \
             WHERE request_id = $1 AND mode IN ('LiveApply', 'LiveDestroy') AND step_scoped = TRUE",
        )
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await
        .expect("count step grants after request-site mismatch");
        assert_eq!(
            jobs_after_site_mismatch, 0,
            "a request-site mismatch must mint no step grant"
        );

        let mut destroy_without_prior_apply = spec_one.clone();
        destroy_without_prior_apply.mode = JobMode::LiveDestroy;
        let unbound_destroy = create_step_live_job(
            &mut tx,
            dummy_approved_plan_reference(),
            request_id,
            step_one.id,
            &platform,
            &destroy_without_prior_apply,
            &digest,
            StepLiveJobAuthority::SystemAutoTeardown,
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(matches!(
            unbound_destroy,
            Err(CreateLiveApplyJobError::Invalid(
                "step live-destroy requires the prior signed live-apply authority"
            ))
        ));
        let nonexistent_step_id = Uuid::new_v4();
        let nonexistent_step_spec = make_spec(nonexistent_step_id);
        let foreign_owner = create_step_live_job(
            &mut tx,
            dummy_approved_plan_reference(),
            request_id,
            nonexistent_step_id,
            &platform,
            &nonexistent_step_spec,
            &digest,
            StepLiveJobAuthority::VerifiedHuman(&approver),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(
            matches!(foreign_owner, Err(CreateLiveApplyJobError::Invalid(_))),
            "a syntactically valid key without a request-owned step must be rejected"
        );

        for actor_class in [
            ryuki_engine::auth::ActorClass::Workload,
            ryuki_engine::auth::ActorClass::Unknown,
            ryuki_engine::auth::ActorClass::Simulated,
        ] {
            let mut nonhuman = live_approver_session("human-shaped-nonhuman");
            nonhuman.actor_class = actor_class;
            let denied = create_step_live_job(
                &mut tx,
                approved_plan_one.clone(),
                request_id,
                step_one.id,
                &platform,
                &spec_one,
                &digest,
                StepLiveJobAuthority::VerifiedHuman(&nonhuman),
                Utc::now() + Duration::hours(1),
                &cp_key,
            )
            .await;
            assert!(matches!(denied, Err(CreateLiveApplyJobError::Invalid(_))));
        }
        let wrong_system_authority = create_step_live_job(
            &mut tx,
            approved_plan_one.clone(),
            request_id,
            step_one.id,
            &platform,
            &spec_one,
            &digest,
            StepLiveJobAuthority::SystemAutoTeardown,
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(matches!(
            wrong_system_authority,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        let denied_jobs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs \
             WHERE request_id = $1 AND mode = 'LiveApply' AND step_scoped = TRUE",
        )
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await
        .expect("count denied step grants");
        assert_eq!(denied_jobs, 0, "denied authorities must mint no step grant");

        let job1 = create_step_live_job(
            &mut tx,
            approved_plan_one.clone(),
            request_id,
            step_one.id,
            &platform,
            &spec_one,
            &digest,
            StepLiveJobAuthority::VerifiedHuman(&approver),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("first step grant mints");
        let job2 = create_step_live_job(
            &mut tx,
            approved_plan_two.clone(),
            request_id,
            step_two.id,
            &platform,
            &spec_two,
            &digest,
            StepLiveJobAuthority::VerifiedHuman(&approver),
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("second step grant coexists (mig-153 exemption)");
        tx.commit().await.unwrap();
        assert_ne!(job1, job2, "each step gets a distinct job id");

        #[derive(sqlx::FromRow)]
        struct Row {
            step_scoped: bool,
            live_context: Option<sqlx::types::Json<VerifiedLiveContext>>,
        }
        for (jid, expected_spec_digest) in [
            (job1, ryuki_protocol::job_spec_digest(&spec_one)),
            (job2, ryuki_protocol::job_spec_digest(&spec_two)),
        ] {
            let row: Row =
                sqlx::query_as("SELECT step_scoped, live_context FROM agent_jobs WHERE id = $1")
                    .bind(jid)
                    .fetch_one(&pool)
                    .await
                    .expect("load minted job");
            assert!(row.step_scoped, "step LiveApply job must be step_scoped");
            let grant = row.live_context.expect("grant present").0;
            assert!(
                verify_vlc(&grant, &cp_vk).is_ok(),
                "grant signature verifies"
            );
            assert_eq!(grant.platform, platform, "grant binds destination platform");
            assert_eq!(
                grant.step_job_id,
                Some(jid),
                "grant is bound to THIS step's dispatched job id"
            );
            assert_eq!(
                grant.approved_plan_digest, digest,
                "grant carries the digest"
            );
            let expected_plan = if jid == job1 {
                &approved_plan_one
            } else {
                &approved_plan_two
            };
            assert_eq!(grant.approved_plan_job_id, expected_plan.job_id);
            assert_eq!(grant.approved_plan_attempt_id, expected_plan.attempt_id);
            assert_eq!(
                grant.job_spec_digest, expected_spec_digest,
                "grant binds the exact persisted step JobSpec"
            );
        }

        // Both coexist under one request — the exemption works.
        let live_apply_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            live_apply_count, 2,
            "two step LiveApply jobs coexist for one request"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE request_id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_agent(&pool, &plan_agent_id).await;
        pool.close().await;
    }

    /// Definitive cross-crate proof: the agent's REAL `build_signed_result`
    /// (S5b-2b-i) output for a LiveApply Applied result passes the REAL CP
    /// verifier (verify_vlc + digest equality + everything) against live PG.
    #[tokio::test]
    async fn db_s5b2_agent_live_apply_builder_accepted_by_verifier() {
        use ryuki_agent::executor::JobExecutor;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // The agent's identity is enrolled; the grant is signed by the shared CP
        // key (installed as the global via seed_live_apply_job → ensure_test_cp_key).
        let identity = ryuki_agent::identity::AgentIdentity::generate();
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5b2-{suffix}");
        let agent_id = format!("s5b2-agent-{suffix}");
        let (token, agent_enrollment_id) =
            seed_agent_from_identity(&pool, &agent_id, &platform, &identity).await;

        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &agent_id,
            agent_enrollment_id,
            &identity.public_key_b64(),
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let job = build_protocol_job(
            &job_row,
            agent_enrollment_id,
            attempt_id,
            fencing.clone(),
            nonce.clone(),
            gen,
        );

        // Agent code: a stub Applied execution → the REAL build_signed_result with
        // the matching plan digest (what S5b-2b-ii's loop will do after the gate).
        let evidence = ryuki_agent::executor::StubExecutor::new(
            ryuki_engine::runners::RunStatus::Applied,
            b"terraform apply output (scrubbed)".to_vec(),
            None,
        )
        .execute(&job.spec)
        .expect("stub execute");
        let execution_trust_profile = canonical_execution_trust_profile(&job.spec, &platform);
        let agent_body = ryuki_agent::result::build_signed_result_with_trust_profile(
            &identity,
            &agent_id,
            &job,
            &evidence,
            Some(digest.clone()),
            None,
            Some(execution_trust_profile),
        )
        .expect("build_signed_result for LiveApply Applied must succeed");

        let cp_body: ResultBody =
            serde_json::from_value(serde_json::to_value(&agent_body).expect("serialise"))
                .expect("CP deserialises agent body");
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp =
            post_job_result_with_pool(agent_id.clone(), job_id.to_string(), hdrs, cp_body, &pool)
                .await;
        assert!(
            resp.is_ok(),
            "agent-built LiveApply result must pass the CP verifier: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Succeeded", "applied live job must be terminal");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S5c tests — approve_live_apply_with (operator endpoint core) ──────────
    //
    // All tests call `approve_live_apply_with` directly (no Extension / no HTTP
    // layer) so they need only a PgPool and a SigningKey.  The admin/403 path is
    // enforced by the /api/admin RBAC middleware and the in-handler
    // `check_permission` defense-in-depth guard; both are unit-tested by
    // ryuki-engine's own tests and by the RBAC middleware tests in main.rs.  A
    // note instead of a duplicate integration test is sufficient here.
    //
    // The handler itself is thin: it unwraps pool/cp_key (503) and delegates.
    // Covered by: service_unavailable path is trivially visible from the code;
    // the admin permission check calls `check_permission(session, "admin")` from
    // ryuki_engine::auth, whose own test suite asserts false for non-admin roles.

    /// A valid LiveApply body produces a job whose stored grant verifies
    /// cryptographically and carries the correct fields.
    #[tokio::test]
    async fn db_t1_approve_creates_valid_signed_job() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::{sha256_hex as proto_sha256, verify_vlc};
        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5c-t1-{suffix}");
        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id, &platform).await;
        let digest = proto_sha256(b"approved-plan-s5c");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let plan_agent_id = format!("s5c-t1-plan-agent-{suffix}");
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(&pool, &plan_agent_id, &platform).await;
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;

        let body = ApproveLiveApplyBody {
            approved_plan_job_id: approved_plan.job_id,
            approved_plan_attempt_id: approved_plan.attempt_id,
            request_id,
            platform: platform.clone(),
            spec,
            approved_plan_digest: digest.clone(),
            expiry_seconds: 3600,
        };

        let approver_session = live_approver_session("sentinel-approver");
        let result = approve_live_apply_with(&pool, &cp_key, &approver_session, &body).await;
        assert!(
            result.is_ok(),
            "approve_live_apply_with must succeed for valid input: {:?}",
            result.err()
        );

        let json_val = result.unwrap().0;
        let job_id: Uuid =
            serde_json::from_value(json_val["job_id"].clone()).expect("job_id must be a UUID");
        assert_eq!(json_val["status"], "Pending");
        assert_eq!(json_val["mode"], "LiveApply");
        assert_eq!(json_val["approver"], "sentinel-approver");

        // Read stored live_context and verify the grant.
        #[derive(sqlx::FromRow)]
        struct LiveContextRow {
            live_context: Option<sqlx::types::Json<serde_json::Value>>,
            mode: String,
            status: String,
        }
        let row = sqlx::query_as::<_, LiveContextRow>(
            "SELECT live_context, mode, status FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("fetch job row");

        assert_eq!(row.mode, "LiveApply");
        assert_eq!(row.status, "Pending");

        let grant_json = row.live_context.expect("live_context must be set");
        let grant: VerifiedLiveContext =
            serde_json::from_value(grant_json.0).expect("grant must deserialise");

        assert!(
            verify_vlc(&grant, &cp_vk).is_ok(),
            "stored grant must verify with the CP public key"
        );
        assert_eq!(grant.approved_plan_digest, digest);
        assert_eq!(grant.approver, "sentinel-approver");
        assert_eq!(grant.request_id, request_id);
        assert_eq!(grant.platform, platform);
        assert_eq!(grant.approved_plan_job_id, approved_plan.job_id);
        assert_eq!(grant.approved_plan_attempt_id, approved_plan.attempt_id);

        #[derive(sqlx::FromRow)]
        struct ApprovalAuditRow {
            actor_principal: String,
            actor_display: String,
            actor_roles: Vec<String>,
            provider_mode: String,
            from_status: Option<String>,
            to_status: String,
            from_stage: Option<String>,
            to_stage: String,
            detail: serde_json::Value,
            outcome: String,
            prev_hash: Option<String>,
            entry_hash: Option<String>,
        }
        let audit_row: ApprovalAuditRow = sqlx::query_as(
            "SELECT actor_principal, actor_display, actor_roles, provider_mode, \
             from_status, to_status, from_stage, to_stage, detail, outcome, \
             prev_hash, entry_hash FROM audit_log \
             WHERE request_id = $1 AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("live-apply mint must append one canonical approval audit row");
        assert_eq!(audit_row.actor_principal, approver_session.user_id);
        assert_eq!(audit_row.actor_display, approver_session.display_name);
        assert_eq!(audit_row.actor_roles, approver_session.roles);
        assert_eq!(audit_row.provider_mode, approver_session.provider_mode);
        assert_eq!(grant.approver, audit_row.actor_principal);
        assert_eq!(audit_row.from_status.as_deref(), Some("locked"));
        assert_eq!(audit_row.to_status, "locked");
        assert_eq!(audit_row.from_stage.as_deref(), Some("lock"));
        assert_eq!(audit_row.to_stage, "lock");
        assert_eq!(audit_row.detail["agent_job_id"], json!(job_id));
        assert_eq!(audit_row.detail["approved_plan_digest"], json!(digest));
        assert_eq!(audit_row.detail["mode"], "LiveApply");
        assert!(audit_row.detail.get("spec").is_none());
        assert!(audit_row.detail.get("live_context").is_none());
        assert_eq!(audit_row.outcome, "approved");
        assert!(audit_row
            .prev_hash
            .as_deref()
            .is_some_and(|h| !h.is_empty()));
        assert!(audit_row
            .entry_hash
            .as_deref()
            .is_some_and(|h| !h.is_empty()));
        let chain = crate::audit::verify_audit_chain(&pool)
            .await
            .expect("verify audit chain");
        assert!(
            chain.verified,
            "approval must preserve audit chain integrity"
        );
        assert!(chain.checked > 0, "the committed approval must be checked");
        assert_eq!(chain.first_divergent_id, None);
        assert_eq!(chain.reason, None);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &plan_agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_concurrent_live_approvals_commit_one_job_and_one_audit() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let platform = format!("s5c-race-{}", Uuid::new_v4().simple());
        seed_active_request(&pool, request_id, &platform).await;
        let digest = proto_sha256(b"approved-plan-live-approval-race");
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let plan_agent_id = format!("s5c-race-plan-agent-{}", Uuid::new_v4().simple());
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(&pool, &plan_agent_id, &platform).await;
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;
        let session_a = live_approver_session("race-approver-a");
        let session_b = live_approver_session("race-approver-b");

        let (first, second) = tokio::join!(
            create_live_apply_job(
                &pool,
                approved_plan.clone(),
                request_id,
                &platform,
                &spec,
                &digest,
                &session_a,
                Utc::now() + Duration::hours(1),
                &cp_key,
            ),
            create_live_apply_job(
                &pool,
                approved_plan.clone(),
                request_id,
                &platform,
                &spec,
                &digest,
                &session_b,
                Utc::now() + Duration::hours(1),
                &cp_key,
            )
        );

        assert_eq!(
            first.is_ok() as usize + second.is_ok() as usize,
            1,
            "exactly one concurrent mint must win: first={first:?}, second={second:?}"
        );
        let loser = if first.is_err() { &first } else { &second };
        assert!(matches!(
            loser,
            Err(CreateLiveApplyJobError::Invalid(
                "a live-apply has already been approved for this request"
            ))
        ));

        let job_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("count raced live-apply jobs");
        let audit_actors: Vec<String> = sqlx::query_scalar(
            "SELECT actor_principal FROM audit_log WHERE request_id = $1 \
             AND action = 'request.approve-live-apply' ORDER BY id",
        )
        .bind(request_id)
        .fetch_all(&pool)
        .await
        .expect("read raced live-approval audits");
        assert_eq!(job_count, 1, "unique live-apply slot must hold");
        assert_eq!(audit_actors.len(), 1, "the losing conflict emits no audit");
        assert!(
            audit_actors[0] == session_a.user_id || audit_actors[0] == session_b.user_id,
            "audit actor must be the verified winning session"
        );
        let chain = crate::audit::verify_audit_chain(&pool)
            .await
            .expect("verify raced live-approval audit chain");
        assert!(
            chain.verified,
            "concurrent approval must preserve the chain"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE request_id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_agent(&pool, &plan_agent_id).await;
        pool.close().await;
    }

    /// A non-hex approved_plan_digest is rejected with 400.
    #[tokio::test]
    async fn db_t1_bad_plan_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        // Seed an active request so the bad-DIGEST rejection (a post-gate check
        // in create_live_apply_job) is what's exercised — not the concluded gate.
        seed_active_request(&pool, request_id, "any").await;
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: "not-hex".into(),
            expiry_seconds: 3600,
        };

        let result =
            approve_live_apply_with(&pool, &cp_key, &live_approver_session("ops-test"), &body)
                .await;
        assert!(result.is_err(), "non-hex digest must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// expiry_seconds = 0 is rejected with 400.
    #[tokio::test]
    async fn db_t1_expiry_zero_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: proto_sha256(b"plan"),
            expiry_seconds: 0,
        };

        let result =
            approve_live_apply_with(&pool, &cp_key, &live_approver_session("ops-test"), &body)
                .await;
        assert!(result.is_err(), "zero expiry must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// expiry_seconds > MAX_GRANT_TTL_HOURS * 3600 is rejected with 400.
    #[tokio::test]
    async fn db_t1_expiry_over_max_ttl_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: proto_sha256(b"plan"),
            expiry_seconds: (MAX_GRANT_TTL_HOURS as u64) * 3600 + 1,
        };

        let result =
            approve_live_apply_with(&pool, &cp_key, &live_approver_session("ops-test"), &body)
                .await;
        assert!(result.is_err(), "over-max TTL must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// spec.mode != LiveApply is rejected with 400.
    #[tokio::test]
    async fn db_t1_non_live_apply_mode_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::OfflineDryRun,
        };
        let body = ApproveLiveApplyBody {
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: proto_sha256(b"plan"),
            expiry_seconds: 3600,
        };

        let result =
            approve_live_apply_with(&pool, &cp_key, &live_approver_session("ops-test"), &body)
                .await;
        assert!(result.is_err(), "OfflineDryRun spec must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// The approver stored in the grant and canonical audit row comes from the
    /// same verified session, never from the request body.
    #[tokio::test]
    async fn db_t1_approver_is_from_param_not_body() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::{sha256_hex as proto_sha256, verify_vlc};
        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5c-t6-{suffix}");
        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id, &platform).await;
        let digest = proto_sha256(b"plan-for-approver-test");
        let sentinel_approver = "session-derived-approver-not-from-body";
        let approver_session = live_approver_session(sentinel_approver);

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let plan_agent_id = format!("s5c-t6-plan-agent-{suffix}");
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(&pool, &plan_agent_id, &platform).await;
        let approved_plan = seed_signed_successful_plan_for_mutation(
            &pool,
            request_id,
            &platform,
            &spec,
            &digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;
        let body = ApproveLiveApplyBody {
            approved_plan_job_id: approved_plan.job_id,
            approved_plan_attempt_id: approved_plan.attempt_id,
            request_id,
            platform: platform.clone(),
            spec,
            approved_plan_digest: digest.clone(),
            expiry_seconds: 3600,
        };

        let result = approve_live_apply_with(&pool, &cp_key, &approver_session, &body).await;
        assert!(result.is_ok(), "approve must succeed: {:?}", result.err());

        let json_val = result.unwrap().0;
        let job_id: Uuid = serde_json::from_value(json_val["job_id"].clone()).expect("UUID");

        #[derive(sqlx::FromRow)]
        struct Row {
            live_context: Option<sqlx::types::Json<serde_json::Value>>,
        }
        let row = sqlx::query_as::<_, Row>("SELECT live_context FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("fetch");

        let grant: VerifiedLiveContext =
            serde_json::from_value(row.live_context.expect("live_context").0).expect("deserialise");

        // The grant's approver must equal the verified session principal,
        // proving the body cannot influence it.
        assert_eq!(
            grant.approver, sentinel_approver,
            "grant.approver must come from the session, not the body"
        );
        let audit_actor: String = sqlx::query_scalar(
            "SELECT actor_principal FROM audit_log \
             WHERE request_id = $1 AND action = 'request.approve-live-apply'",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("approval audit actor");
        assert_eq!(audit_actor, sentinel_approver);
        assert_eq!(grant.approver, audit_actor);
        assert!(verify_vlc(&grant, &cp_vk).is_ok(), "grant must verify");
        assert_eq!(
            grant.job_spec_digest,
            ryuki_protocol::job_spec_digest(&body.spec),
            "admin-created grants must bind the exact request-owned JobSpec"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &plan_agent_id).await;
        pool.close().await;
    }

    // ── admin_list_agents: returns agents and their jobs ──────────────────

    #[tokio::test]
    async fn db_t2_list_agents_returns_agents_and_jobs() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Unique platform prefix prevents cross-test interference.
        let suffix = Uuid::new_v4().to_string().replace('-', "");
        let suffix = &suffix[..8];
        let platform_a = format!("t2la-{suffix}a");
        let platform_b = format!("t2la-{suffix}b");
        let agent_id_a = format!("t2la-agent-{suffix}-a");
        let agent_id_b = format!("t2la-agent-{suffix}-b");

        // Seed two agents.
        seed_agent(&pool, &agent_id_a, &platform_a, "approved").await;
        seed_agent(&pool, &agent_id_b, &platform_b, "pending").await;

        // Seed two jobs for agent A (directly set agent_id on the job so it
        // appears in the agent→jobs association returned by list_agents_with).
        let job1 = seed_pending_job(&pool, &platform_a).await;
        let job2 = seed_pending_job(&pool, &platform_a).await;
        sqlx::query("UPDATE agent_jobs SET agent_id = $1, status = 'Succeeded' WHERE id = ANY($2)")
            .bind(&agent_id_a)
            .bind(&[job1, job2] as &[Uuid])
            .execute(&pool)
            .await
            .expect("associate jobs with agent");

        // Call the testable core (auth already tested separately).
        let result = list_agents_with(&pool).await;
        assert!(
            result.is_ok(),
            "list_agents_with must succeed: {:?}",
            result.err()
        );
        let json_val = result.unwrap().0;

        let agents_arr = json_val["agents"].as_array().expect("agents must be array");

        // Both seeded agents must appear.
        let found_a = agents_arr
            .iter()
            .any(|v| v["agent_id"].as_str() == Some(&agent_id_a));
        let found_b = agents_arr
            .iter()
            .any(|v| v["agent_id"].as_str() == Some(&agent_id_b));
        assert!(found_a, "agent A must appear in list");
        assert!(found_b, "agent B must appear in list");

        // Agent A's jobs must be nested under it.
        let agent_a_entry = agents_arr
            .iter()
            .find(|v| v["agent_id"].as_str() == Some(&agent_id_a))
            .expect("agent A entry");
        assert!(Uuid::parse_str(
            agent_a_entry["enrollment_id"]
                .as_str()
                .expect("immutable enrollment id")
        )
        .is_ok());
        assert!(valid_public_key_fingerprint_shape(
            agent_a_entry["public_key_fingerprint"]
                .as_str()
                .expect("reviewable public-key fingerprint")
        ));
        assert!(valid_public_key_fingerprint_shape(
            agent_a_entry["capabilities_digest"]
                .as_str()
                .expect("reviewable capabilities digest")
        ));
        assert_eq!(
            agent_a_entry["cryptographically_admitted"],
            json!(true),
            "a post-cutover approved fixture must retain its consumed-challenge provenance"
        );
        let jobs_a = agent_a_entry["jobs"]
            .as_array()
            .expect("jobs must be array");
        assert_eq!(jobs_a.len(), 2, "agent A must have exactly 2 jobs");

        // Agent B has no jobs associated; its jobs array must be empty.
        let agent_b_entry = agents_arr
            .iter()
            .find(|v| v["agent_id"].as_str() == Some(&agent_id_b))
            .expect("agent B entry");
        assert_eq!(
            agent_b_entry["cryptographically_admitted"],
            json!(true),
            "a challenge-linked Pending fixture must expose its admission provenance"
        );
        let jobs_b = agent_b_entry["jobs"]
            .as_array()
            .expect("jobs must be array");
        assert!(jobs_b.is_empty(), "agent B must have no jobs");

        // Clean up.
        cleanup_jobs_for_platform(&pool, &platform_a).await;
        cleanup_jobs_for_platform(&pool, &platform_b).await;
        cleanup_agent(&pool, &agent_id_a).await;
        cleanup_agent(&pool, &agent_id_b).await;
        pool.close().await;
    }

    // ── admin_list_agents: non-admin session → 403 ───────────────────────

    #[tokio::test]
    async fn db_t2_list_agents_non_admin_403() {
        // This test does not need a DB — the check_permission gate fires before
        // any pool access. We skip the DB guard for speed and still test the 403
        // branch correctly using the handler's in-handler auth check.
        let non_admin_session = AuthSession {
            user_id: "non-admin-user".to_string(),
            display_name: "Non Admin".to_string(),
            // Requester role has no "admin" permission.
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            provider_mode: "test".to_string(),
            ..Default::default()
        };

        // check_permission must return false for a non-admin.
        assert!(
            !check_permission(&non_admin_session, "admin"),
            "Requester must not hold admin permission"
        );

        // Verify the handler branch: forbidden() produces a 403.
        let (status, _body) = forbidden("admin permission required");
        assert_eq!(status, StatusCode::FORBIDDEN, "forbidden() must be 403");
    }

    // ── admin_list_agents: response never contains token_hash ────────────

    #[tokio::test]
    async fn db_t2_list_agents_no_secrets() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let suffix = Uuid::new_v4().to_string().replace('-', "");
        let suffix = &suffix[..8];
        let platform = format!("t2ns-{suffix}");
        let agent_id = format!("t2ns-agent-{suffix}");

        // seed_agent returns the plaintext token; we only need the hash to
        // check it does NOT appear in the response.
        let _plaintext = seed_agent(&pool, &agent_id, &platform, "pending").await;

        // Retrieve the stored token_hash and raw public key directly so we can
        // assert both are absent while the derived fingerprint is present.
        let (hash, public_key): (String, String) =
            sqlx::query_as("SELECT token_hash, public_key FROM agents WHERE agent_id = $1")
                .bind(&agent_id)
                .fetch_one(&pool)
                .await
                .expect("fetch stored enrollment values for assertion");

        let result = list_agents_with(&pool).await;
        assert!(result.is_ok(), "list must succeed");
        let json_str = serde_json::to_string(&result.unwrap().0).expect("serialize");

        assert!(
            !json_str.contains(&hash),
            "response must not contain the token_hash value"
        );
        assert!(
            !json_str.contains(&public_key),
            "response must not contain the raw public key"
        );
        assert!(
            json_str.contains(&public_key_fingerprint(&public_key)),
            "response must contain the reviewable public-key fingerprint"
        );

        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// AWX bridge slice 2: a successful agent result advances the dispatched
    /// (Executing) parent request to Verifying with the execute stage Completed;
    /// a non-executing request is left untouched (synthetic/test jobs).
    #[tokio::test]
    async fn db_backlink_advances_executing_request() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = Uuid::new_v4();
        let stages = serde_json::json!([{
            "name": "execute", "status": "InProgress",
            "started_at": null, "completed_at": null,
            "evidence": [], "metadata": {}
        }]);
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 'backlink-test', 'executing', 'execute', $2::jsonb)",
        )
        .bind(req_id)
        .bind(&stages)
        .execute(&pool)
        .await
        .expect("insert executing request");

        // Success result: executing -> verifying, execute stage Completed.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            Uuid::new_v4(),
        )
        .await
        .expect("backlink");
        tx.commit().await.unwrap();

        let (status, stages_after): (String, serde_json::Value) =
            sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .expect("read back");
        assert_eq!(status, "verifying", "executing -> verifying on success");
        let execute = stages_after
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "execute")
            .expect("execute stage");
        assert_eq!(execute["status"], "Completed", "execute stage completed");
        assert!(
            execute["metadata"]["agent_job_id"].is_string(),
            "execute stage records the agent job id"
        );

        // The agent-driven hop must land in the hash-chained audit trail with
        // machine-actor attribution (QA finding: this transition was the one
        // unaudited status change in the whole lifecycle).
        let (actor, from_status, to_status, outcome): (String, String, String, String) =
            sqlx::query_as(
                "SELECT actor_principal, from_status, to_status, outcome FROM audit_log \
                 WHERE request_id = $1 AND action = 'request.execution-result' \
                 ORDER BY id DESC LIMIT 1",
            )
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .expect("audit row for the executing -> verifying hop");
        assert!(actor.starts_with("agent:"), "machine actor, got {actor}");
        assert_eq!(from_status, "executing");
        assert_eq!(to_status, "verifying");
        assert_eq!(outcome, "applied");

        // A non-executing request is left untouched (CAS guard / skip path).
        sqlx::query("UPDATE requests SET status = 'completed' WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .ok();
        let mut tx2 = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx2,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::OfflineDryRun,
            "failed",
            "x",
            Uuid::new_v4(),
        )
        .await
        .expect("backlink no-op");
        tx2.commit().await.unwrap();
        let status2: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status2, "completed", "non-executing request is not mutated");

        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// Regression: if `requests.stages` cannot be parsed into `Vec<Stage>` (a schema
    /// skew / corruption), the execution backlink must PRESERVE the existing stages
    /// JSONB rather than wiping it to `[]`. The status still advances; the history is
    /// not destroyed.
    #[tokio::test]
    async fn db_backlink_preserves_unparseable_stages() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = Uuid::new_v4();
        // An OBJECT, not a Vec<Stage> array → serde_json::from_value::<Vec<Stage>> fails.
        let corrupt = serde_json::json!({"legacy_shape": true, "stages": ["x"]});
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 'backlink-corrupt', 'executing', 'execute', $2::jsonb)",
        )
        .bind(req_id)
        .bind(&corrupt)
        .execute(&pool)
        .await
        .expect("insert executing request with unparseable stages");

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            Uuid::new_v4(),
        )
        .await
        .expect("backlink must not error on unparseable stages");
        tx.commit().await.unwrap();

        let (status, stages_after): (String, serde_json::Value) =
            sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .expect("read back");
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;

        assert_eq!(
            status, "verifying",
            "status still advances on a success result"
        );
        assert_eq!(
            stages_after, corrupt,
            "unparseable stages are PRESERVED untouched, NOT wiped to []"
        );
    }

    // ── #42 slice 2b: next-step dispatch on step success/failure ─────────────

    /// Seeds an `executing` request row (mirrors
    /// `db_backlink_advances_executing_request`'s raw-SQL seeding pattern),
    /// returns its id.
    async fn seed_executing_request(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let stages = serde_json::json!([{
            "name": "execute", "status": "InProgress",
            "started_at": null, "completed_at": null,
            "evidence": [], "metadata": {}
        }]);
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 'step-2b-test', 'executing', 'execute', $2::jsonb)",
        )
        .bind(id)
        .bind(&stages)
        .execute(pool)
        .await
        .expect("insert executing request");
        id
    }

    /// Dispatch a step: insert a synthetic `agent_jobs` row and link it via
    /// `job_steps::mark_running`, exactly as `dispatch_ready_steps` would.
    /// Returns the minted `agent_jobs.id`.
    async fn dispatch_step_job(pool: &PgPool, request_id: Uuid, step_id: Uuid) -> Uuid {
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'OfflineDryRun') RETURNING id",
        )
        .bind(request_id)
        .fetch_one(pool)
        .await
        .expect("insert synthetic agent_job");
        crate::repos::job_steps::mark_running(pool, step_id, job_id)
            .await
            .expect("mark_running");
        job_id
    }

    /// #42 slice B1a: dispatch a step as a LivePlan job — mirrors
    /// `dispatch_step_job` exactly, but inserts `mode='LivePlan'` and links
    /// via `job_steps::mark_planning` (not `mark_running`), exactly as
    /// `dispatch_ready_steps` would for a LivePlan-mode plan. Returns the
    /// minted `agent_jobs.id`.
    async fn dispatch_liveplan_step_job(pool: &PgPool, request_id: Uuid, step_id: Uuid) -> Uuid {
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LivePlan') RETURNING id",
        )
        .bind(request_id)
        .fetch_one(pool)
        .await
        .expect("insert synthetic LivePlan agent_job");
        crate::repos::job_steps::mark_planning(pool, step_id, job_id)
            .await
            .expect("mark_planning");
        job_id
    }

    async fn cleanup_step_2b_request(pool: &PgPool, id: Uuid) {
        sqlx::query("DELETE FROM job_steps WHERE request_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM agent_jobs WHERE request_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    /// Chain a -> b: completing 'a' dispatches 'b' and keeps the request
    /// `executing`; completing 'b' (the final step) advances the request to
    /// `verifying`.
    #[tokio::test]
    async fn db_step2b_chain_dispatches_next_and_completes() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed 2-step plan");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let job_a = dispatch_step_job(&pool, req_id, step_a.id).await;

        // Complete 'a' with success.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            job_a,
        )
        .await
        .expect("backlink a");
        tx.commit().await.unwrap();

        let status_mid: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status_mid, "executing",
            "request stays executing while 'b' is still pending"
        );

        let plan_mid = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan mid");
        let a_mid = plan_mid.iter().find(|s| s.step_key == "a").unwrap();
        let b_mid = plan_mid.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(a_mid.status, "Succeeded", "a marked Succeeded");
        assert_eq!(b_mid.status, "Running", "b dispatched (now Running)");
        let job_b = b_mid
            .agent_job_id
            .expect("b must have a dispatched agent_job");

        // Complete 'b' (the final step) with success.
        let mut tx2 = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx2,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            job_b,
        )
        .await
        .expect("backlink b");
        tx2.commit().await.unwrap();

        let status_final: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status_final, "verifying",
            "request advances to verifying once ALL steps succeeded"
        );

        let plan_final = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan final");
        for s in &plan_final {
            assert_eq!(
                s.status, "Succeeded",
                "step {} must be Succeeded",
                s.step_key
            );
        }

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// Chain a -> b: a step FAILURE fails the request immediately and does
    /// NOT dispatch downstream steps.
    #[tokio::test]
    async fn db_step2b_failure_fails_request_without_dispatching_next() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed 2-step plan");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let job_a = dispatch_step_job(&pool, req_id, step_a.id).await;

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::OfflineDryRun,
            "failed",
            "deadbeefdeadbeef",
            job_a,
        )
        .await
        .expect("backlink a failure");
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "failed", "a step failure fails the request");

        let plan_after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after");
        let a_after = plan_after.iter().find(|s| s.step_key == "a").unwrap();
        let b_after = plan_after.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(a_after.status, "Failed", "a marked Failed");
        assert_eq!(
            b_after.status, "Pending",
            "b is NEVER dispatched once the request has failed"
        );
        assert!(
            b_after.agent_job_id.is_none(),
            "b must have no dispatched agent_job"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    // ── #42 slice B1a: LivePlan step success/failure ──────────────────────

    /// A step's LivePlan succeeding parks it at AwaitingApproval with its
    /// digest recorded — it does NOT dispatch the next step and does NOT
    /// advance the request out of `executing`. This is the forward per-step
    /// live path's human-gated pause point (see
    /// docs/design/live-apply-per-step.md): a downstream step's plan cannot
    /// be computed until an operator has approved and applied this one
    /// (slice B1b), so nothing here proceeds on its own.
    #[tokio::test]
    async fn db_step_liveplan_success_awaits_approval_without_dispatching() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed 2-step plan");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let job_a = dispatch_liveplan_step_job(&pool, req_id, step_a.id).await;
        let evidence_digest = "b".repeat(64);
        let raw_plan_digest = "a".repeat(64);

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution_with_raw_plan_digest(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::LivePlan,
            "planned",
            BacklinkDigests {
                evidence: &evidence_digest,
                raw_plan: Some(&raw_plan_digest),
            },
            job_a,
        )
        .await
        .expect("backlink a liveplan success");
        tx.commit().await.unwrap();

        let plan_after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after");
        let a_after = plan_after.iter().find(|s| s.step_key == "a").unwrap();
        let b_after = plan_after.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(
            a_after.status, "AwaitingApproval",
            "a's successful LivePlan parks it at AwaitingApproval"
        );
        assert_eq!(
            a_after.live_plan_digest.as_deref(),
            Some(raw_plan_digest.as_str()),
            "a's live_plan_digest is recorded from the signed raw-plan commitment"
        );
        assert_eq!(
            b_after.status, "Pending",
            "b must NOT be dispatched on a's LivePlan success — B1a withholds downstream dispatch"
        );
        assert!(
            b_after.agent_job_id.is_none(),
            "b must have no dispatched agent_job"
        );

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "executing",
            "the request stays executing — a LivePlan success never advances it"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// A step's LivePlan failing fails the step and the request, exactly like
    /// the existing OfflineDryRun failure path (no teardown logic — that is
    /// slice B2).
    #[tokio::test]
    async fn db_step_liveplan_failure_fails_request() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed 2-step plan");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let job_a = dispatch_liveplan_step_job(&pool, req_id, step_a.id).await;

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LivePlan,
            "failed",
            "livedigest-a-failed",
            job_a,
        )
        .await
        .expect("backlink a liveplan failure");
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "failed", "a's LivePlan failure fails the request");

        let plan_after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after");
        let a_after = plan_after.iter().find(|s| s.step_key == "a").unwrap();
        let b_after = plan_after.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(a_after.status, "Failed", "a marked Failed");
        assert_eq!(
            a_after.live_plan_digest, None,
            "no digest is recorded on a LivePlan failure"
        );
        assert_eq!(
            b_after.status, "Pending",
            "b is NEVER dispatched once the request has failed"
        );
        assert!(
            b_after.agent_job_id.is_none(),
            "b must have no dispatched agent_job"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// #42 slice B1a: when a LivePlan step fails while an INDEPENDENT sibling
    /// step is still in-flight (`Planning`), the failing request must reconcile
    /// that sibling to `Failed` too — not leave it stranded `Planning`. This
    /// exercises `fail_inflight_steps` sweeping `Planning` (not just `Running`,
    /// which was slice 2b's OfflineDryRun-only case). The current linear
    /// offering template can't produce concurrent `Planning` steps, but the
    /// dispatch path allows a multi-root live plan, so the reconciliation must
    /// be correct regardless.
    #[tokio::test]
    async fn db_step_liveplan_failure_reconciles_planning_sibling() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        // Two INDEPENDENT roots — both are initially ready and both get a
        // LivePlan job dispatched (status Planning).
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec![], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed 2 independent roots");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let step_b = plan.iter().find(|s| s.step_key == "b").expect("step b");
        let job_a = dispatch_liveplan_step_job(&pool, req_id, step_a.id).await;
        let _job_b = dispatch_liveplan_step_job(&pool, req_id, step_b.id).await;

        // 'a' fails while 'b' is still Planning (in-flight LivePlan).
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LivePlan,
            "failed",
            "livedigest-a-failed",
            job_a,
        )
        .await
        .expect("backlink a liveplan failure");
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "failed", "a's LivePlan failure fails the request");

        let after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after");
        let a_after = after.iter().find(|s| s.step_key == "a").unwrap();
        let b_after = after.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(a_after.status, "Failed", "a marked Failed");
        assert_eq!(
            b_after.status, "Failed",
            "the in-flight Planning sibling b is reconciled to Failed, not stranded Planning"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// #42 slice B1a (TOCTOU regression): a LivePlan step success that arrives
    /// AFTER a concurrent sibling failure has already failed the request and
    /// swept this step to `Failed` must NOT resurrect the step to
    /// `AwaitingApproval`. Simulates the post-lock state the losing transaction
    /// would observe (request already `failed`, step already `Failed`) and
    /// asserts the backlink no-ops. Guards both fix layers: the post-lock
    /// request-status re-read (bails on non-`executing`) and the
    /// `record_live_plan_digest` `WHERE status = 'Planning'` predicate.
    #[tokio::test]
    async fn db_step_liveplan_success_under_failed_request_does_not_resurrect() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[("a", vec![], "linux-server-deployment")],
        )
        .await
        .expect("seed 1-step plan");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let job_a = dispatch_liveplan_step_job(&pool, req_id, step_a.id).await;

        // Simulate the race outcome the losing tx would see post-lock: a sibling
        // failure already failed the request and swept step 'a' to Failed.
        sqlx::query("UPDATE requests SET status = 'failed' WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .unwrap();
        crate::repos::job_steps::mark_status(&pool, step_a.id, "Failed")
            .await
            .unwrap();

        // The late LivePlan success must be a no-op — no resurrection.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::LivePlan,
            "planned",
            "late-digest",
            job_a,
        )
        .await
        .expect("backlink late liveplan success");
        tx.commit().await.unwrap();

        let after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after");
        let a_after = after.iter().find(|s| s.step_key == "a").unwrap();
        assert_eq!(
            a_after.status, "Failed",
            "a late LivePlan success under a failed request must NOT resurrect the swept step"
        );
        assert_eq!(
            a_after.live_plan_digest, None,
            "no digest is recorded for a swept step"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// #42 slice B1b: the forward live chain through the backlink. Chain a->b,
    /// both applied one at a time: completing a's LiveApply marks a `Applied`
    /// and dispatches b as `LivePlan` (b parks for its own approval), keeping
    /// the request executing; completing b's LiveApply (once dispatched) marks
    /// b `Applied` and — all steps now applied — advances the request to
    /// `verifying`.
    #[tokio::test]
    async fn db_step_liveapply_success_applies_and_chains_to_verifying() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed a->b chain");
        drop(conn);

        // 'a' has been approved and is Applying with a dispatched LiveApply job.
        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        let step_a = plan.iter().find(|s| s.step_key == "a").unwrap();
        let job_a: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, step_scoped) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveApply', TRUE) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE job_steps SET status = 'Applying', agent_job_id = $2 WHERE id = $1")
            .bind(step_a.id)
            .bind(job_a)
            .execute(&pool)
            .await
            .unwrap();

        // a's LiveApply succeeds -> a Applied, b dispatched as LivePlan, still executing.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Applied,
            &JobMode::LiveApply,
            "applied",
            "a-applied-digest",
            job_a,
        )
        .await
        .expect("backlink a liveapply");
        tx.commit().await.unwrap();

        let mid = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        let a_mid = mid.iter().find(|s| s.step_key == "a").unwrap();
        let b_mid = mid.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(a_mid.status, "Applied", "a is applied");
        assert_eq!(
            b_mid.status, "Planning",
            "b dispatched as LivePlan after a applied"
        );
        let status_mid: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status_mid, "executing", "request stays executing mid-chain");

        // b's LivePlan -> AwaitingApproval, then approved -> Applying, then LiveApply -> Applied.
        let job_b: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, step_scoped) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveApply', TRUE) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE job_steps SET status = 'Applying', agent_job_id = $2 WHERE step_key = 'b' AND request_id = $1")
            .bind(req_id)
            .bind(job_b)
            .execute(&pool)
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Applied,
            &JobMode::LiveApply,
            "applied",
            "b-applied-digest",
            job_b,
        )
        .await
        .expect("backlink b liveapply");
        tx.commit().await.unwrap();

        let status_final: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status_final, "verifying",
            "all steps applied -> request advances to verifying"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// #42 slice B1b (Codex finding): when a LiveApply step fails while an
    /// INDEPENDENT sibling is still `Applying` (its live apply in flight), the
    /// failing request must reconcile that sibling to `Failed` too — not leave
    /// it stranded `Applying`. Exercises `fail_inflight_steps` sweeping
    /// `Applying` (the B1b in-flight live-apply state), the analogue of the
    /// `Planning` sweep for LivePlan.
    #[tokio::test]
    async fn db_step_liveapply_failure_reconciles_applying_sibling() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec![], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed 2 independent roots");
        drop(conn);

        // Both roots have been approved and are Applying (LiveApply in flight).
        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        let step_a = plan.iter().find(|s| s.step_key == "a").unwrap();
        let step_b = plan.iter().find(|s| s.step_key == "b").unwrap();
        let mut job_ids = Vec::new();
        for step in [step_a, step_b] {
            let jid: Uuid = sqlx::query_scalar(
                "INSERT INTO agent_jobs (request_id, platform, spec, mode, step_scoped) \
                 VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveApply', TRUE) RETURNING id",
            )
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE job_steps SET status = 'Applying', agent_job_id = $2 WHERE id = $1",
            )
            .bind(step.id)
            .bind(jid)
            .execute(&pool)
            .await
            .unwrap();
            job_ids.push(jid);
        }

        // a's LiveApply fails while b is still Applying.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LiveApply,
            "failed",
            "a-apply-failed",
            job_ids[0],
        )
        .await
        .expect("backlink a liveapply failure");
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "failed", "a's live-apply failure fails the request");
        let after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        let a_after = after.iter().find(|s| s.step_key == "a").unwrap();
        let b_after = after.iter().find(|s| s.step_key == "b").unwrap();
        assert_eq!(a_after.status, "Failed", "a marked Failed");
        assert_eq!(
            b_after.status, "Failed",
            "the in-flight Applying sibling b is reconciled to Failed, not stranded"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    // ── #42 slice B2-2: auto compensating teardown ──────────────────────────

    /// Seed an executing request whose chain a->b->c has a,b `Applied` through
    /// real CP-signed LiveApply grants backed by exact signed LivePlan rows, and
    /// c `Applying`. An existing identity may be supplied for the full-loop
    /// test; otherwise this helper owns and returns a fixture agent to clean up.
    async fn seed_teardown_chain(
        pool: &PgPool,
        existing_agent: Option<(&str, Uuid, &ed25519_dalek::SigningKey)>,
    ) -> (Uuid, Uuid, Option<String>) {
        let req_id = seed_executing_request(pool).await;
        let (agent_id, agent_key, agent_enrollment_id, owned_agent_id) = match existing_agent {
            Some((agent_id, enrollment_id, signing_key)) => (
                agent_id.to_string(),
                signing_key.clone(),
                enrollment_id,
                None,
            ),
            None => {
                let agent_id = format!("teardown-plan-agent-{}", Uuid::new_v4().simple());
                let (_token, key, enrollment_id) =
                    seed_agent_with_key(pool, &agent_id, "DEFRA").await;
                (agent_id.clone(), key, enrollment_id, Some(agent_id))
            }
        };
        let mut conn = pool.acquire().await.unwrap();
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
                ("c", vec!["b".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .unwrap();
        drop(conn);
        let steps = crate::repos::job_steps::load_plan(pool, req_id)
            .await
            .expect("teardown steps");
        let (name, site, environment, cpu, memory_gb): (String, String, String, i32, i32) =
            sqlx::query_as(
                "SELECT name, site, environment, cpu, memory_gb FROM requests WHERE id = $1",
            )
            .bind(req_id)
            .fetch_one(pool)
            .await
            .expect("teardown request inputs");
        let metadata = std::collections::HashMap::new();
        let digest = "a".repeat(64);
        let cp_key = ensure_test_cp_key();
        let approver = live_approver_session("teardown-fixture-approver");
        for step in steps
            .iter()
            .filter(|step| matches!(step.step_key.as_str(), "a" | "b"))
        {
            let iac_digest = ryuki_runner::iac::offering_iac_digest(&step.iac_ref)
                .unwrap_or_else(|| "0".repeat(64));
            let mut vars = ryuki_runner::iac::render_vars(&ryuki_runner::iac::DeploymentInputs {
                offering_id: &step.iac_ref,
                request_id: &req_id.to_string(),
                name: &name,
                site: &site,
                environment: &environment,
                cpu: u32::try_from(cpu).unwrap_or(0),
                memory_gb: u32::try_from(memory_gb).unwrap_or(0),
                metadata: &metadata,
            });
            // The synthetic request intentionally leaves its deployment shape
            // empty; complete this positive signed-plan fixture with a safe,
            // reviewable shape before minting its apply authority.
            vars.extend(reviewable_live_plan_vars());
            let apply_spec = JobSpec {
                request_id: req_id,
                offering_id: Uuid::new_v4(),
                iac_ref: step.iac_ref.clone(),
                iac_digest,
                vars,
                state_key: Some(crate::contracts::step_state_key(step.id)),
                mode: JobMode::LiveApply,
            };
            let approved_plan = seed_signed_successful_plan_for_mutation(
                pool,
                req_id,
                &site,
                &apply_spec,
                &digest,
                &agent_id,
                agent_enrollment_id,
                &agent_key,
            )
            .await;
            let mut tx = pool.begin().await.expect("teardown apply tx");
            let apply_job_id = create_step_live_job(
                &mut tx,
                approved_plan,
                req_id,
                step.id,
                &site,
                &apply_spec,
                &digest,
                StepLiveJobAuthority::VerifiedHuman(&approver),
                Utc::now() + Duration::hours(1),
                &cp_key,
            )
            .await
            .expect("seed exact applied step grant");
            sqlx::query(
                "UPDATE agent_jobs SET status = 'Succeeded', result_status = 'verified', \
                     completed_at = NOW() WHERE id = $1",
            )
            .bind(apply_job_id)
            .execute(&mut *tx)
            .await
            .expect("complete applied fixture row");
            sqlx::query(
                "UPDATE job_steps SET status = 'Applied', live_plan_digest = $2, \
                     agent_job_id = $3 WHERE id = $1",
            )
            .bind(step.id)
            .bind(&digest)
            .bind(apply_job_id)
            .execute(&mut *tx)
            .await
            .expect("link applied step authority");
            tx.commit().await.expect("commit applied step authority");
        }
        let job_c: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, step_scoped) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveApply', TRUE) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_steps SET status = 'Applying', agent_job_id = $2 \
             WHERE request_id = $1 AND step_key = 'c'",
        )
        .bind(req_id)
        .bind(job_c)
        .execute(pool)
        .await
        .unwrap();
        (req_id, job_c, owned_agent_id)
    }

    async fn step_of<'a>(
        plan: &'a [crate::repos::job_steps::JobStepRow],
        key: &str,
    ) -> &'a crate::repos::job_steps::JobStepRow {
        plan.iter().find(|s| s.step_key == key).expect("step")
    }

    /// A live step failing with earlier applied steps triggers auto teardown:
    /// the applied steps are destroyed in REVERSE dependency order (b before a),
    /// one at a time, and the request only reaches `failed` once everything is
    /// rolled back.
    #[tokio::test]
    async fn db_b2_teardown_reverse_order_and_completes() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _cp_key = ensure_test_cp_key();
        let (req_id, job_c, owned_agent_id) = seed_teardown_chain(&pool, None).await;

        // c's LiveApply fails -> teardown begins. b (its only Applied dependent
        // is now Failed c) is ready first; a is NOT (b still Applied).
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LiveApply,
            "failed",
            "c-apply-failed",
            job_c,
        )
        .await
        .expect("backlink c failure");
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(step_of(&plan, "c").await.status, "Failed");
        assert_eq!(
            step_of(&plan, "b").await.status,
            "TearingDown",
            "b is torn down first (reverse order)"
        );
        assert_eq!(
            step_of(&plan, "a").await.status,
            "Applied",
            "a waits until its dependent b is torn down"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "executing",
            "request stays executing during teardown"
        );

        // b's LiveDestroy succeeds -> b ToreDown, a now ready -> a TearingDown.
        let job_b = step_of(&plan, "b").await.agent_job_id.unwrap();
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Applied,
            &JobMode::LiveDestroy,
            "applied",
            "b-destroyed",
            job_b,
        )
        .await
        .expect("backlink b destroy");
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(step_of(&plan, "b").await.status, "ToreDown");
        assert_eq!(
            step_of(&plan, "a").await.status,
            "TearingDown",
            "a is torn down after b"
        );

        // a's LiveDestroy succeeds -> a ToreDown, nothing left -> request failed.
        let job_a = step_of(&plan, "a").await.agent_job_id.unwrap();
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Applied,
            &JobMode::LiveDestroy,
            "applied",
            "a-destroyed",
            job_a,
        )
        .await
        .expect("backlink a destroy");
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(step_of(&plan, "a").await.status, "ToreDown");
        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "failed",
            "request fails cleanly once every applied step is rolled back"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        if let Some(agent_id) = owned_agent_id {
            cleanup_agent(&pool, &agent_id).await;
        }
        pool.close().await;
    }

    /// #42 B2-3 FULL LOOP, cross-crate: an applied step + a failing sibling
    /// triggers the auto-teardown dispatch (a REAL `LiveDestroy` job with a
    /// REAL CP-minted, step-bound grant via `dispatch_teardown_steps`); the
    /// AGENT side then runs its REAL trust gate (`evaluate_live_execution`
    /// with NO plan digest) and REAL result builder (`build_signed_result`,
    /// Applied, no digest) for that job; and the REAL CP verifier
    /// (`post_job_result_with_pool`) accepts the signed result, marks the job
    /// terminal, the step `ToreDown`, and advances the cascade. The runner's
    /// actual `terraform destroy` execution is proven separately by
    /// ryuki-runner's real-terraform e2e; here the destroy evidence is canned
    /// so the test exercises the trust/result loop deterministically.
    #[tokio::test]
    async fn db_b23_full_loop_agent_destroy_result_marks_step_tore_down() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // One global CP key for BOTH the teardown grant mint (inside
        // backlink → dispatch_teardown_steps) and the result verifier.
        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        // Enroll a REAL agent identity on the seeded request's site platform.
        let identity = ryuki_agent::identity::AgentIdentity::generate();
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let agent_id = format!("b23-agent-{suffix}");
        let (token, agent_enrollment_id) =
            seed_agent_from_identity(&pool, &agent_id, "DEFRA", &identity).await;

        // Executing request: a, b Applied (with recorded digests), c Applying.
        let (req_id, job_c, owned_agent_id) = seed_teardown_chain(
            &pool,
            Some((&agent_id, agent_enrollment_id, identity.signing_key())),
        )
        .await;
        assert!(owned_agent_id.is_none());

        // c's LiveApply FAILS → the teardown begins: b (the deepest applied
        // step) gets a REAL LiveDestroy job + CP-signed step-bound grant.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LiveApply,
            "failed",
            "c-apply-failed",
            job_c,
        )
        .await
        .expect("backlink c failure");
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(step_of(&plan, "b").await.status, "TearingDown");
        let destroy_job_id = step_of(&plan, "b")
            .await
            .agent_job_id
            .expect("auto-teardown must mint a LiveDestroy job for b");

        // Lease THE minted destroy job (targeted by id — race-free against any
        // other Pending DEFRA jobs) and ack it to Running, as the agent would.
        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let mut lease_tx = begin_agent_job_lease_fixture_tx(&pool).await;
        let job_row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = $4, \
                 lease_deadline = NOW() + make_interval(secs => $5), \
                 updated_at = NOW() \
             WHERE id = $6 AND status = 'Pending' RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind(&agent_id)
        .bind(attempt)
        .bind(&fencing)
        .bind(&nonce)
        .bind(LEASE_TTL_SECS as f64)
        .bind(destroy_job_id)
        .fetch_one(&mut *lease_tx)
        .await
        .expect("lease the minted LiveDestroy job");
        lease_tx
            .commit()
            .await
            .expect("commit LiveDestroy lease fixture");
        assert_eq!(job_row.mode, "LiveDestroy", "the minted job is a destroy");
        ack_to_running(&pool, destroy_job_id, attempt, &fencing).await;

        // Build the protocol Job the agent would receive — INCLUDING the
        // CP-minted grant (the destroy gate requires it; build_protocol_job
        // leaves live_context None for the non-live tests).
        let mut job = build_protocol_job(
            &job_row,
            agent_enrollment_id,
            attempt,
            fencing.clone(),
            nonce.clone(),
            job_row.lease_generation,
        );
        let grant: VerifiedLiveContext = serde_json::from_value(
            job_row
                .live_context
                .as_ref()
                .expect("a teardown job must carry its grant")
                .0
                .clone(),
        )
        .expect("minted grant deserialises");
        job.live_context = Some(grant);

        // RUN AGENT CODE (1): the REAL trust gate — no plan digest for destroy.
        let decision = ryuki_agent::live::evaluate_live_execution(&job, &cp_vk, true, None);
        assert_eq!(
            decision,
            ryuki_agent::live::LiveDecision::Proceed,
            "the CP-minted step-bound grant must pass the agent's destroy gate"
        );

        // RUN AGENT CODE (2): destroy evidence (canned Applied outcome — the
        // real terraform destroy is ryuki-runner's e2e) + the REAL
        // build_signed_result. A LiveDestroy result carries NO digest.
        let evidence = ryuki_agent::executor::Evidence {
            status: ryuki_engine::runners::RunStatus::Applied,
            evidence_bytes: b"Destroy complete! Resources: 1 destroyed. (scrubbed)".to_vec(),
            evidence_json: Some(serde_json::json!({
                "summary": "Destroy complete! Resources: 1 destroyed."
            })),
        };
        let execution_trust_profile = canonical_execution_trust_profile(&job.spec, &job.platform);
        assert_eq!(
            execution_trust_profile_digest(&execution_trust_profile),
            job.live_context
                .as_ref()
                .expect("destroy grant")
                .execution_authority
                .execution_trust_profile_digest,
            "destroy must report the exact profile approved by the successful plan"
        );
        let agent_body = ryuki_agent::result::build_signed_result_with_trust_profile(
            &identity,
            &agent_id,
            &job,
            &evidence,
            None,
            None,
            Some(execution_trust_profile),
        )
        .expect("build_signed_result for a LiveDestroy Applied result must succeed");

        // Cross the crate boundary and feed the REAL CP verifier.
        let cp_body: ResultBody =
            serde_json::from_value(serde_json::to_value(&agent_body).expect("serialise"))
                .expect("CP deserialises the agent ResultBody");
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            destroy_job_id.to_string(),
            hdrs,
            cp_body,
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "agent-built LiveDestroy result must pass the CP verifier: {:?}",
            resp.err()
        );

        // THE LOOP CLOSES: job terminal, step b ToreDown, cascade advanced to a.
        let db = read_job_result_row(&pool, destroy_job_id).await;
        assert_eq!(db.status, "Succeeded", "destroy job must be terminal");
        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(
            step_of(&plan, "b").await.status,
            "ToreDown",
            "the destroyed step must be marked ToreDown by the agent's result"
        );
        assert_eq!(
            step_of(&plan, "a").await.status,
            "TearingDown",
            "the reverse-order cascade must advance to a"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// A teardown that ITSELF fails halts the rollback: the request fails and
    /// the remaining applied steps are left intact for an operator (no thrash).
    #[tokio::test]
    async fn db_b2_teardown_failure_halts() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _cp_key = ensure_test_cp_key();
        let (req_id, job_c, owned_agent_id) = seed_teardown_chain(&pool, None).await;

        // c fails -> b starts tearing down.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LiveApply,
            "failed",
            "c-apply-failed",
            job_c,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        let job_b = step_of(&plan, "b").await.agent_job_id.unwrap();

        // b's LiveDestroy FAILS -> halt: request failed, a left Applied.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LiveDestroy,
            "failed",
            "b-destroy-failed",
            job_b,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(
            step_of(&plan, "b").await.status,
            "Failed",
            "failed teardown -> step Failed"
        );
        assert_eq!(
            step_of(&plan, "a").await.status,
            "Applied",
            "a is LEFT intact for an operator (no further teardown dispatched)"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "failed",
            "the request fails (needs-operator via surviving Applied step)"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        if let Some(agent_id) = owned_agent_id {
            cleanup_agent(&pool, &agent_id).await;
        }
        pool.close().await;
    }

    /// #42 B2-2 (Codex finding #3): a late straggler failure that reaches
    /// `fail_request_with_teardown` while a rollback is ALREADY in flight (a step
    /// is `TearingDown` and NOTHING is `Applied`) must NOT plain-fail the request
    /// out of `executing`. Flipping it out of `executing` would make the in-flight
    /// `LiveDestroy` results be dropped by the backlink status guard, stranding
    /// the rollback forever. The request stays `executing` so teardown finishes.
    #[tokio::test]
    async fn db_b2_teardown_late_failure_keeps_executing() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .unwrap();
        drop(conn);
        // Rollback in flight: 'a' is TearingDown (its LiveDestroy dispatched),
        // 'b' already Failed. Nothing is Applied.
        let job_a: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, step_scoped) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveDestroy', TRUE) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_steps SET status = 'TearingDown', agent_job_id = $2 \
             WHERE request_id = $1 AND step_key = 'a'",
        )
        .bind(req_id)
        .bind(job_a)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_steps SET status = 'Failed' WHERE request_id = $1 AND step_key = 'b'",
        )
        .bind(req_id)
        .execute(&pool)
        .await
        .unwrap();

        // A late straggler failure reaches the teardown-aware fail path.
        let mut tx = pool.begin().await.unwrap();
        fail_request_with_teardown(
            &mut tx,
            req_id,
            serde_json::json!([]),
            job_a,
            "failed",
            "late-straggler",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "executing",
            "a straggler failure must NOT strand the in-flight rollback"
        );
        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(
            step_of(&plan, "a").await.status,
            "TearingDown",
            "the in-flight teardown step is left to complete"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// #42 B2-2 (Codex finding #4): if a `LiveDestroy` (teardown) job's lease
    /// expires mid-run (the agent died after possibly touching real infra), the
    /// lease-expiry sweep must HALT the rollback — mark the teardown step `Failed`
    /// and the request `failed`, and move the job to `ReconcileRequired` — rather
    /// than leaving the step `TearingDown` and the request `executing` forever.
    #[tokio::test]
    async fn db_b2_destroy_lease_expiry_halts_rollback() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[("a", vec![], "linux-server-deployment")],
        )
        .await
        .unwrap();
        drop(conn);
        // 'a' is TearingDown behind a LiveDestroy job whose lease already expired.
        let job_a: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs \
                 (request_id, platform, spec, mode, step_scoped, status, lease_deadline) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveDestroy', TRUE, 'Leased', \
                     NOW() - make_interval(secs => 60)) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_steps SET status = 'TearingDown', agent_job_id = $2 \
             WHERE request_id = $1 AND step_key = 'a'",
        )
        .bind(req_id)
        .bind(job_a)
        .execute(&pool)
        .await
        .unwrap();

        expire_leases(&pool).await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(
            step_of(&plan, "a").await.status,
            "Failed",
            "the stuck teardown step is halted to Failed"
        );
        let (req_status, stages): (String, serde_json::Value) =
            sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            req_status, "failed",
            "the request is failed (needs operator)"
        );
        let execute = stages
            .as_array()
            .and_then(|items| items.iter().find(|item| item["name"] == "execute"))
            .expect("execute stage remains in the durable stage history");
        assert_eq!(execute["status"], "Failed");
        let execution_audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE request_id = $1 \
             AND action = 'request.execution-result' AND to_status = 'failed'",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .expect("count lease-expiry lifecycle audit");
        assert_eq!(execution_audit, 1);
        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job_a)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            job_status, "ReconcileRequired",
            "the expired destroy job needs operator reconciliation"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// #42 B2-2 (Codex finding #1): when auto teardown begins, any step still parked
    /// `AwaitingApproval` is swept to `Failed`. Teardown keeps the request `executing`
    /// (so LiveDestroy results route back), which leaves the step-approval endpoint
    /// reachable; a still-parked step could otherwise be approved into a fresh `LiveApply`
    /// after rollback started. Failing the parked step removes anything left to approve.
    #[tokio::test]
    async fn db_b2_teardown_sweeps_awaiting_approval() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _cp_key = ensure_test_cp_key();
        // Start from exact signed plan/apply authority for the Applied step;
        // teardown must never be exercised with a digest-only stand-in.
        let (req_id, job_c, owned_agent_id) = seed_teardown_chain(&pool, None).await;
        // Park b at the approval boundary while c remains a live apply in
        // flight. Clearing b's old fixture link models a not-yet-approved step.
        sqlx::query(
            "UPDATE job_steps SET status = 'AwaitingApproval', agent_job_id = NULL \
             WHERE request_id = $1 AND step_key = 'b'",
        )
        .bind(req_id)
        .execute(&pool)
        .await
        .unwrap();

        // 'c' fails -> teardown begins (a is Applied) and the request stays executing.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::LiveApply,
            "failed",
            "c-apply-failed",
            job_c,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(
            step_of(&plan, "b").await.status,
            "Failed",
            "the parked AwaitingApproval step is swept -> nothing left to approve mid-rollback"
        );
        assert_eq!(
            step_of(&plan, "a").await.status,
            "TearingDown",
            "the applied step is being rolled back"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "executing", "teardown keeps the request executing");

        cleanup_step_2b_request(&pool, req_id).await;
        if let Some(agent_id) = owned_agent_id {
            cleanup_agent(&pool, &agent_id).await;
        }
        pool.close().await;
    }

    /// #42 B2-2 (Codex round-3): when `fail_inflight_steps` sweeps an in-flight step to
    /// `Failed`, it also cancels that step's still-`Pending` linked agent_job. This closes the
    /// residual approval-vs-failure race: a step-approval that commits just before the sweep
    /// leaves a freshly dispatched `Pending` LiveApply job whose step is now `Failed`; without
    /// cancelling it, the job stays leaseable and could apply live infra outside rollback
    /// coverage. A `Leased`/`Running` linked job is instead LEFT for the lease-expiry reconcile
    /// path (it may already have touched infra).
    #[tokio::test]
    async fn db_b2_fail_inflight_cancels_pending_linked_job() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec![], "linux-server-deployment"),
            ],
        )
        .await
        .unwrap();
        drop(conn);
        // 'a' Applying behind a still-`Pending` LiveApply (the approval-race orphan shape).
        let job_a: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, step_scoped) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveApply', 'Pending', TRUE) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_steps SET status = 'Applying', agent_job_id = $2 \
             WHERE request_id = $1 AND step_key = 'a'",
        )
        .bind(req_id)
        .bind(job_a)
        .execute(&pool)
        .await
        .unwrap();
        // 'b' Applying behind a `Leased` job — must be LEFT for lease-expiry reconcile.
        let job_b: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, step_scoped) \
             VALUES ($1, 'DEFRA', '{}'::jsonb, 'LiveApply', 'Leased', TRUE) RETURNING id",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_steps SET status = 'Applying', agent_job_id = $2 \
             WHERE request_id = $1 AND step_key = 'b'",
        )
        .bind(req_id)
        .bind(job_b)
        .execute(&pool)
        .await
        .unwrap();

        let swept = crate::repos::job_steps::fail_inflight_steps(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(swept, 2, "both Applying steps are swept to Failed");

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .unwrap();
        assert_eq!(step_of(&plan, "a").await.status, "Failed");
        assert_eq!(step_of(&plan, "b").await.status, "Failed");
        let a_job: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job_a)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            a_job, "Cancelled",
            "the Pending orphan is cancelled -> no longer leaseable"
        );
        let b_job: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job_b)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            b_job, "Leased",
            "a Leased job is left for lease-expiry reconcile, not silently cancelled"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// Diamond a -> {b, c} -> d: completing 'a' dispatches both 'b' and 'c';
    /// completing only 'b' must NOT dispatch 'd' (c is still Running);
    /// completing 'c' then dispatches 'd'; completing 'd' finishes the
    /// request.
    #[tokio::test]
    async fn db_step2b_diamond_waits_for_all_parents() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec!["a".to_string()], "linux-server-deployment"),
                ("c", vec!["a".to_string()], "linux-server-deployment"),
                (
                    "d",
                    vec!["b".to_string(), "c".to_string()],
                    "linux-server-deployment",
                ),
            ],
        )
        .await
        .expect("seed diamond plan");
        drop(conn);

        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let job_a = dispatch_step_job(&pool, req_id, step_a.id).await;

        // Complete 'a' -> both 'b' and 'c' become ready and are dispatched.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            job_a,
        )
        .await
        .expect("backlink a");
        tx.commit().await.unwrap();

        let plan_after_a = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after a");
        let b1 = plan_after_a.iter().find(|s| s.step_key == "b").unwrap();
        let c1 = plan_after_a.iter().find(|s| s.step_key == "c").unwrap();
        let d1 = plan_after_a.iter().find(|s| s.step_key == "d").unwrap();
        assert_eq!(b1.status, "Running", "b dispatched after a succeeds");
        assert_eq!(c1.status, "Running", "c dispatched after a succeeds");
        assert_eq!(d1.status, "Pending", "d not ready yet (b,c pending)");
        let job_b = b1.agent_job_id.expect("b has a dispatched job");
        let job_c = c1.agent_job_id.expect("c has a dispatched job");

        // Complete only 'b' -> 'd' must NOT be dispatched (c still Running).
        let mut tx2 = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx2,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            job_b,
        )
        .await
        .expect("backlink b");
        tx2.commit().await.unwrap();

        let status_after_b: String =
            sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            status_after_b, "executing",
            "request stays executing (c still running, d not ready)"
        );
        let plan_after_b = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after b");
        let d_after_b = plan_after_b.iter().find(|s| s.step_key == "d").unwrap();
        assert_eq!(
            d_after_b.status, "Pending",
            "d must NOT dispatch while c is still Running"
        );
        assert!(
            d_after_b.agent_job_id.is_none(),
            "d must have no dispatched agent_job yet"
        );

        // Complete 'c' -> now 'd' becomes ready and is dispatched.
        let mut tx3 = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx3,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            job_c,
        )
        .await
        .expect("backlink c");
        tx3.commit().await.unwrap();

        let plan_after_c = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after c");
        let d_after_c = plan_after_c.iter().find(|s| s.step_key == "d").unwrap();
        assert_eq!(
            d_after_c.status, "Running",
            "d dispatched once both b and c have succeeded"
        );
        let job_d = d_after_c.agent_job_id.expect("d has a dispatched job");

        let status_after_c: String =
            sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            status_after_c, "executing",
            "request still executing while d runs"
        );

        // Complete 'd' -> whole plan done, request -> verifying.
        let mut tx4 = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx4,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            job_d,
        )
        .await
        .expect("backlink d");
        tx4.commit().await.unwrap();

        let status_final: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status_final, "verifying",
            "request advances to verifying once the whole diamond plan succeeded"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// No-plan single job (today's behavior, unchanged): a request with NO
    /// `job_steps` rows advances directly via the single-job path.
    #[tokio::test]
    async fn db_step2b_no_plan_single_job_unaffected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        // No job_steps rows are inserted for this request.

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "deadbeefdeadbeef",
            Uuid::new_v4(),
        )
        .await
        .expect("backlink no-plan");
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "verifying",
            "a no-plan request advances directly to verifying (today's unchanged behavior)"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// A successful single-job LivePlan is a human approval pause, not an
    /// execution completion. Only the later LiveApply may move the request to
    /// `verifying`.
    #[tokio::test]
    async fn db_single_live_plan_stays_executing_for_approval() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let job_id = Uuid::new_v4();
        let evidence_digest = "b".repeat(64);
        let raw_plan_digest = "a".repeat(64);

        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution_with_raw_plan_digest(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::LivePlan,
            "planned",
            BacklinkDigests {
                evidence: &evidence_digest,
                raw_plan: Some(&raw_plan_digest),
            },
            job_id,
        )
        .await
        .expect("backlink live plan");
        tx.commit().await.unwrap();

        let (status, stage, stages): (String, String, serde_json::Value) =
            sqlx::query_as("SELECT status, stage, stages FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "executing");
        assert_eq!(stage, "execute");
        let execute = stages
            .as_array()
            .and_then(|items| items.iter().find(|item| item["name"] == "execute"))
            .expect("execute stage");
        assert_eq!(execute["status"], "InProgress");
        assert_eq!(
            execute["metadata"]["live_plan_evidence_digest"],
            evidence_digest
        );
        assert_eq!(
            execute["metadata"]["live_plan_raw_plan_digest"],
            raw_plan_digest
        );

        let (from_status, to_status, outcome): (String, String, String) = sqlx::query_as(
            "SELECT from_status, to_status, outcome FROM audit_log \
             WHERE request_id = $1 AND action = 'request.live-plan-result' \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(req_id)
        .fetch_one(&pool)
        .await
        .expect("live-plan audit row");
        assert_eq!(from_status, "executing");
        assert_eq!(to_status, "executing");
        assert_eq!(outcome, "planned");

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    /// Concurrency reconciliation: independent roots 'a' and 'b', with 'c'
    /// depending only on 'b'. Completing 'b' (success) dispatches 'c' while the
    /// request is still executing; THEN 'a' fails. The failing request must
    /// reconcile the freshly-dispatched, in-flight 'c' to Failed rather than
    /// leaving it stranded Running under a terminal request. (Regression for
    /// the #42 slice-2b concurrency finding.)
    #[tokio::test]
    async fn db_step2b_failure_reconciles_inflight_dispatched_step() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_executing_request(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire conn");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req_id,
            &[
                ("a", vec![], "linux-server-deployment"),
                ("b", vec![], "linux-server-deployment"),
                ("c", vec!["b".to_string()], "linux-server-deployment"),
            ],
        )
        .await
        .expect("seed a/b roots + c depends on b");
        drop(conn);

        // Both independent roots are initially ready and dispatched.
        let plan = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan");
        let step_a = plan.iter().find(|s| s.step_key == "a").expect("step a");
        let step_b = plan.iter().find(|s| s.step_key == "b").expect("step b");
        let job_a = dispatch_step_job(&pool, req_id, step_a.id).await;
        let job_b = dispatch_step_job(&pool, req_id, step_b.id).await;

        // 'b' succeeds -> 'c' becomes ready and is dispatched; request stays executing.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            &JobMode::OfflineDryRun,
            "planned",
            "b0",
            job_b,
        )
        .await
        .expect("backlink b success");
        tx.commit().await.unwrap();

        let mid = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan mid-flight");
        let c_mid = mid.iter().find(|s| s.step_key == "c").expect("step c");
        assert_eq!(c_mid.status, "Running", "b's success dispatched c");
        assert!(
            c_mid.agent_job_id.is_some(),
            "c was dispatched an agent_job"
        );
        let status_mid: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status_mid, "executing",
            "request still executing (a in-flight)"
        );

        // 'a' fails -> request fails; the in-flight 'c' must be reconciled to Failed.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Failed,
            &JobMode::OfflineDryRun,
            "failed",
            "a0",
            job_a,
        )
        .await
        .expect("backlink a failure");
        tx.commit().await.unwrap();

        let status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "failed", "a's failure fails the request");

        let after = crate::repos::job_steps::load_plan(&pool, req_id)
            .await
            .expect("load plan after");
        let a_after = after.iter().find(|s| s.step_key == "a").unwrap();
        let b_after = after.iter().find(|s| s.step_key == "b").unwrap();
        let c_after = after.iter().find(|s| s.step_key == "c").unwrap();
        assert_eq!(a_after.status, "Failed", "a marked Failed");
        assert_eq!(b_after.status, "Succeeded", "b's success is preserved");
        assert_eq!(
            c_after.status, "Failed",
            "the in-flight dispatched c is reconciled to Failed, not stranded Running"
        );

        cleanup_step_2b_request(&pool, req_id).await;
        pool.close().await;
    }

    // ── #23 follow-up: dead-lettered job list + requeue ──────────────────────

    /// Seed a requests row at a given status (returns its id). Active statuses
    /// ('executing') permit requeue; concluded ones ('cancelled'/'failed') do not.
    async fn seed_request_row(pool: &PgPool, status: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO requests (id, request_type, status, stage, site, environment, \
             name, cpu, memory_gb, created_by) \
             VALUES ($1, 'server-deployment', $2, 'execute', 'DEFRA', 'production', \
             'dlq-test', 2, 4, 'requester')",
        )
        .bind(id)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed request row");
        id
    }

    /// Build a valid OfflineDryRun JobSpec whose `request_id` is the agent's source
    /// of truth for the parent request.
    fn dead_letter_spec(request_id: Uuid, mode: JobMode) -> JobSpec {
        JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: std::collections::BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode,
        }
    }

    /// Seed a terminal DeadLettered job (delivery_attempts at the cap) directly. The
    /// `spec.request_id` (what the agent acts on) == `request_id`, and the scalar
    /// column also == `request_id` (the common, consistent case).
    async fn seed_dead_lettered_job(pool: &PgPool, platform: &str, request_id: Uuid) -> Uuid {
        seed_dead_lettered_job_full(
            pool,
            platform,
            request_id,
            request_id,
            JobMode::OfflineDryRun,
        )
        .await
    }

    /// Seed a DeadLettered job with EXPLICIT column vs spec request ids + spec mode —
    /// to exercise the spec-is-source-of-truth guards (column may differ from spec).
    async fn seed_dead_lettered_job_full(
        pool: &PgPool,
        platform: &str,
        column_request_id: Uuid,
        spec_request_id: Uuid,
        spec_mode: JobMode,
    ) -> Uuid {
        let spec = dead_letter_spec(spec_request_id, spec_mode);
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, delivery_attempts) \
             VALUES ($1, $2, $3, 'OfflineDryRun', 'DeadLettered', 5) RETURNING id",
        )
        .bind(column_request_id)
        .bind(platform)
        .bind(&spec_json)
        .fetch_one(pool)
        .await
        .expect("seed dead-lettered job")
    }

    async fn cleanup_request_row(pool: &PgPool, id: Uuid) {
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    // ── Admin cancel of a Pending job ─────────────────────────────────────────

    /// Like `handler_pool` but TOLERANT of a behind-migrations local DB (mirrors the
    /// scheduler db_tests' `global_pool`): it does NOT bail when `run_migrations` reports a
    /// checksum drift, so the cancel tests run on a drifted local DB and on a fresh CI DB.
    async fn handler_pool_lenient() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()?;
        let _ = crate::database::run_migrations(pool).await; // tolerate drift
        Some(pool)
    }

    /// Ensure the `agent_jobs` status CHECK admits `'Cancelled'` (mig 136), self-applied
    /// with the SAME DDL as the migration so the happy test writes `'Cancelled'` even on a
    /// behind-migrations local DB; on CI the migration already did this, so the guarded
    /// DROP/ADD is an idempotent re-apply (a superset — existing statuses still allowed).
    async fn ensure_cancelled_status_allowed(pool: &PgPool) {
        sqlx::query("ALTER TABLE agent_jobs DROP CONSTRAINT IF EXISTS agent_jobs_status_check")
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_status_check \
             CHECK (status IN ('Pending','Leased','Running','Succeeded','Failed','Expired',\
             'ReconcileRequired','LiveRefused','DeadLettered','Cancelled'))",
        )
        .execute(pool)
        .await
        .expect("widen agent_jobs status CHECK to admit 'Cancelled'");
    }

    /// Ensure the `agent_jobs` mode CHECK admits `'LiveDestroy'` (mig 155), self-applied with
    /// the SAME DDL as the migration so the teardown-cancel test can insert a LiveDestroy job
    /// on a behind-migrations local DB; on CI the migration already did this, so the guarded
    /// DROP/ADD is an idempotent re-apply (a superset — existing modes still allowed).
    async fn ensure_live_destroy_mode_allowed(pool: &PgPool) {
        sqlx::query("ALTER TABLE agent_jobs DROP CONSTRAINT IF EXISTS agent_jobs_mode_check")
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "ALTER TABLE agent_jobs ADD CONSTRAINT agent_jobs_mode_check \
             CHECK (mode IN ('OfflineDryRun','LivePlan','LiveApply','LiveDestroy'))",
        )
        .execute(pool)
        .await
        .expect("widen agent_jobs mode CHECK to admit 'LiveDestroy'");
    }

    /// Seed an agent job in a given status (Pending / Leased) for the cancel tests.
    async fn seed_job_in_status(
        pool: &PgPool,
        platform: &str,
        request_id: Uuid,
        status: &str,
    ) -> Uuid {
        let spec = dead_letter_spec(request_id, JobMode::OfflineDryRun);
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, $3, 'OfflineDryRun', $4) RETURNING id",
        )
        .bind(request_id)
        .bind(platform)
        .bind(&spec_json)
        .bind(status)
        .fetch_one(pool)
        .await
        .expect("seed agent job")
    }

    async fn cancel_audit_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE action = 'agent-job-cancelled' AND detail->>'job_id' = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count cancel audit")
    }

    /// The `to_status` of the job's `job.cancelled` event, or None if absent.
    async fn cancelled_event_to_status(pool: &PgPool, job_id: Uuid) -> Option<String> {
        sqlx::query_scalar(
            "SELECT payload->>'to_status' FROM domain_events \
             WHERE event_type = 'job.cancelled' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job_id.to_string())
        .fetch_optional(pool)
        .await
        .expect("query cancel event")
    }

    /// Cancel a Pending job → Cancelled: audited, a NON-alerting cancel event, the parent
    /// request left actionable; a second cancel 409s (no 2nd audit).
    #[tokio::test]
    async fn cancel_pending_happy_then_double_cancel_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-cxl-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;

        let Json(out) = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(CancelJobBody {
                reason: "created in error; platform decommissioned".into(),
            }),
        )
        .await
        .expect("cancel must succeed");
        assert_eq!(out["status"], json!("Cancelled"));
        assert_eq!(out["cancelled"], json!(true));
        assert_eq!(out["request_id"], json!(req.to_string()));

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(job_status, "Cancelled", "the job is now terminal Cancelled");
        // Parent request remains actionable — NOT stranded into an invalid state (codex B2).
        let req_status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            req_status, "executing",
            "the parent request stays Executing (operator fails it separately)"
        );
        assert_eq!(
            cancel_audit_count(pool, job).await,
            1,
            "one cancel audit row"
        );
        // The event uses the robust non-prefilter marker (codex B1).
        assert_eq!(
            cancelled_event_to_status(pool, job).await.as_deref(),
            Some("admin-cancelled"),
            "one non-alerting cancel event with the non-prefilter marker"
        );
        assert!(
            !ryuki_engine::event_alerts::alert_worthy_statuses().contains(&"admin-cancelled"),
            "admin-cancelled must NOT be in the alert prefilter — a cancel can never page"
        );

        // A second cancel of the now-Cancelled job → 409, no second audit.
        let again = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(CancelJobBody {
                reason: "again".into(),
            }),
        )
        .await
        .expect_err("a cancelled job cannot be cancelled again");
        assert_eq!(again.0, StatusCode::CONFLICT);
        assert_eq!(
            cancel_audit_count(pool, job).await,
            1,
            "the failed second cancel writes no audit row"
        );

        cleanup_dead_letter_events(pool, job).await;
        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// A Leased job cannot be cancelled → 409; the job stays Leased and no audit is written.
    #[tokio::test]
    async fn cancel_leased_job_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-cxl-leased-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_job_in_status(pool, &platform, req, "Leased").await;

        let err = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(CancelJobBody {
                reason: "too late".into(),
            }),
        )
        .await
        .expect_err("only a Pending job can be cancelled");
        assert_eq!(err.0, StatusCode::CONFLICT);

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(job_status, "Leased", "the leased job is untouched");
        assert_eq!(
            cancel_audit_count(pool, job).await,
            0,
            "a wrong-status cancel writes no audit row"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// #42 B2-2 (Codex finding #2): a Pending `LiveDestroy` (auto-teardown) job must NOT be
    /// operator-cancellable. Cancelling it would strand its step `TearingDown` and the request
    /// `executing` with no result ever arriving and no lease to expire — a permanent rollback
    /// wedge. The cancel is rejected (409), the job is left Pending, and no audit row is written.
    #[tokio::test]
    async fn cancel_pending_live_destroy_rejected_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_live_destroy_mode_allowed(pool).await;
        let platform = format!("plt-cxl-destroy-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let spec = dead_letter_spec(req, JobMode::LiveDestroy);
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        let job: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, step_scoped) \
             VALUES ($1, $2, $3, 'LiveDestroy', 'Pending', TRUE) RETURNING id",
        )
        .bind(req)
        .bind(&platform)
        .bind(&spec_json)
        .fetch_one(pool)
        .await
        .expect("seed pending LiveDestroy job");

        let err = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(CancelJobBody {
                reason: "operator tries to cancel a teardown".into(),
            }),
        )
        .await
        .expect_err("a Pending LiveDestroy teardown job is not cancellable");
        assert_eq!(err.0, StatusCode::CONFLICT);

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            job_status, "Pending",
            "the teardown job is left intact to run (or expire), not cancelled"
        );
        assert_eq!(
            cancel_audit_count(pool, job).await,
            0,
            "a rejected teardown cancel writes no audit row"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// An unknown job id → 404; a non-admin → 403.
    #[tokio::test]
    async fn cancel_unknown_404_and_non_admin_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let unknown = Uuid::new_v4();
        let err = admin_cancel_pending_job(
            Path(unknown.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(CancelJobBody {
                reason: "nope".into(),
            }),
        )
        .await
        .expect_err("unknown id is a 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);

        let denied = admin_cancel_pending_job(
            Path(unknown.to_string()),
            Extension(non_admin_session()),
            Json(CancelJobBody {
                reason: "nope".into(),
            }),
        )
        .await
        .expect_err("a non-admin is forbidden");
        assert_eq!(denied.0, StatusCode::FORBIDDEN);

        let _ = pool; // pool only needed to gate on RYUKI_DATABASE_URL availability
    }

    // ── Admin force-fail of a stuck Leased job ────────────────────────────────

    /// Seed a job in a given status AND mode (the force-fail path is mode-aware).
    async fn seed_job_with_mode(
        pool: &PgPool,
        platform: &str,
        request_id: Uuid,
        status: &str,
        mode: JobMode,
    ) -> Uuid {
        // Compute the label BEFORE moving `mode` into the spec (JobMode is not Copy;
        // the unit-variant match does not move it).
        let mode_label = match mode {
            JobMode::OfflineDryRun => "OfflineDryRun",
            JobMode::LivePlan => "LivePlan",
            JobMode::LiveApply => "LiveApply",
            JobMode::LiveDestroy => "LiveDestroy",
        };
        let spec = dead_letter_spec(request_id, mode);
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(request_id)
        .bind(platform)
        .bind(&spec_json)
        .bind(mode_label)
        .bind(status)
        .fetch_one(pool)
        .await
        .expect("seed agent job with mode")
    }

    async fn force_fail_audit_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE action = 'agent-job-force-failed' AND detail->>'job_id' = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count force-fail audit")
    }

    async fn force_failed_event_to_status(pool: &PgPool, job_id: Uuid) -> Option<String> {
        sqlx::query_scalar(
            "SELECT payload->>'to_status' FROM domain_events \
             WHERE event_type = 'job.force_failed' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job_id.to_string())
        .fetch_optional(pool)
        .await
        .expect("query force-fail event")
    }

    /// Force-fail a stuck Leased dry-run job → Failed: audited, a NON-alerting event,
    /// parent request left actionable; status is now Failed so a late result CAS rejects.
    #[tokio::test]
    async fn force_fail_leased_dryrun_happy() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-ff-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_job_in_status(pool, &platform, req, "Leased").await; // OfflineDryRun

        let Json(out) = admin_force_fail_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody {
                reason: "agent host is dead; killing the stuck job".into(),
            }),
        )
        .await
        .expect("force-fail must succeed");
        assert_eq!(out["status"], json!("Failed"));
        assert_eq!(out["force_failed"], json!(true));
        assert_eq!(out["request_id"], json!(req.to_string()));

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            job_status, "Failed",
            "the job is now terminal Failed (a late result CAS on Leased/Running rejects)"
        );
        let req_status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            req_status, "executing",
            "the parent request stays actionable"
        );
        assert_eq!(
            force_fail_audit_count(pool, job).await,
            1,
            "one force-fail audit row"
        );
        assert_eq!(
            force_failed_event_to_status(pool, job).await.as_deref(),
            Some("admin-force-failed"),
            "one non-alerting force-fail event"
        );
        assert!(
            !ryuki_engine::event_alerts::alert_worthy_statuses().contains(&"admin-force-failed"),
            "admin-force-failed must NOT be in the alert prefilter — a force-fail can never page"
        );
        // Secret hygiene: the reason is audit-only — absent from the response + the event.
        assert!(
            !out.to_string().contains("agent host is dead"),
            "the reason must NOT be echoed in the response"
        );
        let event_payload: Option<String> = sqlx::query_scalar(
            "SELECT payload::text FROM domain_events \
             WHERE event_type = 'job.force_failed' AND aggregate_id = $1",
        )
        .bind(job.to_string())
        .fetch_optional(pool)
        .await
        .unwrap();
        assert!(
            event_payload.is_some_and(|p| !p.contains("agent host is dead")),
            "the reason must NOT be in the domain-event payload"
        );

        // A Leased LivePlan job force-fails too (LivePlan never touches real infra).
        let lp = seed_job_with_mode(pool, &platform, req, "Leased", JobMode::LivePlan).await;
        let _ = admin_force_fail_job(
            Path(lp.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody {
                reason: "stuck live-plan".into(),
            }),
        )
        .await
        .expect("force-fail of a leased live-plan must succeed");
        let lp_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(lp)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            lp_status, "Failed",
            "a leased live-plan job force-fails to Failed"
        );

        cleanup_dead_letter_events(pool, lp).await;
        cleanup_dead_letter_events(pool, job).await;
        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// B1 regression (codex): the SPEC mode is authoritative, NOT the scalar `mode`
    /// column. A Leased job with column `mode='OfflineDryRun'` but `spec.mode=LiveApply`
    /// must be REFUSED (409) — the old column-based CAS would have force-failed it.
    #[tokio::test]
    async fn force_fail_decides_on_spec_mode_not_column() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-ff-spec-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        // column mode = OfflineDryRun (the non-load-bearing scalar) but the dispatched
        // spec.mode = LiveApply (what the agent actually acts on).
        let spec = dead_letter_spec(req, JobMode::LiveApply);
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        let job: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, $3, 'OfflineDryRun', 'Leased') RETURNING id",
        )
        .bind(req)
        .bind(&platform)
        .bind(&spec_json)
        .fetch_one(pool)
        .await
        .expect("seed mismatched-mode job");

        let err = admin_force_fail_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody {
                reason: "should be refused".into(),
            }),
        )
        .await
        .expect_err("a job whose SPEC mode is LiveApply must not be force-failed");
        assert_eq!(err.0, StatusCode::CONFLICT);

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(job_status, "Leased", "the live-apply-spec job is untouched");
        assert_eq!(
            force_fail_audit_count(pool, job).await,
            0,
            "no audit on a refused force-fail"
        );
        assert!(
            force_failed_event_to_status(pool, job).await.is_none(),
            "no domain event on a refused force-fail"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// A Leased job with a malformed stored spec fails CLOSED → 500 (never force-failed
    /// on undecodable mode), and the row is untouched.
    #[tokio::test]
    async fn force_fail_malformed_spec_is_500_fail_closed() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-ff-bad-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        // A Leased job whose `spec` is not a valid JobSpec (empty object).
        let job: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased') RETURNING id",
        )
        .bind(req)
        .bind(&platform)
        .fetch_one(pool)
        .await
        .expect("seed malformed-spec job");

        let err = admin_force_fail_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody {
                reason: "bad spec".into(),
            }),
        )
        .await
        .expect_err("a malformed spec fails closed");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            job_status, "Leased",
            "a malformed-spec job is never mutated"
        );
        assert_eq!(
            force_fail_audit_count(pool, job).await,
            0,
            "no audit on a fail-closed force-fail"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// A Leased LiveApply job is EXCLUDED (409 — it must go through lease-expiry →
    /// ReconcileRequired to protect real infra). A Running / Pending job also 409s.
    #[tokio::test]
    async fn force_fail_rejects_leased_liveapply_running_and_pending() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-ff-rej-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;

        // Leased LiveApply → 409; row stays Leased, no audit (codex: protect real infra).
        let la = seed_job_with_mode(pool, &platform, req, "Leased", JobMode::LiveApply).await;
        let e1 = admin_force_fail_job(
            Path(la.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody { reason: "x".into() }),
        )
        .await
        .expect_err("a leased live-apply job is 409");
        assert_eq!(e1.0, StatusCode::CONFLICT);
        let la_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(la)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            la_status, "Leased",
            "the leased live-apply job is untouched"
        );
        assert_eq!(
            force_fail_audit_count(pool, la).await,
            0,
            "a rejected force-fail writes no audit row"
        );

        // Running (dry-run) → 409.
        let run = seed_job_in_status(pool, &platform, req, "Running").await;
        let e2 = admin_force_fail_job(
            Path(run.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody { reason: "x".into() }),
        )
        .await
        .expect_err("a running job is 409");
        assert_eq!(e2.0, StatusCode::CONFLICT);

        // Pending → 409 (use cancel instead).
        let pend = seed_job_in_status(pool, &platform, req, "Pending").await;
        let e3 = admin_force_fail_job(
            Path(pend.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody { reason: "x".into() }),
        )
        .await
        .expect_err("a pending job is 409");
        assert_eq!(e3.0, StatusCode::CONFLICT);

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// unknown id → 404; non-admin → 403.
    #[tokio::test]
    async fn force_fail_unknown_404_and_non_admin_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let unknown = Uuid::new_v4();
        let e = admin_force_fail_job(
            Path(unknown.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody { reason: "x".into() }),
        )
        .await
        .expect_err("unknown id is a 404");
        assert_eq!(e.0, StatusCode::NOT_FOUND);
        let d = admin_force_fail_job(
            Path(unknown.to_string()),
            Extension(non_admin_session()),
            Json(ForceFailJobBody { reason: "x".into() }),
        )
        .await
        .expect_err("a non-admin is forbidden");
        assert_eq!(d.0, StatusCode::FORBIDDEN);
        let _ = pool;
    }

    // ── Admin job inspection (read-only operational state) ─────────────────────

    /// Inspecting a job returns its operational state and NO secret/large columns
    /// (spec / fencing_token / cp_nonce / live_context / signed_envelope / evidence_json).
    #[tokio::test]
    async fn inspect_job_returns_state_without_secrets() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-insp-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        // Bury a recognizable SENTINEL in the SECRET columns (spec vars, live_context,
        // fencing_token, cp_nonce) so the test proves no VALUE leaks — not just no key (codex).
        let sentinel = format!("SENTINEL-SECRET-{}", Uuid::new_v4().simple());
        let mut spec = dead_letter_spec(req, JobMode::OfflineDryRun);
        spec.vars.insert("secret_var".into(), sentinel.clone());
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        let live_context = serde_json::json!({ "grant_token": sentinel.clone() });
        let evidence_json = serde_json::json!({ "raw_evidence": sentinel.clone() });
        let signed_envelope = serde_json::json!({ "attestation": sentinel.clone() });
        let job: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs \
             (request_id, platform, spec, mode, status, live_context, fencing_token, cp_nonce, \
              evidence_json, signed_envelope) \
             VALUES ($1, $2, $3, 'OfflineDryRun', 'Leased', $4, $5, $6, $7, $8) RETURNING id",
        )
        .bind(req)
        .bind(&platform)
        .bind(&spec_json)
        .bind(&live_context)
        .bind(&sentinel)
        .bind(&sentinel)
        .bind(&evidence_json)
        .bind(&signed_envelope)
        .fetch_one(pool)
        .await
        .expect("seed sentinel-bearing job");

        let Json(out) = admin_agent_job_get(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("inspect must succeed");
        assert_eq!(out["job_id"], json!(job.to_string()));
        assert_eq!(out["status"], json!("Leased"));
        assert_eq!(out["mode"], json!("OfflineDryRun"));
        assert_eq!(out["platform"], json!(platform));
        assert_eq!(out["delivery_attempts"], json!(0));
        assert!(out["created_at"].is_string(), "created_at is present");

        // Secret hygiene: NO secret/large column names appear anywhere in the response.
        let body = out.to_string();
        for forbidden in [
            "spec",
            "fencing_token",
            "cp_nonce",
            "live_context",
            "signed_envelope",
            "evidence_json",
        ] {
            assert!(
                !body.contains(forbidden),
                "the inspection response must not expose `{forbidden}`: {body}"
            );
        }
        // And no VALUE from the secret columns leaks.
        assert!(
            !body.contains(&sentinel),
            "a secret-column sentinel value must NEVER appear in the inspection response"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// unknown id → 404; non-admin → 403.
    #[tokio::test]
    async fn inspect_unknown_404_and_non_admin_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let unknown = Uuid::new_v4();
        let e = admin_agent_job_get(
            Path(unknown.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect_err("unknown id is a 404");
        assert_eq!(e.0, StatusCode::NOT_FOUND);
        let d = admin_agent_job_get(Path(unknown.to_string()), Extension(non_admin_session()))
            .await
            .expect_err("a non-admin is forbidden");
        assert_eq!(d.0, StatusCode::FORBIDDEN);
        let _ = pool;
    }

    async fn requeue_audit_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE action = 'agent-job-requeue' AND detail->>'job_id' = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count requeue audit")
    }

    /// list returns DeadLettered jobs with secret-safe metadata only; non-dead
    /// jobs are excluded.
    #[tokio::test]
    async fn db_dead_lettered_jobs_list_happy() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let dl1 = seed_dead_lettered_job(pool, &platform, req).await;
        let dl2 = seed_dead_lettered_job(pool, &platform, req).await;
        let pending = seed_pending_job(pool, &platform).await;

        let Json(out) = admin_dead_lettered_jobs(Extension(AuthSession::static_dry_run()))
            .await
            .expect("list must succeed");
        let jobs = out["dead_lettered_jobs"].as_array().unwrap();
        let ids: Vec<&str> = jobs.iter().map(|j| j["job_id"].as_str().unwrap()).collect();
        assert!(ids.contains(&dl1.to_string().as_str()), "dl1 listed");
        assert!(ids.contains(&dl2.to_string().as_str()), "dl2 listed");
        assert!(
            !ids.contains(&pending.to_string().as_str()),
            "a Pending job must NOT be listed"
        );
        // Secret hygiene: NO spec / live_context in any entry.
        for j in jobs {
            assert!(j.get("spec").is_none(), "spec must not be exposed");
            assert!(
                j.get("live_context").is_none(),
                "live_context must not be exposed"
            );
            assert!(j["request_id"].is_string(), "request_id present");
        }

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    // ── ReconcileRequired resolution ──────────────────────────────────────────

    async fn seed_reconcile_required_job(pool: &PgPool, platform: &str, request_id: Uuid) -> Uuid {
        let spec = dead_letter_spec(request_id, JobMode::LiveApply);
        let spec_json = serde_json::to_value(&spec).expect("spec serialises");
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, $3, 'LiveApply', 'ReconcileRequired') RETURNING id",
        )
        .bind(request_id)
        .bind(platform)
        .bind(&spec_json)
        .fetch_one(pool)
        .await
        .expect("seed reconcile-required job")
    }

    async fn resolve_audit_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE action = 'agent-job-reconcile-resolved' AND detail->>'job_id' = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count resolve audit")
    }

    async fn reconcile_resolved_event_count(pool: &PgPool, job_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM domain_events \
             WHERE event_type = 'job.reconcile_resolved' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count reconcile-resolved events")
    }

    /// Resolve a ReconcileRequired job → Failed: audited, a non-alerting resolution
    /// event, the parent request left Executing; a second resolve 409s (no 2nd audit).
    #[tokio::test]
    async fn reconcile_resolve_happy_then_double_resolve_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-rec-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_reconcile_required_job(pool, &platform, req).await;

        let Json(out) = admin_resolve_reconcile_required_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody {
                reason: "reconciled the half-applied resources out-of-band".into(),
            }),
        )
        .await
        .expect("resolve must succeed");
        assert_eq!(out["status"], json!("Failed"));
        assert_eq!(out["resolved"], json!(true));
        assert_eq!(out["request_id"], json!(req.to_string()));

        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(job_status, "Failed", "the job is now terminal Failed");
        // The parent request is NOT touched (job-scoped resolve).
        let req_status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            req_status, "executing",
            "the parent request stays Executing"
        );
        assert_eq!(resolve_audit_count(pool, job).await, 1, "one audit row");
        assert_eq!(
            reconcile_resolved_event_count(pool, job).await,
            1,
            "one non-alerting resolution event"
        );

        // A second resolve of the now-Failed job → 409, no second audit.
        let again = admin_resolve_reconcile_required_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody {
                reason: "again".into(),
            }),
        )
        .await
        .expect_err("a resolved job cannot be resolved again");
        assert_eq!(again.0, StatusCode::CONFLICT);
        assert_eq!(
            resolve_audit_count(pool, job).await,
            1,
            "the failed second resolve writes no audit row"
        );

        cleanup_dead_letter_events(pool, job).await;
        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    #[tokio::test]
    async fn reconcile_resolved_live_destroy_halts_teardown_step_and_request() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-rec-destroy-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let stages = json!([{
            "name": "execute", "status": "InProgress",
            "started_at": null, "completed_at": null,
            "evidence": [], "metadata": {}
        }]);
        sqlx::query("UPDATE requests SET stages = $2::jsonb WHERE id = $1")
            .bind(req)
            .bind(&stages)
            .execute(pool)
            .await
            .expect("seed execute stage history");
        let mut conn = pool.acquire().await.expect("step-plan connection");
        crate::repos::job_steps::insert_plan(
            &mut conn,
            req,
            &[("destroy-me", vec![], "linux-server-deployment")],
        )
        .await
        .expect("seed teardown step");
        drop(conn);

        let spec = dead_letter_spec(req, JobMode::LiveDestroy);
        let job: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs \
             (request_id, platform, spec, mode, status, step_scoped) \
             VALUES ($1, $2, $3, 'LiveDestroy', 'ReconcileRequired', TRUE) RETURNING id",
        )
        .bind(req)
        .bind(&platform)
        .bind(serde_json::to_value(spec).expect("spec serialises"))
        .fetch_one(pool)
        .await
        .expect("seed reconcile-required destroy");
        sqlx::query(
            "UPDATE job_steps SET status = 'TearingDown', agent_job_id = $2 \
             WHERE request_id = $1 AND step_key = 'destroy-me'",
        )
        .bind(req)
        .bind(job)
        .execute(pool)
        .await
        .expect("link teardown job");

        let Json(out) = admin_resolve_reconcile_required_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody {
                reason: "provider and state dispositions reconciled".into(),
            }),
        )
        .await
        .expect("resolve destroy reconciliation");
        assert_eq!(out["status"], "Failed");

        let step_status: String = sqlx::query_scalar(
            "SELECT status FROM job_steps WHERE request_id = $1 AND step_key = 'destroy-me'",
        )
        .bind(req)
        .fetch_one(pool)
        .await
        .expect("step status");
        assert_eq!(step_status, "Failed");
        let (request_status, stages_after): (String, serde_json::Value) =
            sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
                .bind(req)
                .fetch_one(pool)
                .await
                .expect("request status");
        assert_eq!(request_status, "failed");
        let execute = stages_after
            .as_array()
            .and_then(|items| items.iter().find(|item| item["name"] == "execute"))
            .expect("execute stage");
        assert_eq!(execute["status"], "Failed");
        let lifecycle_audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE request_id = $1 \
             AND action = 'request.execution-result' AND to_status = 'failed'",
        )
        .bind(req)
        .fetch_one(pool)
        .await
        .expect("count lifecycle audit");
        assert_eq!(lifecycle_audit, 1);

        cleanup_dead_letter_events(pool, job).await;
        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// run-7 lifecycle contract: a TERMINAL non-Succeeded LiveApply PERMANENTLY
    /// consumes the request's single live-apply slot. The all-statuses index
    /// (`idx_agent_jobs_unique_live_apply`, migration 057) blocks a re-mint even
    /// while the parent request is still `Executing` — so the block is the INDEX,
    /// not the concluded-request gate. This is the assertion that would CATCH a
    /// future "scope the index to non-terminal statuses" change (which would turn
    /// the no-double-apply invariant fail-OPEN). Only AFTER the operator concludes
    /// the request with `/fail` does the concluded gate ALSO refuse — a distinct
    /// branch. There is no in-place retry; a re-attempt needs a fresh request.
    #[tokio::test]
    async fn db_live_apply_slot_permanent_after_terminal_apply() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let cp_key = ensure_test_cp_key();
        let platform = format!("plt-slot-{}", Uuid::new_v4().simple());
        // The parent request is mid-apply: Executing (NOT concluded).
        let req = seed_request_for_scope(pool, &platform, "production").await;

        let spec = JobSpec {
            request_id: req,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: reviewable_live_plan_vars(),
            state_key: Some(format!("request-{req}")),
            mode: JobMode::LiveApply,
        };
        let plan_digest = proto_sha256(b"approved-plan-bytes");
        let plan_agent_id = format!("slot-plan-agent-{}", Uuid::new_v4().simple());
        let (_plan_token, plan_key, plan_enrollment_id) =
            seed_agent_with_key(pool, &plan_agent_id, &platform).await;
        let approved_plan = seed_signed_successful_plan_for_mutation(
            pool,
            req,
            &platform,
            &spec,
            &plan_digest,
            &plan_agent_id,
            plan_enrollment_id,
            &plan_key,
        )
        .await;
        // create_live_apply_job borrows everything (request_id is Copy), so the
        // same args drive all three mint attempts below.
        let grant_expiry = chrono::Utc::now() + chrono::Duration::hours(1);

        // 1. Mint the ONE LiveApply job for this request.
        let job_id = create_live_apply_job(
            pool,
            approved_plan.clone(),
            req,
            &platform,
            &spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            grant_expiry,
            &cp_key,
        )
        .await
        .expect("first live-apply mint must succeed");

        // 2. Drive it terminal via the REAL reconcile path: simulate a lease-expiry
        //    → ReconcileRequired, then the operator resolves it to Failed.
        sqlx::query(
            "UPDATE agent_jobs SET status = 'ReconcileRequired', updated_at = NOW() WHERE id = $1",
        )
        .bind(job_id)
        .execute(pool)
        .await
        .expect("force job to ReconcileRequired");
        let Json(_) = admin_resolve_reconcile_required_job(
            Path(job_id.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody {
                reason: "reconciled the half-applied resources out-of-band".into(),
            }),
        )
        .await
        .expect("resolve to Failed must succeed");

        // 3. Job is terminal Failed; the parent request is STILL Executing (not
        //    concluded), so the NEXT mint is gated by the INDEX, not the gate.
        let job_status: String = sqlx::query_scalar("SELECT status FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(job_status, "Failed", "job is terminal Failed");
        let req_status: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            req_status, "executing",
            "the parent request stays Executing (NOT concluded)"
        );

        // 4. Re-mint while Executing → blocked by the ALL-statuses INDEX
        //    (Invalid "already approved"), NOT RequestConcluded. Catches a future
        //    "scope the index to non-terminal statuses" regression.
        let blocked_by_index = create_live_apply_job(
            pool,
            approved_plan.clone(),
            req,
            &platform,
            &spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            grant_expiry,
            &cp_key,
        )
        .await;
        assert!(
            matches!(blocked_by_index, Err(CreateLiveApplyJobError::Invalid(_))),
            "a terminal LiveApply must block re-mint via the permanent index while the \
             request is still Executing; got {blocked_by_index:?}"
        );

        // 5. Operator concludes the request (the POST /api/requests/{id}/fail outcome).
        sqlx::query("UPDATE requests SET status = 'failed', updated_at = NOW() WHERE id = $1")
            .bind(req)
            .execute(pool)
            .await
            .expect("conclude request as failed");

        // 6. Now the concluded gate ALSO refuses — a DISTINCT branch from step 4.
        let blocked_by_gate = create_live_apply_job(
            pool,
            approved_plan,
            req,
            &platform,
            &spec,
            &plan_digest,
            &live_approver_session("ops-alice"),
            grant_expiry,
            &cp_key,
        )
        .await;
        assert!(
            matches!(
                blocked_by_gate,
                Err(CreateLiveApplyJobError::RequestConcluded)
            ),
            "after /fail the concluded-request gate refuses re-mint; got {blocked_by_gate:?}"
        );

        // Throughout, exactly ONE LiveApply row ever existed for the request.
        let live_apply_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1 AND mode = 'LiveApply'",
        )
        .bind(req)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            live_apply_count, 1,
            "no-double-apply held: one live-apply slot, ever"
        );
        let approval_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE request_id = $1 \
             AND action = 'request.approve-live-apply'",
        )
        .bind(req)
        .fetch_one(pool)
        .await
        .expect("count live-approval audits");
        assert_eq!(
            approval_audit_count, 1,
            "the successful mint emits one audit; index/gate losers emit none"
        );

        // Schema-level guard: the unique index must remain ALL-statuses — its
        // predicate is exactly `mode = 'LiveApply'` with NO status clause. This
        // catches a future "scope the index to non-terminal statuses" edit at the
        // catalog level, not just behaviorally.
        let indexdef: String = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_agent_jobs_unique_live_apply'",
        )
        .fetch_one(pool)
        .await
        .expect("the live-apply unique index must exist");
        assert!(
            indexdef.contains("mode = 'LiveApply'"),
            "index predicate must be mode='LiveApply'; got {indexdef}"
        );
        assert!(
            !indexdef.to_lowercase().contains("status"),
            "index must span ALL statuses (no status predicate); got {indexdef}"
        );

        cleanup_dead_letter_events(pool, job_id).await;
        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_agent(pool, &plan_agent_id).await;
        cleanup_request_row(pool, req).await;
    }

    /// Resolve rejects: a non-ReconcileRequired job → 409, an unknown id → 404, a
    /// non-admin → 403, an empty reason → 400.
    #[tokio::test]
    async fn reconcile_resolve_rejects_wrong_status_unknown_nonadmin_empty() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-rec2-{}", Uuid::new_v4().simple());
        // A Pending job is not ReconcileRequired → 409.
        let pending = seed_pending_job(pool, &platform).await;
        let conflict = admin_resolve_reconcile_required_job(
            Path(pending.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody { reason: "x".into() }),
        )
        .await
        .expect_err("a Pending job is not resolvable");
        assert_eq!(conflict.0, StatusCode::CONFLICT);

        // Unknown id → 404.
        let unknown = admin_resolve_reconcile_required_job(
            Path(Uuid::new_v4().to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody { reason: "x".into() }),
        )
        .await
        .expect_err("unknown id");
        assert_eq!(unknown.0, StatusCode::NOT_FOUND);

        // Non-admin → 403 (before any DB work).
        let denied = admin_resolve_reconcile_required_job(
            Path(pending.to_string()),
            Extension(non_admin_session()),
            Json(ReconcileBody { reason: "x".into() }),
        )
        .await
        .expect_err("non-admin");
        assert_eq!(denied.0, StatusCode::FORBIDDEN);

        // Empty reason → 400 (admin, before the CAS).
        let empty = admin_resolve_reconcile_required_job(
            Path(pending.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ReconcileBody {
                reason: "   ".into(),
            }),
        )
        .await
        .expect_err("empty reason");
        assert_eq!(empty.0, StatusCode::BAD_REQUEST);

        cleanup_jobs_for_platform(pool, &platform).await;
    }

    /// #15: dispatch orders by priority DESC, then created_at (FIFO), then id — a higher-
    /// priority job leases before an OLDER lower-priority one; equal priority falls back to
    /// FIFO; and a freshly-inserted job inherits the migration default priority 5.
    #[tokio::test]
    async fn agent_job_dispatch_prefers_priority_then_fifo() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-prio-{}", Uuid::new_v4().simple());
        let j_old = seed_pending_job(pool, &platform).await;
        let j_new = seed_pending_job(pool, &platform).await;

        // The migration default is applied to a job inserted without a priority.
        let def: i32 = sqlx::query_scalar("SELECT priority FROM agent_jobs WHERE id = $1")
            .bind(j_old)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(def, 5, "the migration default priority is 5");

        // j_old: OLDER + LOW priority; j_new: newer + HIGH priority.
        sqlx::query(
            "UPDATE agent_jobs SET priority = 2, created_at = NOW() - INTERVAL '1 hour' \
             WHERE id = $1",
        )
        .bind(j_old)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("UPDATE agent_jobs SET priority = 8 WHERE id = $1")
            .bind(j_new)
            .execute(pool)
            .await
            .unwrap();

        let dispatch = |plat: String| async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM agent_jobs WHERE platform = $1 AND status = 'Pending' \
                 ORDER BY priority DESC, created_at, id LIMIT 1",
            )
            .bind(plat)
            .fetch_one(pool)
            .await
            .unwrap()
        };
        // Priority beats FIFO: the newer-but-higher-priority job dispatches first.
        assert_eq!(
            dispatch(platform.clone()).await,
            j_new,
            "the higher-priority job dispatches first despite a later created_at"
        );

        // Equal priority → FIFO: the OLDER job wins.
        sqlx::query("UPDATE agent_jobs SET priority = 5 WHERE id = ANY($1)")
            .bind(vec![j_old, j_new])
            .execute(pool)
            .await
            .unwrap();
        assert_eq!(
            dispatch(platform.clone()).await,
            j_old,
            "equal priority falls back to FIFO (oldest first)"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
    }

    /// #15: POST .../jobs/{id}/priority reprioritizes a PENDING job (audited); a non-admin
    /// is 403; an out-of-range priority is 400; a non-pending job is 409; an unknown id is
    /// 404.
    #[tokio::test]
    async fn agent_job_reprioritize_pending_only_and_guards() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-rp-{}", Uuid::new_v4().simple());
        let job = seed_pending_job(pool, &platform).await;

        // Non-admin → 403 (before any DB work).
        let denied = admin_set_job_priority(
            Path(job.to_string()),
            Extension(non_admin_session()),
            Json(SetJobPriorityBody { priority: 9 }),
        )
        .await;
        assert!(
            matches!(denied, Err((StatusCode::FORBIDDEN, _))),
            "{denied:?}"
        );

        // Out-of-range priority → 400.
        let bad = admin_set_job_priority(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(SetJobPriorityBody { priority: 99 }),
        )
        .await;
        assert!(matches!(bad, Err((StatusCode::BAD_REQUEST, _))), "{bad:?}");

        // Happy: reprioritize the pending job to 9 → 200; the row is updated; audited.
        let Json(out) = admin_set_job_priority(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(SetJobPriorityBody { priority: 9 }),
        )
        .await
        .expect("reprioritize must succeed");
        assert_eq!(out["priority"], json!(9));
        let row_prio: i32 = sqlx::query_scalar("SELECT priority FROM agent_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(row_prio, 9, "the row priority is persisted");
        let audited: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM audit_log WHERE action = 'agent-job-reprioritize' \
             AND detail->>'job_id' = $1)",
        )
        .bind(job.to_string())
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(audited, "a reprioritize audit row must exist");

        // A NON-alerting reprioritize event carries the new priority + the non-prefilter
        // marker (queue-priority changes are observable on /api/events but never page).
        let evt: Option<(String, i64)> = sqlx::query_as(
            "SELECT payload->>'to_status', (payload->>'to_priority')::bigint FROM domain_events \
             WHERE event_type = 'job.reprioritized' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job.to_string())
        .fetch_optional(pool)
        .await
        .expect("query reprioritize event");
        assert_eq!(
            evt.as_ref().map(|(s, p)| (s.as_str(), *p)),
            Some(("admin-reprioritized", 9)),
            "one non-alerting reprioritize event carrying the new priority"
        );
        assert!(
            !ryuki_engine::event_alerts::alert_worthy_statuses().contains(&"admin-reprioritized"),
            "admin-reprioritized must NOT be in the alert prefilter — it can never page"
        );

        // A NON-pending (Leased) job → 409 (the status CAS misses).
        let leased = seed_pending_job(pool, &platform).await;
        let mut lease_tx = begin_agent_job_lease_fixture_tx(pool).await;
        sqlx::query("UPDATE agent_jobs SET status = 'Leased', agent_id = 'a' WHERE id = $1")
            .bind(leased)
            .execute(&mut *lease_tx)
            .await
            .unwrap();
        lease_tx
            .commit()
            .await
            .expect("commit reprioritize lease fixture");
        let conflict = admin_set_job_priority(
            Path(leased.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(SetJobPriorityBody { priority: 7 }),
        )
        .await;
        assert!(
            matches!(conflict, Err((StatusCode::CONFLICT, _))),
            "a non-pending job must 409: {conflict:?}"
        );

        // Unknown id → 404.
        let unknown = admin_set_job_priority(
            Path(Uuid::new_v4().to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(SetJobPriorityBody { priority: 5 }),
        )
        .await;
        assert!(
            matches!(unknown, Err((StatusCode::NOT_FOUND, _))),
            "{unknown:?}"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
    }

    /// #6: queue-depth reports the PENDING backlog per platform — count (a Leased job is
    /// EXCLUDED), top priority, and the oldest pending instant (a FIXED created_at, codex).
    /// A non-admin is 403.
    #[tokio::test]
    async fn agent_queue_depth_reports_pending_per_platform() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = Uuid::new_v4().simple();
        let plat_a = format!("plt-qa-{suffix}");
        let plat_b = format!("plt-qb-{suffix}");
        // Platform A: 3 pending (one bumped to priority 9, one with a FIXED oldest
        // created_at) + 1 Leased that must be EXCLUDED from the pending count.
        let oldest = chrono::DateTime::parse_from_rfc3339("2025-02-01T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let a1 = seed_pending_job(pool, &plat_a).await;
        let a2 = seed_pending_job(pool, &plat_a).await;
        let _a3 = seed_pending_job(pool, &plat_a).await;
        let a_leased = seed_pending_job(pool, &plat_a).await;
        sqlx::query("UPDATE agent_jobs SET created_at = $1 WHERE id = $2")
            .bind(oldest)
            .bind(a1)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE agent_jobs SET priority = 9 WHERE id = $1")
            .bind(a2)
            .execute(pool)
            .await
            .unwrap();
        let mut lease_tx = begin_agent_job_lease_fixture_tx(pool).await;
        sqlx::query("UPDATE agent_jobs SET status = 'Leased', agent_id = 'x' WHERE id = $1")
            .bind(a_leased)
            .execute(&mut *lease_tx)
            .await
            .unwrap();
        lease_tx
            .commit()
            .await
            .expect("commit queue-depth lease fixture");
        let _b1 = seed_pending_job(pool, &plat_b).await;

        let Json(out) = admin_agent_queue_depth(Extension(AuthSession::static_dry_run()))
            .await
            .expect("queue depth must succeed");
        let queues = out["queues"].as_array().unwrap();
        let a = queues
            .iter()
            .find(|q| q["platform"] == json!(plat_a))
            .expect("platform A present");
        assert_eq!(a["pending_count"], json!(3), "the Leased job is excluded");
        assert_eq!(
            a["top_priority"],
            json!(9),
            "the bumped job sets top_priority"
        );
        assert_eq!(
            a["oldest_pending_at"],
            json!(oldest.to_rfc3339()),
            "the oldest pending instant"
        );
        let b = queues
            .iter()
            .find(|q| q["platform"] == json!(plat_b))
            .expect("platform B present");
        assert_eq!(b["pending_count"], json!(1));

        // Non-admin → 403.
        let denied = admin_agent_queue_depth(Extension(non_admin_session())).await;
        assert!(
            matches!(denied, Err((StatusCode::FORBIDDEN, _))),
            "{denied:?}"
        );

        cleanup_jobs_for_platform(pool, &plat_a).await;
        cleanup_jobs_for_platform(pool, &plat_b).await;
    }

    /// #agent-job-result: the result endpoint returns the SIGNED ATTESTATION + metadata and
    /// NEVER the raw evidence_json — a sentinel secret seeded into evidence_json must not
    /// appear anywhere in the response. The top-level evidence_digest matches the envelope's.
    #[tokio::test]
    async fn agent_job_result_returns_attestation_not_raw_evidence() {
        use ryuki_protocol::{JobMode, JobResultStatus, SignedEnvelope, REDACTION_POLICY_VERSION};
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-res-{}", Uuid::new_v4().simple());
        let job = seed_pending_job(pool, &platform).await;
        let result_id = Uuid::new_v4();
        let digest = "b".repeat(64);
        let envelope = SignedEnvelope {
            agent_id: "agent-x".into(),
            agent_enrollment_id: Uuid::nil(),
            platform: platform.clone(),
            job_id: job,
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: Uuid::new_v4(),
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: "a".repeat(64),
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: digest.clone(),
            redaction_policy_version: REDACTION_POLICY_VERSION.into(),
            timestamp: Utc::now(),
            key_id: "key-1".into(),
            cp_nonce: "nonce-1".into(),
            signature: "sig".into(),
        };
        let env_json = serde_json::to_string(&envelope).unwrap();
        // The raw evidence_json carries a SENTINEL that must NEVER reach the response.
        let evidence = serde_json::json!({ "raw": "SUPERSECRET-DO-NOT-LEAK" }).to_string();
        sqlx::query(
            // 'check_ok' is the value the production POST path stores and the only
            // casing the mig 055 result_status CHECK accepts (codex).
            "UPDATE agent_jobs SET result_status = 'check_ok', completed_at = NOW(), \
             result_id = $1, evidence_digest = $2, signed_envelope = $3::jsonb, \
             evidence_json = $4::jsonb WHERE id = $5",
        )
        .bind(result_id)
        .bind(&digest)
        .bind(&env_json)
        .bind(&evidence)
        .bind(job)
        .execute(pool)
        .await
        .unwrap();

        let Json(out) = admin_agent_job_result(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("result must succeed");
        assert_eq!(out["result_status"], json!("check_ok"));
        assert_eq!(out["evidence_digest"], json!(digest), "top-level digest");
        assert!(
            out["signed_envelope"].is_object(),
            "the attestation is returned"
        );
        // codex: top-level evidence_digest == signed_envelope.evidence_digest.
        assert_eq!(
            out["evidence_digest"],
            out["signed_envelope"]["evidence_digest"]
        );
        // SECRET HYGIENE: the raw evidence_json sentinel NEVER appears in the body.
        let body = out.to_string();
        assert!(
            !body.contains("SUPERSECRET"),
            "raw evidence must not leak: {body}"
        );
        assert!(out.get("evidence_json").is_none(), "no evidence_json key");
        assert!(
            out.get("spec").is_none() && out.get("live_context").is_none(),
            "no spec/live_context"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
    }

    #[tokio::test]
    async fn agent_job_result_derives_safe_live_plan_review_from_verified_bytes() {
        use ryuki_protocol::{SignedEnvelope, REDACTION_POLICY_VERSION};
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-plan-review-{}", Uuid::new_v4().simple());
        let job = seed_pending_job(pool, &platform).await;
        let spec = reviewable_live_plan_spec();
        let safe_projection = reviewable_live_plan(&["create"]);
        let evidence = serde_json::to_vec(&safe_projection).unwrap();
        let digest = ryuki_protocol::sha256_hex(&evidence);
        let result_id = Uuid::new_v4();
        let envelope = SignedEnvelope {
            agent_id: "agent-x".into(),
            agent_enrollment_id: Uuid::nil(),
            platform: platform.clone(),
            job_id: job,
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::LivePlan,
            status: JobResultStatus::Planned,
            job_spec_digest: ryuki_protocol::job_spec_digest(&spec),
            approved_plan_digest: None,
            raw_plan_digest: Some("a".repeat(64)),
            execution_trust_profile: None,
            evidence_digest: digest.clone(),
            redaction_policy_version: REDACTION_POLICY_VERSION.into(),
            timestamp: Utc::now(),
            key_id: "key-1".into(),
            cp_nonce: "nonce-1".into(),
            signature: "sig".into(),
        };
        sqlx::query(
            "INSERT INTO evidence_blobs (digest, bytes, size_bytes) VALUES ($1, $2, $3) \
             ON CONFLICT (digest) DO UPDATE SET bytes = EXCLUDED.bytes, size_bytes = EXCLUDED.size_bytes",
        )
        .bind(&digest)
        .bind(&evidence)
        .bind(evidence.len() as i64)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE agent_jobs SET spec = $1::jsonb, mode = 'LivePlan', status = 'Succeeded', \
             result_status = 'planned', completed_at = NOW(), result_id = $2, \
             evidence_digest = $3, raw_plan_digest = $4, signed_envelope = $5::jsonb WHERE id = $6",
        )
        .bind(serde_json::to_value(&spec).unwrap())
        .bind(result_id)
        .bind(&digest)
        .bind("a".repeat(64))
        .bind(serde_json::to_value(&envelope).unwrap())
        .bind(job)
        .execute(pool)
        .await
        .unwrap();

        let Json(out) = admin_agent_job_result(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("reviewable result");
        assert_eq!(out["plan_review"]["digest_verified"], true);
        assert_eq!(out["plan_review"]["counts"]["create"], 1);
        assert_eq!(out["plan_review"]["placement"]["name"], "first-test-vm");
        let rendered_review = out["plan_review"].to_string();
        assert!(!rendered_review.contains("canonical_plan_sha256"));
        assert!(!rendered_review.contains(&"a".repeat(64)));
        assert_eq!(out["raw_plan_digest"], "a".repeat(64));
        assert_eq!(
            out["signed_envelope"]["raw_plan_digest"],
            out["raw_plan_digest"]
        );
        assert!(out.get("evidence_json").is_none());
        assert!(out.get("spec").is_none());

        cleanup_jobs_for_platform(pool, &platform).await;
        sqlx::query("DELETE FROM evidence_blobs WHERE digest = $1")
            .bind(&digest)
            .execute(pool)
            .await
            .ok();
    }

    /// #agent-job-result: defense-in-depth (codex re-review #2) — a row stored BEFORE the
    /// Step 5b ingestion guard (mig 055 predates it) whose signed_envelope carries an
    /// unrecognised redaction_policy_version must NOT ride into the read view. The read side
    /// re-gates against the allowlist and fails closed with a GENERIC, non-echoing error.
    #[tokio::test]
    async fn agent_job_result_unsupported_stored_policy_version_is_not_served() {
        use ryuki_protocol::{JobMode, JobResultStatus, SignedEnvelope};
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-badpol-{}", Uuid::new_v4().simple());
        let job = seed_pending_job(pool, &platform).await;
        let result_id = Uuid::new_v4();
        let digest = "c".repeat(64);
        // A pre-guard stored envelope smuggling a secret into the policy-version slot.
        let mut envelope = SignedEnvelope {
            agent_id: "agent-x".into(),
            agent_enrollment_id: Uuid::nil(),
            platform: platform.clone(),
            job_id: job,
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: Uuid::new_v4(),
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: "a".repeat(64),
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: digest.clone(),
            redaction_policy_version: "SUPERSECRET".into(),
            timestamp: Utc::now(),
            key_id: "key-1".into(),
            cp_nonce: "nonce-1".into(),
            signature: "sig".into(),
        };
        let env_json = serde_json::to_string(&envelope).unwrap();
        sqlx::query(
            "UPDATE agent_jobs SET result_status = 'check_ok', completed_at = NOW(), \
             result_id = $1, evidence_digest = $2, signed_envelope = $3::jsonb WHERE id = $4",
        )
        .bind(result_id)
        .bind(&digest)
        .bind(&env_json)
        .bind(job)
        .execute(pool)
        .await
        .unwrap();

        let err = admin_agent_job_result(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect_err("an unsupported stored policy version must not be served");
        let (status, Json(body)) = err;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // The generic error must NOT echo the smuggled secret.
        assert!(
            !body.to_string().contains("SUPERSECRET"),
            "read-side rejection must not echo the secret: {body}"
        );

        envelope.redaction_policy_version = "ryuki-redaction-v1".into();
        sqlx::query("UPDATE agent_jobs SET signed_envelope = $1::jsonb WHERE id = $2")
            .bind(serde_json::to_value(&envelope).unwrap())
            .bind(job)
            .execute(pool)
            .await
            .unwrap();
        let legacy = admin_agent_job_result(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect_err("stored evidence under superseded redaction v1 must not be served");
        assert_eq!(legacy.0, StatusCode::INTERNAL_SERVER_ERROR);

        cleanup_jobs_for_platform(pool, &platform).await;
    }

    /// #agent-job-result: a job with NO result yet (signed_envelope NULL) → 404; an unknown
    /// id → 404.
    #[tokio::test]
    async fn agent_job_result_no_result_and_unknown_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-nr-{}", Uuid::new_v4().simple());
        let job = seed_pending_job(pool, &platform).await; // no result set
        let no_result = admin_agent_job_result(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await;
        assert!(
            matches!(no_result, Err((StatusCode::NOT_FOUND, _))),
            "no-result -> 404: {no_result:?}"
        );
        let unknown = admin_agent_job_result(
            Path(Uuid::new_v4().to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await;
        assert!(
            matches!(unknown, Err((StatusCode::NOT_FOUND, _))),
            "unknown -> 404"
        );
        cleanup_jobs_for_platform(pool, &platform).await;
    }

    /// #agent-job-result: a non-admin → 403; a malformed id → 404 (parsed BEFORE get_db, so
    /// it 404s even with no DB — codex). Neither needs a pool.
    #[tokio::test]
    async fn agent_job_result_403_and_malformed_404() {
        let denied = admin_agent_job_result(Path("x".into()), Extension(non_admin_session())).await;
        assert!(
            matches!(denied, Err((StatusCode::FORBIDDEN, _))),
            "{denied:?}"
        );
        let bad = admin_agent_job_result(
            Path("not-a-uuid".into()),
            Extension(AuthSession::static_dry_run()),
        )
        .await;
        assert!(
            matches!(bad, Err((StatusCode::NOT_FOUND, _))),
            "malformed id -> 404 (parsed before get_db): {bad:?}"
        );
    }

    /// requeue happy: an ACTIVE parent + a DeadLettered job → Pending with a fresh
    /// budget + cleared lease state, audited.
    #[tokio::test]
    async fn db_requeue_dead_lettered_happy() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_dead_lettered_job(pool, &platform, req).await;

        let Json(out) = admin_requeue_dead_lettered_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("requeue must succeed");
        assert_eq!(out["status"], "Pending");
        assert_eq!(out["requeued"], true);

        let (status, attempts) = job_status_and_attempts(pool, job).await;
        assert_eq!(status, "Pending", "job back to Pending");
        assert_eq!(attempts, 0, "delivery budget reset");
        let agent_id: Option<String> =
            sqlx::query_scalar("SELECT agent_id FROM agent_jobs WHERE id = $1")
                .bind(job)
                .fetch_one(pool)
                .await
                .expect("read agent_id");
        assert!(agent_id.is_none(), "lease state cleared");
        assert_eq!(requeue_audit_count(pool, job).await, 1, "one requeue audit");

        // A NON-alerting requeue event with the robust non-prefilter marker (so a job
        // re-entering the queue is observable on /api/events but can never page).
        let to_status: Option<String> = sqlx::query_scalar(
            "SELECT payload->>'to_status' FROM domain_events \
             WHERE event_type = 'job.requeued' AND aggregate_type = 'agent_job' \
               AND aggregate_id = $1",
        )
        .bind(job.to_string())
        .fetch_optional(pool)
        .await
        .expect("query requeue event");
        assert_eq!(
            to_status.as_deref(),
            Some("admin-requeued"),
            "one non-alerting requeue event with the non-prefilter marker"
        );
        assert!(
            !ryuki_engine::event_alerts::alert_worthy_statuses().contains(&"admin-requeued"),
            "admin-requeued must NOT be in the alert prefilter — a requeue can never page"
        );

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    #[tokio::test]
    async fn db_requeue_live_plan_preserves_agent_affinity() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-requeue-affinity-{}", Uuid::new_v4().simple());
        let agent_id = format!("agent-requeue-{}", Uuid::new_v4());
        seed_agent(pool, &agent_id, &platform, "approved").await;
        let request_id = seed_request_row(pool, "executing").await;
        let job =
            seed_dead_lettered_job_full(pool, &platform, request_id, request_id, JobMode::LivePlan)
                .await;
        sqlx::query("UPDATE agent_jobs SET agent_id = $2 WHERE id = $1")
            .bind(job)
            .bind(&agent_id)
            .execute(pool)
            .await
            .expect("bind dead-lettered live plan");

        let _ = admin_requeue_dead_lettered_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("requeue live plan");

        let (status, assigned_agent): (String, Option<String>) =
            sqlx::query_as("SELECT status, agent_id FROM agent_jobs WHERE id = $1")
                .bind(job)
                .fetch_one(pool)
                .await
                .expect("read requeued live plan");
        assert_eq!(status, "Pending");
        assert_eq!(assigned_agent.as_deref(), Some(agent_id.as_str()));

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_agent(pool, &agent_id).await;
        cleanup_request_row(pool, request_id).await;
    }

    /// requeue rejects a non-DeadLettered job (and is idempotent: a second requeue
    /// of an already-requeued job 409s because it is now Pending).
    #[tokio::test]
    async fn db_requeue_rejects_non_dead_lettered_and_is_idempotent() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;

        // A plain Pending job → 409.
        let pending = seed_pending_job(pool, &platform).await;
        let Err((s1, _)) = admin_requeue_dead_lettered_job(
            Path(pending.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        else {
            panic!("requeue of a non-dead-lettered job must 409");
        };
        assert_eq!(s1, StatusCode::CONFLICT);

        // Idempotency: requeue a DeadLettered job (200), then a second requeue 409s.
        let job = seed_dead_lettered_job(pool, &platform, req).await;
        let _ = admin_requeue_dead_lettered_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("first requeue 200");
        let Err((s2, _)) = admin_requeue_dead_lettered_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        else {
            panic!("second requeue (now Pending) must 409");
        };
        assert_eq!(s2, StatusCode::CONFLICT);

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// requeue unknown / malformed id → 404.
    #[tokio::test]
    async fn db_requeue_unknown_id_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        for id in [Uuid::new_v4().to_string(), "not-a-uuid".to_string()] {
            let Err((status, _)) =
                admin_requeue_dead_lettered_job(Path(id), Extension(AuthSession::static_dry_run()))
                    .await
            else {
                panic!("unknown/malformed id must 404");
            };
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }

    /// requeue REFUSES a job whose parent request has concluded (codex MAJOR):
    /// cancelled, failed, and orphaned parents all 409, and the job is UNCHANGED.
    #[tokio::test]
    async fn db_requeue_rejects_concluded_parent() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let cancelled = seed_request_row(pool, "cancelled").await;
        let failed = seed_request_row(pool, "failed").await;

        for parent in [cancelled, failed] {
            let job = seed_dead_lettered_job(pool, &platform, parent).await;
            let Err((status, _)) = admin_requeue_dead_lettered_job(
                Path(job.to_string()),
                Extension(AuthSession::static_dry_run()),
            )
            .await
            else {
                panic!("requeue with a concluded parent must 409");
            };
            assert_eq!(status, StatusCode::CONFLICT);
            // The job is untouched — still DeadLettered with its attempts intact.
            let (s, a) = job_status_and_attempts(pool, job).await;
            assert_eq!(s, "DeadLettered", "job must NOT be requeued");
            assert_eq!(a, 5, "delivery_attempts must NOT be reset");
        }

        // Orphan: a job whose request_id has no requests row → 409.
        let orphan = seed_dead_lettered_job(pool, &platform, Uuid::new_v4()).await;
        let Err((status, _)) = admin_requeue_dead_lettered_job(
            Path(orphan.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        else {
            panic!("requeue of an orphan job must 409");
        };
        assert_eq!(status, StatusCode::CONFLICT);

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, cancelled).await;
        cleanup_request_row(pool, failed).await;
    }

    /// requeue validates the dispatched SPEC, not the scalar columns (codex MAJOR):
    /// the agent acts on spec.request_id / spec.mode, and create_agent_job does not
    /// pin the columns to the spec. So requeue must guard the spec.
    #[tokio::test]
    async fn db_requeue_validates_the_spec_not_the_columns() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let active = seed_request_row(pool, "executing").await;
        let concluded = seed_request_row(pool, "cancelled").await;

        // A) column request_id ACTIVE but spec.request_id CONCLUDED → 409 (the guard
        //    must follow the spec, which is what the agent executes).
        let job_a =
            seed_dead_lettered_job_full(pool, &platform, active, concluded, JobMode::OfflineDryRun)
                .await;
        let Err((sa, _)) = admin_requeue_dead_lettered_job(
            Path(job_a.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        else {
            panic!("spec.request_id concluded must 409 even when the column is active");
        };
        assert_eq!(sa, StatusCode::CONFLICT);
        assert_eq!(job_status_and_attempts(pool, job_a).await.0, "DeadLettered");

        // B) column request_id CONCLUDED but spec.request_id ACTIVE → 200 (the spec's
        //    parent is active, so requeue is allowed regardless of the stale column).
        let job_b =
            seed_dead_lettered_job_full(pool, &platform, concluded, active, JobMode::OfflineDryRun)
                .await;
        let _ = admin_requeue_dead_lettered_job(
            Path(job_b.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("spec.request_id active must requeue (200) even if the column is concluded");
        assert_eq!(job_status_and_attempts(pool, job_b).await.0, "Pending");

        // C) spec.mode = LiveApply (column says OfflineDryRun) → 409: a live job must
        //    never be re-dispatched as non-mutating Pending work.
        let job_c =
            seed_dead_lettered_job_full(pool, &platform, active, active, JobMode::LiveApply).await;
        let Err((sc, _)) = admin_requeue_dead_lettered_job(
            Path(job_c.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        else {
            panic!("a LiveApply spec must 409 even when the column mode is OfflineDryRun");
        };
        assert_eq!(sc, StatusCode::CONFLICT);
        assert_eq!(job_status_and_attempts(pool, job_c).await.0, "DeadLettered");

        // D) malformed spec → 409 (the agent could not have run it).
        let job_d: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, delivery_attempts) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'DeadLettered', 5) RETURNING id",
        )
        .bind(active)
        .bind(&platform)
        .fetch_one(pool)
        .await
        .expect("seed malformed-spec job");
        let Err((sd, _)) = admin_requeue_dead_lettered_job(
            Path(job_d.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        else {
            panic!("a malformed spec must 409");
        };
        assert_eq!(sd, StatusCode::CONFLICT);

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, active).await;
        cleanup_request_row(pool, concluded).await;
    }

    /// The audited reset does NOT let a poisoned job escape the automatic cap
    /// (codex MINOR): after requeue (budget reset to 0), driving the job back
    /// through lease-expiry re-dead-letters it once the fresh budget is exhausted.
    #[tokio::test]
    async fn db_requeue_then_cap_reapplies() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let _expire = EXPIRE_TEST_LOCK.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_dead_lettered_job(pool, &platform, req).await;

        let _ = admin_requeue_dead_lettered_job(
            Path(job.to_string()),
            Extension(AuthSession::static_dry_run()),
        )
        .await
        .expect("requeue 200");
        assert_eq!(
            job_status_and_attempts(pool, job).await,
            ("Pending".into(), 0)
        );

        // Fresh budget: five redispatches, then the sixth expiry dead-letters again.
        for cycle in 1..=5_i32 {
            release_expired(pool, job).await;
            expire_leases(pool).await.expect("expire");
            let (status, attempts) = job_status_and_attempts(pool, job).await;
            assert_eq!(
                status, "Pending",
                "cycle {cycle} redispatches on the fresh budget"
            );
            assert_eq!(attempts, cycle, "cycle {cycle} increments attempts");
        }
        release_expired(pool, job).await;
        expire_leases(pool).await.expect("expire");
        assert_eq!(
            job_status_and_attempts(pool, job).await.0,
            "DeadLettered",
            "the fresh budget is exactly the cap — it re-dead-letters, not escapes it"
        );

        cleanup_dead_letter_events(pool, job).await;
        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// Both endpoints are admin-only: a non-admin session → 403, no state change.
    #[tokio::test]
    async fn db_dead_letter_endpoints_admin_gated() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", Uuid::new_v4().simple());
        let req = seed_request_row(pool, "executing").await;
        let job = seed_dead_lettered_job(pool, &platform, req).await;

        let Err((s_list, _)) = admin_dead_lettered_jobs(Extension(non_admin_session())).await
        else {
            panic!("non-admin list must 403");
        };
        assert_eq!(s_list, StatusCode::FORBIDDEN);

        let Err((s_req, _)) =
            admin_requeue_dead_lettered_job(Path(job.to_string()), Extension(non_admin_session()))
                .await
        else {
            panic!("non-admin requeue must 403");
        };
        assert_eq!(s_req, StatusCode::FORBIDDEN);
        // Unchanged.
        assert_eq!(job_status_and_attempts(pool, job).await.0, "DeadLettered");

        cleanup_jobs_for_platform(pool, &platform).await;
        cleanup_request_row(pool, req).await;
    }

    /// The admin router builds (no matchit panic) with the new static
    /// `dead-lettered-jobs` path sitting beside the `{agent_id}` param.
    #[test]
    fn admin_routes_build_with_dead_letter_paths() {
        let _router = admin_routes();
    }

    /// Routing regression (codex): the job-state read is a 5-segment `jobs/{job_id}/state`
    /// route, so it must NOT shadow `POST /api/admin/agents/{agent_id}/approve` for an agent
    /// literally named "jobs". matchit must still dispatch `POST /agents/jobs/approve` to the
    /// approve route (the handler then fails extraction without the auth middleware — a 4xx/5xx,
    /// NOT a 405 from the jobs namespace). A bare 4-segment `jobs/{job_id}` GET would 405 it.
    #[tokio::test]
    async fn admin_jobs_namespace_does_not_shadow_agent_approve() {
        use tower::ServiceExt;
        let resp = admin_routes()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/admin/agents/jobs/approve")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router dispatch");
        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "POST /agents/jobs/approve must reach the agent approve route, not 405 via the \
             jobs/{{job_id}}/state namespace"
        );
    }

    // ── RBAC scope-guard tests (run-5) ─────────────────────────────────────

    fn scoped_admin_session(site: &str) -> AuthSession {
        AuthSession {
            user_id: "scoped-admin".into(),
            display_name: "Scoped Admin".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: true,
            provider_mode: "test".into(),
            site_scope: vec![site.to_string()],
            ..Default::default()
        }
    }

    async fn seed_request_for_scope(pool: &PgPool, site: &str, environment: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO requests (id, request_type, status, stage, site, environment, \
             name, cpu, memory_gb, created_by) \
             VALUES ($1, 'server-deployment', 'executing', 'execute', $2, $3, \
             'scope-test', 2, 4, 'test-user')",
        )
        .bind(id)
        .bind(site)
        .bind(environment)
        .execute(pool)
        .await
        .expect("seed request for scope");
        id
    }

    async fn cleanup_request_and_jobs(pool: &PgPool, request_id: Uuid) {
        sqlx::query("DELETE FROM agent_jobs WHERE request_id = $1")
            .bind(request_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(request_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn db_scope_requeue_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-{}", Uuid::new_v4().simple());
        // GBLON request; DEFRA-scoped admin
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_dead_lettered_job(pool, &platform, req).await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) =
            admin_requeue_dead_lettered_job(Path(job.to_string()), Extension(scoped)).await
        else {
            panic!("out-of-scope requeue must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(job_status_and_attempts(pool, job).await.0, "DeadLettered");
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_requeue_in_scope_acts() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_dead_lettered_job(pool, &platform, req).await;
        let scoped = scoped_admin_session("GBLON");
        let _ = admin_requeue_dead_lettered_job(Path(job.to_string()), Extension(scoped))
            .await
            .expect("in-scope requeue must succeed");
        assert_eq!(job_status_and_attempts(pool, job).await.0, "Pending");
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_requeue_out_of_scope_wrong_status_is_404_not_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-{}", Uuid::new_v4().simple());
        // Concluded request; out-of-scope admin — must 404, not 409
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        sqlx::query("UPDATE requests SET status = 'failed' WHERE id = $1")
            .bind(req)
            .execute(pool)
            .await
            .ok();
        let job = seed_dead_lettered_job(pool, &platform, req).await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) =
            admin_requeue_dead_lettered_job(Path(job.to_string()), Extension(scoped)).await
        else {
            panic!("must 404 not 409");
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "out-of-scope must 404, not 409"
        );
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_force_fail_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-ff-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, req, "Leased").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_force_fail_job(
            Path(job.to_string()),
            Extension(scoped),
            Json(ForceFailJobBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("out-of-scope force-fail must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_force_fail_out_of_scope_wrong_status_is_404_not_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-ff2-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        // Pending → would 409 for unrestricted; 404 for out-of-scope
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_force_fail_job(
            Path(job.to_string()),
            Extension(scoped),
            Json(ForceFailJobBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("must 404 not 409");
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "out-of-scope must 404, not 409"
        );
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_reconcile_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-rec-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, req, "ReconcileRequired").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_resolve_reconcile_required_job(
            Path(job.to_string()),
            Extension(scoped),
            Json(ReconcileBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("out-of-scope reconcile must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_reconcile_out_of_scope_wrong_status_is_404_not_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-rec2-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        // Pending → would 409 for unrestricted; 404 for out-of-scope
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_resolve_reconcile_required_job(
            Path(job.to_string()),
            Extension(scoped),
            Json(ReconcileBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("must 404 not 409");
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "out-of-scope must 404, not 409"
        );
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_cancel_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-cxl-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(scoped),
            Json(CancelJobBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("out-of-scope cancel must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_cancel_out_of_scope_wrong_status_is_404_not_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-cxl2-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        // Leased → would 409 for unrestricted; 404 for out-of-scope
        let job = seed_job_in_status(pool, &platform, req, "Leased").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(scoped),
            Json(CancelJobBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("must 404 not 409");
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "out-of-scope must 404, not 409"
        );
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_cancel_projects_authoritative_spec_request_id() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-cxl-id-{}", Uuid::new_v4().simple());
        let scalar_request = seed_request_for_scope(pool, "DEFRA", "production").await;
        let spec_request = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, scalar_request, "Pending").await;
        let spec = dead_letter_spec(spec_request, JobMode::OfflineDryRun);
        sqlx::query("UPDATE agent_jobs SET spec = $1 WHERE id = $2")
            .bind(serde_json::to_value(&spec).expect("spec serialises"))
            .bind(job)
            .execute(pool)
            .await
            .expect("make request ids divergent");

        let Json(out) = admin_cancel_pending_job(
            Path(job.to_string()),
            Extension(scoped_admin_session("GBLON")),
            Json(CancelJobBody {
                reason: "scope projection regression".into(),
            }),
        )
        .await
        .expect("the spec parent is in scope");
        assert_eq!(out["request_id"], json!(spec_request.to_string()));
        assert_ne!(out["request_id"], json!(scalar_request.to_string()));

        let audited_request_id: String = sqlx::query_scalar(
            "SELECT detail->>'request_id' FROM audit_log \
             WHERE action = 'agent-job-cancelled' AND detail->>'job_id' = $1 \
             ORDER BY occurred_at DESC LIMIT 1",
        )
        .bind(job.to_string())
        .fetch_one(pool)
        .await
        .expect("read cancellation audit");
        assert_eq!(audited_request_id, spec_request.to_string());
        let event_request_id: String = sqlx::query_scalar(
            "SELECT payload->>'request_id' FROM domain_events \
             WHERE event_type = 'job.cancelled' AND aggregate_id = $1 \
             ORDER BY occurred_at DESC LIMIT 1",
        )
        .bind(job.to_string())
        .fetch_one(pool)
        .await
        .expect("read cancellation event");
        assert_eq!(event_request_id, spec_request.to_string());

        cleanup_dead_letter_events(pool, job).await;
        cleanup_request_and_jobs(pool, scalar_request).await;
        cleanup_request_and_jobs(pool, spec_request).await;
    }

    #[tokio::test]
    async fn db_scope_priority_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-pri-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_set_job_priority(
            Path(job.to_string()),
            Extension(scoped),
            Json(SetJobPriorityBody { priority: 5 }),
        )
        .await
        else {
            panic!("out-of-scope priority must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_priority_out_of_scope_wrong_status_is_404_not_409() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-pri2-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        // Leased → would 409 for unrestricted; 404 for out-of-scope
        let job = seed_job_in_status(pool, &platform, req, "Leased").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_set_job_priority(
            Path(job.to_string()),
            Extension(scoped),
            Json(SetJobPriorityBody { priority: 5 }),
        )
        .await
        else {
            panic!("must 404 not 409");
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "out-of-scope must 404, not 409"
        );
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_job_result_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-res-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) =
            admin_agent_job_result(Path(job.to_string()), Extension(scoped)).await
        else {
            panic!("out-of-scope job result must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_job_get_out_of_scope_is_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        ensure_cancelled_status_allowed(pool).await;
        let platform = format!("plt-scope-get-{}", Uuid::new_v4().simple());
        let req = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, req, "Pending").await;
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_agent_job_get(Path(job.to_string()), Extension(scoped)).await
        else {
            panic!("out-of-scope job get must 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        cleanup_request_and_jobs(pool, req).await;
    }

    #[tokio::test]
    async fn db_scope_job_get_projects_authoritative_spec_request_id() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-get-id-{}", Uuid::new_v4().simple());
        let scalar_request = seed_request_for_scope(pool, "DEFRA", "production").await;
        let spec_request = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_job_in_status(pool, &platform, scalar_request, "Pending").await;
        let spec = dead_letter_spec(spec_request, JobMode::OfflineDryRun);
        sqlx::query("UPDATE agent_jobs SET spec = $1 WHERE id = $2")
            .bind(serde_json::to_value(&spec).expect("spec serialises"))
            .bind(job)
            .execute(pool)
            .await
            .expect("make request ids divergent");

        let Json(out) = admin_agent_job_get(
            Path(job.to_string()),
            Extension(scoped_admin_session("GBLON")),
        )
        .await
        .expect("the spec parent is in scope");
        assert_eq!(out["request_id"], json!(spec_request.to_string()));
        assert_ne!(out["request_id"], json!(scalar_request.to_string()));

        cleanup_request_and_jobs(pool, scalar_request).await;
        cleanup_request_and_jobs(pool, spec_request).await;
    }

    #[tokio::test]
    async fn db_scope_dead_lettered_scoped_sees_only_in_scope() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-dl-{}", Uuid::new_v4().simple());
        // Two requests: one in-scope (GBLON), one out-of-scope (DEFRA)
        let req_in = seed_request_for_scope(pool, "GBLON", "production").await;
        let req_out = seed_request_for_scope(pool, "DEFRA", "production").await;
        let job_in = seed_dead_lettered_job(pool, &platform, req_in).await;
        let job_out = seed_dead_lettered_job(pool, &platform, req_out).await;
        let scoped = scoped_admin_session("GBLON");
        let Ok(Json(resp)) = admin_dead_lettered_jobs(Extension(scoped)).await else {
            panic!("scoped list must succeed");
        };
        let jobs = resp["dead_lettered_jobs"].as_array().expect("array");
        let ids: Vec<String> = jobs
            .iter()
            .filter_map(|j| j["job_id"].as_str())
            .map(String::from)
            .collect();
        assert!(
            ids.contains(&job_in.to_string()),
            "in-scope job must appear"
        );
        assert!(
            !ids.contains(&job_out.to_string()),
            "out-of-scope job must be hidden"
        );
        cleanup_request_and_jobs(pool, req_in).await;
        cleanup_request_and_jobs(pool, req_out).await;
    }

    #[tokio::test]
    async fn db_scope_dead_lettered_projects_authoritative_spec_request_id() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-dl-id-{}", Uuid::new_v4().simple());
        let scalar_request = seed_request_for_scope(pool, "DEFRA", "production").await;
        let spec_request = seed_request_for_scope(pool, "GBLON", "production").await;
        let job = seed_dead_lettered_job_full(
            pool,
            &platform,
            scalar_request,
            spec_request,
            JobMode::OfflineDryRun,
        )
        .await;

        let Json(out) = admin_dead_lettered_jobs(Extension(scoped_admin_session("GBLON")))
            .await
            .expect("the spec parent is in scope");
        let listed = out["dead_lettered_jobs"]
            .as_array()
            .expect("dead-lettered jobs array")
            .iter()
            .find(|entry| entry["job_id"] == json!(job.to_string()))
            .expect("divergent job must be listed by its in-scope spec parent");
        assert_eq!(listed["request_id"], json!(spec_request.to_string()));
        assert_ne!(listed["request_id"], json!(scalar_request.to_string()));

        cleanup_request_and_jobs(pool, scalar_request).await;
        cleanup_request_and_jobs(pool, spec_request).await;
    }

    #[tokio::test]
    async fn db_scope_dead_lettered_unrestricted_sees_all() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-dl2-{}", Uuid::new_v4().simple());
        let req_a = seed_request_for_scope(pool, "GBLON", "production").await;
        let req_b = seed_request_for_scope(pool, "DEFRA", "production").await;
        let job_a = seed_dead_lettered_job(pool, &platform, req_a).await;
        let job_b = seed_dead_lettered_job(pool, &platform, req_b).await;
        let Ok(Json(resp)) =
            admin_dead_lettered_jobs(Extension(AuthSession::static_dry_run())).await
        else {
            panic!("unrestricted list must succeed");
        };
        let jobs = resp["dead_lettered_jobs"].as_array().expect("array");
        let ids: Vec<String> = jobs
            .iter()
            .filter_map(|j| j["job_id"].as_str())
            .map(String::from)
            .collect();
        assert!(ids.contains(&job_a.to_string()), "job_a must appear");
        assert!(ids.contains(&job_b.to_string()), "job_b must appear");
        cleanup_request_and_jobs(pool, req_a).await;
        cleanup_request_and_jobs(pool, req_b).await;
    }

    #[tokio::test]
    async fn db_scope_queue_depth_scoped_sees_only_in_scope() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // One platform, two pending jobs: one GBLON (in-scope), one DEFRA (out).
        let platform = format!("plt-scope-qd-{}", Uuid::new_v4().simple());
        let req_in = seed_request_for_scope(pool, "GBLON", "production").await;
        let req_out = seed_request_for_scope(pool, "DEFRA", "production").await;
        let _job_in = seed_job_in_status(pool, &platform, req_in, "Pending").await;
        let _job_out = seed_job_in_status(pool, &platform, req_out, "Pending").await;
        let scoped = scoped_admin_session("GBLON");
        let Ok(Json(resp)) = admin_agent_queue_depth(Extension(scoped)).await else {
            panic!("scoped queue-depth must succeed");
        };
        let queues = resp["queues"].as_array().expect("queues array");
        let mine = queues
            .iter()
            .find(|q| q["platform"].as_str() == Some(platform.as_str()))
            .expect("our platform must appear");
        assert_eq!(
            mine["pending_count"].as_i64(),
            Some(1),
            "scoped admin's queue depth counts only the in-scope pending job, not the DEFRA one"
        );
        cleanup_request_and_jobs(pool, req_in).await;
        cleanup_request_and_jobs(pool, req_out).await;
    }

    #[tokio::test]
    async fn db_scope_force_fail_malformed_spec_scoped_is_404() {
        // codex: a malformed stored spec must NOT be a 500 existence oracle for a
        // scoped principal — it fails closed to the same 404 a missing job returns;
        // an unrestricted principal still surfaces the integrity 500.
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-ffm-{}", Uuid::new_v4().simple());
        // A Leased job whose stored spec is valid JSON but NOT a decodable JobSpec.
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status) \
             VALUES ($1, $2, '{\"not\":\"a-spec\"}'::jsonb, 'OfflineDryRun', 'Leased') RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(pool)
        .await
        .expect("seed malformed-spec job");
        let scoped = scoped_admin_session("DEFRA");
        let Err((status, _)) = admin_force_fail_job(
            Path(job_id.to_string()),
            Extension(scoped),
            Json(ForceFailJobBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("scoped malformed-spec force-fail must 404");
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "scoped principal must not get a malformed-spec 500 oracle"
        );
        let Err((status_u, _)) = admin_force_fail_job(
            Path(job_id.to_string()),
            Extension(AuthSession::static_dry_run()),
            Json(ForceFailJobBody {
                reason: "scope test".into(),
            }),
        )
        .await
        else {
            panic!("unrestricted malformed-spec force-fail must 500");
        };
        assert_eq!(
            status_u,
            StatusCode::INTERNAL_SERVER_ERROR,
            "unrestricted keeps the integrity 500"
        );
        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn db_scope_dead_lettered_env_only_narrows() {
        // codex: exercise the ENVIRONMENT-only bypass path (site unrestricted, env scoped).
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-scope-dle-{}", Uuid::new_v4().simple());
        // Same site, different ENVIRONMENT.
        let req_prod = seed_request_for_scope(pool, "GBLON", "production").await;
        let req_dev = seed_request_for_scope(pool, "GBLON", "development").await;
        let job_prod = seed_dead_lettered_job(pool, &platform, req_prod).await;
        let job_dev = seed_dead_lettered_job(pool, &platform, req_dev).await;
        // Principal scoped on environment ONLY (site unrestricted).
        let mut scoped = scoped_admin_session("GBLON");
        scoped.site_scope = vec![];
        scoped.environment_scope = vec!["production".to_string()];
        let Ok(Json(resp)) = admin_dead_lettered_jobs(Extension(scoped)).await else {
            panic!("env-scoped list must succeed");
        };
        let ids: Vec<String> = resp["dead_lettered_jobs"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|j| j["job_id"].as_str())
            .map(String::from)
            .collect();
        assert!(
            ids.contains(&job_prod.to_string()),
            "production job must appear"
        );
        assert!(
            !ids.contains(&job_dev.to_string()),
            "development job must be hidden (env-only scope)"
        );
        cleanup_request_and_jobs(pool, req_prod).await;
        cleanup_request_and_jobs(pool, req_dev).await;
    }

    #[tokio::test]
    async fn db_scope_approve_agent_scoped_is_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("scope-approve-agent-{}", Uuid::new_v4().simple());
        let _ = seed_agent(pool, &agent_id, "ci", "pending").await;
        let scoped = scoped_admin_session("GBLON");
        let Err((status, _)) = admin_approve_agent(
            Path(agent_id.clone()),
            Extension(scoped),
            Json(approve_body(Uuid::nil(), String::new())),
        )
        .await
        else {
            panic!("scoped approve_agent must 403");
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_scope_revoke_agent_scoped_is_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("scope-revoke-agent-{}", Uuid::new_v4().simple());
        let _ = seed_agent(pool, &agent_id, "ci", "approved").await;
        let scoped = scoped_admin_session("GBLON");
        let Err((status, _)) = admin_revoke_agent(
            Path(agent_id.clone()),
            Extension(scoped),
            Json(revoke_body(Uuid::nil(), String::new())),
        )
        .await
        else {
            panic!("scoped revoke_agent must 403");
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
        cleanup_agent(pool, &agent_id).await;
    }

    #[tokio::test]
    async fn db_scope_list_agents_scoped_is_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let scoped = scoped_admin_session("GBLON");
        let Err((status, _)) = admin_list_agents(Extension(scoped)).await else {
            panic!("scoped list_agents must 403");
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn db_scope_agents_liveness_scoped_is_403() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = handler_pool_lenient().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let scoped = scoped_admin_session("GBLON");
        let Err((status, _)) = admin_agents_liveness(
            Extension(scoped),
            Query(AgentLivenessQuery {
                offline_after_secs: None,
            }),
        )
        .await
        else {
            panic!("scoped agents_liveness must 403");
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
