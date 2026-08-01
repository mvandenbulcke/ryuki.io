//! Inbound webhook RECEIVER (#18 slice 2b — FINAL slice) — the public handler.
//!
//! An external system (ServiceNow, monitoring, CI) POSTs a signed webhook to
//! `/api/integrations/{connection_id}/webhook`. This is a PUBLIC endpoint with NO
//! human session. It authenticates a versioned canonical message containing the
//! fixed method/path, connection id, credential generation, authoritative
//! vendor/site digest, Unix timestamp, delivery id, and SHA-256 of the exact raw
//! body against the connection's dedicated webhook secret.
//!
//! SECURITY-CRITICAL, fail-closed at every step:
//! - The body extractor is `axum::body::Bytes`, NOT `Json` — the canonical
//!   message covers a digest of the EXACT bytes the caller sent, so the body MUST
//!   be read raw and MUST be the LAST extractor (axum consumes it once).
//! - `X-Ryuki-Webhook-Timestamp` is canonical Unix time in seconds and must be
//!   within five minutes of both the API and database clocks.
//! - `X-Ryuki-Webhook-Delivery-Id` is authenticated and claimed durably. The
//!   event and receipt commit together; an exact retry returns the original
//!   event id, while a delivery-id/content collision fails closed.
//! - The HMAC input is the UTF-8 byte sequence below with no trailing newline:
//!   `ryuki-webhook-v2\nmethod:POST\npath:/api/integrations/{connection_id}/webhook\n`
//!   `connection-id:{connection_id}\ncredential-generation:{generation}\n`
//!   `authority-context-sha256:{lower_hex}\ntimestamp:{unix_seconds}\n`
//!   `delivery-id:{delivery_id}\nbody-sha256:{lower_hex}`.
//! - Secret resolution, generation/context selection, HMAC verification, receipt
//!   claim, and event attribution occur in one transaction holding `FOR SHARE`
//!   locks on the connection and immutable secret row. Rotation, reassignment,
//!   and deletion therefore cannot swap authority between verification and use.
//! - Every "this request is not authenticated" path — unknown connection id, a
//!   connection with no webhook secret configured, a missing secret row, AND a
//!   wrong signature — returns the SAME 401 with the SAME body. This is the
//!   NO-ORACLE merge point for the RESPONSE (status + body): a caller cannot
//!   distinguish "connection doesn't exist" from "exists but isn't webhook-enabled"
//!   from "wrong secret" by reading the reply.
//!   NOTE — the merge equalizes status and body, NOT response LATENCY: a configured
//!   connection does a second query plus an AES-GCM decrypt before the signature
//!   check, whereas the unknown/unconfigured paths short-circuit after one query, so
//!   timing can still statistically distinguish webhook-enabled connections. This is
//!   a minor side channel (network jitter largely masks it, and the endpoint is body-
//!   size- and rate-limited); equalizing the timing (padding the fast path with a
//!   dummy decrypt+HMAC) is deferred hardening, not done here.
//! - A real DB/decrypt failure (`resolve_webhook_secret` returning `Err`) is a
//!   generic 500, logged server-side only — its `Display` can leak SQL/vault
//!   internals (see `integration::CredError`), so it must never ride in the body.
//!
//! Recording the domain event is the ENTIRE behavior of this slice. There is NO
//! auto-triggering of any platform action (no request creation, no advance, no
//! mutation of anything besides the `domain_events` append) — wiring a verified
//! webhook to actually drive the platform is a later, owner-gated slice.
//!
//! The whole-app outer stack has an always-on, fail-fast webhook admission gate:
//! bounded salted per-client buckets, one process-global bucket, and a strict
//! in-flight ceiling. It runs before the queueing whole-app concurrency layer,
//! request telemetry, body extraction, database access, secret decryption, or
//! HMAC work and remains active when the optional general API limiter is
//! disabled. The route also has an independent 256 KiB body cap.

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use serde_json::json;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::database::get_db;
use crate::integration::resolve_webhook_authority;
use crate::repos::domain_events::{self, NewEvent};
use crate::repos::inbound_webhook_receipts;

const WEBHOOK_SIGNATURE_VERSION: i16 = 2;
const WEBHOOK_SIGNATURE_DOMAIN: &str = "ryuki-webhook-v2";
const WEBHOOK_TIMESTAMP_HEADER: &str = "X-Ryuki-Webhook-Timestamp";
const WEBHOOK_DELIVERY_ID_HEADER: &str = "X-Ryuki-Webhook-Delivery-Id";
const WEBHOOK_MAX_CLOCK_SKEW_SECS: i64 = 300;
const WEBHOOK_MAX_DELIVERY_ID_BYTES: usize = 128;
const WEBHOOK_MAX_CONNECTION_ID_BYTES: usize = 128;
const WEBHOOK_MAX_BODY_BYTES: usize = 256 * 1024;

const WEBHOOK_CLIENT_REQUESTS_PER_SECOND: u32 = 5;
const WEBHOOK_CLIENT_BURST: u32 = 10;
const WEBHOOK_GLOBAL_REQUESTS_PER_SECOND: u32 = 50;
const WEBHOOK_GLOBAL_BURST: u32 = 100;
const WEBHOOK_MAX_IN_FLIGHT: usize = 4;
const WEBHOOK_RATE_LIMIT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
/// Emit the first rejection for each reason, then one aggregate sample per
/// bounded interval. This keeps a sustained anonymous flood from turning the
/// observability path into a second amplification sink while retaining both an
/// immediate signal and monotonic per-reason totals.
const WEBHOOK_REJECTION_LOG_SAMPLE_EVERY: u64 = 256;

type WebhookClientRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

fn maintain_keyed_rate_limiter<K, S, C, MW>(limiter: &RateLimiter<K, S, C, MW>)
where
    K: std::hash::Hash,
    S: governor::state::keyed::ShrinkableKeyedStateStore<K>,
    C: governor::clock::Clock,
    MW: governor::middleware::RateLimitingMiddleware<C::Instant>,
{
    limiter.retain_recent();
    limiter.shrink_to_fit();
}

#[derive(Clone)]
pub(crate) struct WebhookAdmission {
    per_client: Arc<WebhookClientRateLimiter>,
    global: Arc<DefaultDirectRateLimiter>,
    in_flight: Arc<tokio::sync::Semaphore>,
    bucket_salt: [u8; 32],
    trusted_proxies: Arc<Vec<ryuki_core::config::TrustedProxyNetwork>>,
    telemetry: Arc<WebhookAdmissionTelemetry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionRejection {
    ClientRate,
    GlobalRate,
    InFlight,
}

impl AdmissionRejection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientRate => "client_rate",
            Self::GlobalRate => "global_rate",
            Self::InFlight => "in_flight",
        }
    }
}

#[derive(Default)]
struct WebhookAdmissionTelemetry {
    client_rate: AtomicU64,
    global_rate: AtomicU64,
    in_flight: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebhookAdmissionRejectionSnapshot {
    client_rate: u64,
    global_rate: u64,
    in_flight: u64,
}

impl WebhookAdmissionTelemetry {
    fn record(&self, rejection: AdmissionRejection) -> Option<WebhookAdmissionRejectionSnapshot> {
        let counter = match rejection {
            AdmissionRejection::ClientRate => &self.client_rate,
            AdmissionRejection::GlobalRate => &self.global_rate,
            AdmissionRejection::InFlight => &self.in_flight,
        };
        let reason_count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if reason_count != 1 && reason_count % WEBHOOK_REJECTION_LOG_SAMPLE_EVERY != 0 {
            return None;
        }
        Some(self.snapshot())
    }

    fn snapshot(&self) -> WebhookAdmissionRejectionSnapshot {
        WebhookAdmissionRejectionSnapshot {
            client_rate: self.client_rate.load(Ordering::Relaxed),
            global_rate: self.global_rate.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
        }
    }
}

impl WebhookAdmission {
    pub(crate) fn production(
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> Self {
        Self::new(
            WEBHOOK_CLIENT_REQUESTS_PER_SECOND,
            WEBHOOK_CLIENT_BURST,
            WEBHOOK_GLOBAL_REQUESTS_PER_SECOND,
            WEBHOOK_GLOBAL_BURST,
            WEBHOOK_MAX_IN_FLIGHT,
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
            telemetry: Arc::new(WebhookAdmissionTelemetry::default()),
        }
    }

    fn try_admit(
        &self,
        peer_addr: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, AdmissionRejection> {
        let (client_key, _) = crate::resolve_rate_limit_client_key_from_headers(
            peer_addr,
            headers,
            &self.trusted_proxies,
        );
        let bucket = crate::bounded_rate_limit_key("webhook", &client_key, &self.bucket_salt);
        // Keep the source-specific check first: a source that has exhausted its
        // own quota must not consume the shared quota and starve other senders.
        // The salted bucket namespace is finite, and periodic maintenance below
        // reclaims entries once their budget is indistinguishable from fresh.
        self.per_client
            .check_key(&bucket)
            .map_err(|_| AdmissionRejection::ClientRate)?;
        self.global
            .check()
            .map_err(|_| AdmissionRejection::GlobalRate)?;
        self.in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionRejection::InFlight)
    }

    fn maintain_keyed_state(&self) {
        maintain_keyed_rate_limiter(self.per_client.as_ref());
    }

    pub(crate) fn spawn_maintenance(&self) {
        let admission = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(WEBHOOK_RATE_LIMIT_MAINTENANCE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Tokio intervals tick immediately. Consume that tick so startup
            // does not schedule an unnecessary blocking maintenance task.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let admission = admission.clone();
                if let Err(error) =
                    tokio::task::spawn_blocking(move || admission.maintain_keyed_state()).await
                {
                    tracing::error!(
                        error = %error,
                        "webhook rate-limit state maintenance failed"
                    );
                }
            }
        });
    }

    fn record_rejection(
        &self,
        rejection: AdmissionRejection,
    ) -> Option<WebhookAdmissionRejectionSnapshot> {
        self.telemetry.record(rejection)
    }
}

type WebhookResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()})))
}

/// The SAME body for every "not authenticated" outcome — unknown connection,
/// unconfigured webhook secret, and bad signature must be indistinguishable.
fn signature_verification_failed() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "signature verification failed"})),
    )
}

fn generic_500(
    context: &str,
    err: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    // Log server-side; the body stays generic. `err` may be a raw sqlx/decrypt
    // Display (CredError::Db wraps a raw sqlx error string) — never leak it.
    tracing::error!(error = %err, context, "inbound webhook error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal error"})),
    )
}

fn accepted(event_id: i64) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::ACCEPTED,
        Json(json!({"status": "accepted", "event_id": event_id})),
    )
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn identifier_is_canonical(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_signed_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if value.is_empty() || value.len() > 20 {
        return None;
    }
    let seconds = value.parse::<i64>().ok()?;
    if seconds.to_string() != value {
        return None;
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
}

fn timestamp_is_fresh(
    signed_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let lower = now.checked_sub_signed(chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS));
    let upper = now.checked_add_signed(chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS));
    matches!((lower, upper), (Some(lower), Some(upper)) if signed_at >= lower && signed_at <= upper)
}

/// Domain-separated, line-oriented v2 message. Every interpolated identifier
/// is restricted to `[A-Za-z0-9._-]`, the timestamp has one canonical decimal
/// representation, and the body digest is fixed-length lowercase hex, so no
/// field can inject a delimiter or create an alternate parse.
fn canonical_webhook_message(
    connection_id: &str,
    credential_generation: i64,
    authority_context_sha256: &str,
    signed_at: chrono::DateTime<chrono::Utc>,
    delivery_id: &str,
    body_sha256: &str,
) -> String {
    format!(
        "{WEBHOOK_SIGNATURE_DOMAIN}\nmethod:POST\npath:/api/integrations/{connection_id}/webhook\n\
         connection-id:{connection_id}\ncredential-generation:{credential_generation}\n\
         authority-context-sha256:{authority_context_sha256}\ntimestamp:{}\n\
         delivery-id:{delivery_id}\n\
         body-sha256:{body_sha256}",
        signed_at.timestamp()
    )
}

fn admission_response(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = (status, Json(json!({"error": code, "message": message}))).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn is_webhook_request(method: &Method, path: &str) -> bool {
    if *method != Method::POST {
        return false;
    }
    path.strip_prefix("/api/integrations/")
        .and_then(|rest| rest.strip_suffix("/webhook"))
        .is_some_and(|connection_id| !connection_id.is_empty() && !connection_id.contains('/'))
}

pub(crate) async fn webhook_admission_middleware(
    State(admission): State<WebhookAdmission>,
    request: Request,
    next: Next,
) -> Response {
    if !is_webhook_request(request.method(), request.uri().path()) {
        return next.run(request).await;
    }
    let Some(ConnectInfo(peer_addr)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        tracing::error!("webhook peer address unavailable; failing admission closed");
        return admission_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "WEBHOOK_ADMISSION_CONTEXT_UNAVAILABLE",
            "Webhook admission context is unavailable",
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
                    sample_every = WEBHOOK_REJECTION_LOG_SAMPLE_EVERY,
                    "webhook admission rejections (sampled aggregate)"
                );
            }
            return admission_response(
                StatusCode::TOO_MANY_REQUESTS,
                "WEBHOOK_ADMISSION_EXCEEDED",
                "Too many webhook requests",
            );
        }
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

/// POST /api/integrations/{connection_id}/webhook
///
/// PUBLIC — no human session or agent bearer. Requires
/// `X-Ryuki-Webhook-Timestamp`, `X-Ryuki-Webhook-Delivery-Id`, and an
/// `X-Hub-Signature-256` HMAC over the module's v2 canonical message. A first
/// verified delivery records one domain event; an exact retry returns that
/// event's original id. The external payload is capped at 256 KiB and is never
/// echoed or stored.
pub async fn webhook_receive(
    Path(connection_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> WebhookResult<(StatusCode, Json<serde_json::Value>)> {
    // (b) DB unavailable is a generic 500, not a 401 — this is an infra failure,
    // not a failed authentication, and must not be folded into the no-oracle path.
    let pool = get_db().ok_or_else(|| generic_500("database unavailable", "no pool"))?;
    webhook_receive_with_pool(connection_id, headers, body, pool).await
}

/// Testable core: same contract as [`webhook_receive`] but takes the pool
/// directly, so DB tests can exercise it against a real Postgres instance
/// without going through `get_db()`'s process-global `OnceLock` (mirrors
/// `agents::post_job_result` / `post_job_result_with_pool`).
async fn webhook_receive_with_pool(
    connection_id: String,
    headers: HeaderMap,
    body: Bytes,
    pool: &sqlx::PgPool,
) -> WebhookResult<(StatusCode, Json<serde_json::Value>)> {
    webhook_receive_with_pool_at(connection_id, headers, body, pool, chrono::Utc::now()).await
}

async fn webhook_receive_with_pool_at(
    connection_id: String,
    headers: HeaderMap,
    body: Bytes,
    pool: &sqlx::PgPool,
    application_now: chrono::DateTime<chrono::Utc>,
) -> WebhookResult<(StatusCode, Json<serde_json::Value>)> {
    // (a) Signature header must be present and a valid ASCII header value.
    let sig = single_header(&headers, "X-Hub-Signature-256")
        .ok_or_else(|| bad_request("missing or malformed X-Hub-Signature-256"))?;

    // Cheap pre-DB gate: a valid HMAC-SHA256 is exactly 32 bytes = 64 hex chars
    // (optional "sha256=" prefix). Reject anything that cannot possibly be one
    // BEFORE touching the database, so garbage-signature spam is turned away at
    // ZERO db cost. A well-formed wrong signature still needs the secret below,
    // but the subrouter's mandatory per-client/global/concurrency gate admits only
    // a bounded amount of that work. This returns the SAME uniform 401 as every
    // other auth failure and adds no connection-existence oracle.
    let hex_part = sig.strip_prefix("sha256=").unwrap_or(sig).trim();
    if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(signature_verification_failed());
    }

    let timestamp = single_header(&headers, WEBHOOK_TIMESTAMP_HEADER)
        .ok_or_else(|| bad_request(format!("missing or malformed {WEBHOOK_TIMESTAMP_HEADER}")))?;
    let delivery_id = single_header(&headers, WEBHOOK_DELIVERY_ID_HEADER)
        .ok_or_else(|| bad_request(format!("missing or malformed {WEBHOOK_DELIVERY_ID_HEADER}")))?;

    if !identifier_is_canonical(&connection_id, WEBHOOK_MAX_CONNECTION_ID_BYTES)
        || !identifier_is_canonical(delivery_id, WEBHOOK_MAX_DELIVERY_ID_BYTES)
    {
        return Err(signature_verification_failed());
    }
    let Some(signed_at) = parse_signed_timestamp(timestamp) else {
        return Err(signature_verification_failed());
    };
    if !timestamp_is_fresh(signed_at, application_now) {
        return Err(signature_verification_failed());
    }

    let delivery_id = delivery_id.to_string();
    let body_sha256 = ryuki_protocol::sha256_hex(&body);

    let mut tx = pool
        .begin()
        .await
        .map_err(|error| generic_500("webhook transaction begin failed", error))?;
    inbound_webhook_receipts::enable_contract_v2(&mut tx)
        .await
        .map_err(|error| generic_500("webhook contract activation failed", error))?;

    // (c) NO-ORACLE MERGE POINT: unknown connection id, no webhook secret
    // configured, and a missing secret row all resolve to `Ok(None)` inside
    // `resolve_webhook_authority` and MUST all produce the identical 401 below
    // as a wrong signature (d). The joined connection/credential rows remain
    // share-locked in this transaction through the receipt/event commit.
    let authority = match resolve_webhook_authority(&mut tx, &connection_id).await {
        Err(error) => return Err(generic_500("resolve_webhook_authority failed", error)),
        Ok(None) => return Err(signature_verification_failed()),
        Ok(Some(authority)) => authority,
    };
    let canonical_message = canonical_webhook_message(
        &connection_id,
        authority.generation,
        &authority.authority_context_sha256,
        signed_at,
        &delivery_id,
        &body_sha256,
    );

    // (d) Bad signature is INDISTINGUISHABLE from (c)'s None case — same status,
    // same body.
    if !ryuki_engine::webhook_receipt::verify_hmac_sha256(
        &authority.secret,
        canonical_message.as_bytes(),
        sig,
    ) {
        return Err(signature_verification_failed());
    }

    // Serialize this delivery before the final clock read. The cleanup worker
    // attempts the same key without waiting, so it cannot delete a receipt after
    // this transaction has established freshness but before it claims/reads the
    // key. A hash collision only serializes unrelated deliveries.
    let advisory_lock_key =
        inbound_webhook_receipts::advisory_lock_key(&connection_id, &delivery_id);
    inbound_webhook_receipts::lock_delivery(&mut tx, advisory_lock_key)
        .await
        .map_err(|error| generic_500("webhook delivery lock failed", error))?;

    // The database clock is authoritative across replicas. The application
    // check above cheaply drops stale traffic before secret resolution; this
    // second, non-transaction-stable read occurs after any delivery-lock wait,
    // preventing a skewed or paused replica from accepting it durably.
    let database_now: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| generic_500("database clock read failed", error))?;
    if !timestamp_is_fresh(signed_at, database_now) {
        tx.rollback()
            .await
            .map_err(|error| generic_500("stale webhook rollback failed", error))?;
        return Err(signature_verification_failed());
    }
    let expires_at = signed_at
        .checked_add_signed(chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS))
        .ok_or_else(signature_verification_failed)?;

    // A new, fresh delivery may reuse an identifier only after its old replay
    // window has expired. This targeted delete obeys delivery-lock ordering;
    // global cleanup runs independently and never participates in event work.
    inbound_webhook_receipts::delete_expired_target(
        &mut tx,
        &connection_id,
        &delivery_id,
        database_now,
    )
    .await
    .map_err(|error| generic_500("expired webhook target cleanup failed", error))?;

    if let Some(existing) =
        inbound_webhook_receipts::get_for_update(&mut tx, &connection_id, &delivery_id)
            .await
            .map_err(|error| generic_500("webhook receipt lookup failed", error))?
    {
        let duplicate_event_id = (existing.signature_version == WEBHOOK_SIGNATURE_VERSION
            && existing.webhook_secret_ref.as_deref() == Some(authority.secret_ref.as_str())
            && existing.webhook_secret_generation == Some(authority.generation)
            && existing.authority_context_sha256.as_deref()
                == Some(authority.authority_context_sha256.as_str())
            && existing.webhook_vendor_type.as_deref() == Some(authority.vendor_type.as_str())
            && existing.webhook_site_scope == authority.site_scope
            && existing.signed_at == signed_at
            && existing.body_sha256 == body_sha256)
            .then_some(existing.event_id)
            .flatten();
        let matching_but_unbound = existing.signature_version == WEBHOOK_SIGNATURE_VERSION
            && existing.webhook_secret_ref.as_deref() == Some(authority.secret_ref.as_str())
            && existing.webhook_secret_generation == Some(authority.generation)
            && existing.authority_context_sha256.as_deref()
                == Some(authority.authority_context_sha256.as_str())
            && existing.webhook_vendor_type.as_deref() == Some(authority.vendor_type.as_str())
            && existing.webhook_site_scope == authority.site_scope
            && existing.signed_at == signed_at
            && existing.body_sha256 == body_sha256
            && existing.event_id.is_none();
        tx.rollback()
            .await
            .map_err(|error| generic_500("duplicate webhook rollback failed", error))?;
        if let Some(event_id) = duplicate_event_id {
            return Ok(accepted(event_id));
        }
        if matching_but_unbound {
            return Err(generic_500(
                "webhook receipt invariant failed",
                "claimed receipt has no committed event",
            ));
        }
        return Err(signature_verification_failed());
    }

    let claimed = inbound_webhook_receipts::try_claim(
        &mut tx,
        &connection_id,
        &delivery_id,
        WEBHOOK_SIGNATURE_VERSION,
        &authority.secret_ref,
        authority.generation,
        &authority.authority_context_sha256,
        &authority.vendor_type,
        authority.site_scope.as_deref(),
        signed_at,
        &body_sha256,
        advisory_lock_key,
        expires_at,
    )
    .await
    .map_err(|error| generic_500("webhook receipt claim failed", error))?;

    if !claimed {
        // All v2 delivery writers take the same transaction advisory lock, so
        // an absent key cannot become occupied between the locked read and this
        // insert. Treat a conflict as a database/application invariant failure;
        // never append an unreceipted event.
        return Err(generic_500(
            "webhook receipt invariant failed",
            "delivery key changed while transaction lock was held",
        ));
    }

    // Signature verification and event attribution consume the exact same
    // locked authority snapshot. Missing/deleted connections never degrade to
    // an `unknown` actor or unscoped event.
    let actor = format!("webhook:{}", authority.vendor_type);
    let event_id = domain_events::insert(
        &mut *tx,
        NewEvent {
            event_type: "integration.webhook-received",
            aggregate_type: "integration_connection",
            aggregate_id: &connection_id,
            site: authority.site_scope.as_deref(),
            environment: None,
            actor: &actor,
            // NEVER the raw external payload verbatim — only a hash + size, so
            // this event can never become a vector for storing/replaying
            // whatever the external system chose to send.
            payload: json!({
                "connection_id": &connection_id,
                "vendor_type": &authority.vendor_type,
                "signature_version": WEBHOOK_SIGNATURE_VERSION,
                "webhook_secret_generation": authority.generation,
                "authority_context_sha256": &authority.authority_context_sha256,
                "signed_at": signed_at,
                "delivery_id": &delivery_id,
                "body_sha256": &body_sha256,
                "body_bytes": body.len(),
            }),
        },
    )
    .await
    .map_err(|e| generic_500("domain event insert failed", e))?;

    let bound =
        inbound_webhook_receipts::bind_event(&mut tx, &connection_id, &delivery_id, event_id)
            .await
            .map_err(|error| generic_500("webhook receipt event bind failed", error))?;
    if !bound {
        return Err(generic_500(
            "webhook receipt event bind failed",
            "winning receipt was not bindable",
        ));
    }
    tx.commit()
        .await
        .map_err(|error| generic_500("webhook transaction commit failed", error))?;

    Ok(accepted(event_id))
}

/// Router for the inbound webhook receiver. Merged as a SIBLING to
/// `agents::agent_routes()` in `main.rs` — BEFORE `human_gated_app` — so it
/// bypasses `auth_middleware` entirely (there is no human session to check).
/// `main` wraps the whole application in the path-aware feature admission
/// middleware outside the shared concurrency queue. This subrouter retains the
/// feature-specific body cap; trusted-proxy networks are used only by the outer
/// gate to derive a non-spoofable per-client bucket key.
pub fn routes() -> Router {
    Router::new()
        .route(
            "/api/integrations/{connection_id}/webhook",
            post(webhook_receive),
        )
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            WEBHOOK_MAX_BODY_BYTES,
        ))
}

#[cfg(test)]
mod inbound_webhook_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use crate::integration::{webhook_authority_context_digest, webhook_secret_material_was_used};
    use axum::body::Body;
    use axum::middleware;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use sqlx::PgPool;
    use tokio::sync::{Barrier, Notify};
    use tower::ServiceExt;
    use tower::limit::ConcurrencyLimitLayer;

    /// Mirrors the `global_pool()` helper used throughout agents.rs / background.rs
    /// / scheduler.rs db test modules: connects via the REAL `try_connect_with_url`
    /// (populating the process-global `OnceLock` `get_db()` reads from) rather than
    /// a throwaway pool, so this exercises the exact same pool the production
    /// `webhook_receive` wrapper would use.
    async fn global_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()
            .expect("RYUKI_DATABASE_URL is set but the DB connection failed");
        crate::database::run_migrations(pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    fn test_encryption_key() -> String {
        std::env::var("RYUKI_INTEGRATION__ENCRYPTION_KEY").unwrap_or_else(|_| {
            // Generate per-test material so static secret detectors never need
            // to distinguish a deterministic fixture from production key data.
            base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 32]>())
        })
    }

    fn now_iso() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    async fn insert_test_connection(pool: &PgPool, id: &str, site_scope: Option<&str>) {
        let now = now_iso();
        sqlx::query(
            "INSERT INTO integration_connections \
             (id, vendor_type, name, endpoint_url, site_scope, credential_source, credential_ref, \
              status, readiness, execution_mode, created_by, created_at, updated_at) \
             VALUES ($1, 'servicenow', 'inbound-webhook-test', 'https://x.example', $2, \
                     'vault', 'p', 'configured', 'configured', 'static-dry-run', \
                     'sys', $3, $3)",
        )
        .bind(id)
        .bind(site_scope)
        .bind(&now)
        .execute(pool)
        .await
        .expect("insert connection");
    }

    async fn cleanup_connection(pool: &PgPool, id: &str) {
        sqlx::query("DELETE FROM inbound_webhook_receipts WHERE connection_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        // CASCADE deletes integration_secrets rows.
        sqlx::query("DELETE FROM integration_connections WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM domain_events WHERE aggregate_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    #[derive(Clone)]
    struct TestWebhookSigningContext {
        generation: i64,
        authority_context_sha256: String,
    }

    fn signing_context(
        connection_id: &str,
        secret_ref: &str,
        vendor_type: &str,
        site_scope: Option<&str>,
        generation: i64,
    ) -> TestWebhookSigningContext {
        TestWebhookSigningContext {
            generation,
            authority_context_sha256: webhook_authority_context_digest(
                connection_id,
                secret_ref,
                generation,
                vendor_type,
                site_scope,
            ),
        }
    }

    /// Provision a webhook secret directly (bypassing the admin HTTP handler,
    /// which requires a session) by calling `integration::set_webhook_secret`'s
    /// underlying encrypt+store logic inline. We can't call the handler (it
    /// needs an `AuthSession` Extension), so we replicate the minimal insert the
    /// same way `resolve_webhook_secret` expects to read it back.
    async fn provision_webhook_secret(
        pool: &PgPool,
        connection_id: &str,
        secret: &[u8],
    ) -> TestWebhookSigningContext {
        let (vendor_type, site_scope, prior_generation): (String, Option<String>, i64) =
            sqlx::query_as(
                "SELECT vendor_type, site_scope, webhook_secret_generation \
                 FROM integration_connections WHERE id = $1",
            )
            .bind(connection_id)
            .fetch_one(pool)
            .await
            .expect("load webhook authority");
        let generation = prior_generation
            .checked_add(1)
            .expect("test webhook generation");
        let (ciphertext, nonce, _key_id) =
            crate::integration::encrypt_secret(connection_id, secret)
                .expect("encrypt_secret must succeed with a valid test key");
        let secret_id = format!("is-wh-{}", uuid::Uuid::new_v4());
        let now = now_iso();
        sqlx::query(
            "INSERT INTO integration_secrets \
             (id, connection_id, ciphertext, nonce, key_id, webhook_secret_generation, \
              created_at, updated_at) \
             VALUES ($1,$2,$3,$4,'test-key',$5,$6,$6)",
        )
        .bind(&secret_id)
        .bind(connection_id)
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(generation)
        .bind(&now)
        .execute(pool)
        .await
        .expect("insert secret");
        sqlx::query(
            "UPDATE integration_connections \
             SET webhook_secret_ref = $1, webhook_secret_generation = $2 \
             WHERE id = $3",
        )
        .bind(&secret_id)
        .bind(generation)
        .bind(connection_id)
        .execute(pool)
        .await
        .expect("link webhook_secret_ref");
        signing_context(
            connection_id,
            &secret_id,
            &vendor_type,
            site_scope.as_deref(),
            generation,
        )
    }

    fn sign_bytes(secret: &[u8], message: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }

    fn sign_delivery(
        secret: &[u8],
        authority: &TestWebhookSigningContext,
        connection_id: &str,
        timestamp: i64,
        delivery_id: &str,
        body: &[u8],
    ) -> String {
        let signed_at =
            chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0).expect("test timestamp");
        let digest = ryuki_protocol::sha256_hex(body);
        let canonical = canonical_webhook_message(
            connection_id,
            authority.generation,
            &authority.authority_context_sha256,
            signed_at,
            delivery_id,
            &digest,
        );
        sign_bytes(secret, canonical.as_bytes())
    }

    fn headers_for_delivery(sig: Option<&str>, timestamp: i64, delivery_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(sig) = sig {
            headers.insert(
                "X-Hub-Signature-256",
                axum::http::HeaderValue::from_str(sig).unwrap(),
            );
        }
        headers.insert(
            WEBHOOK_TIMESTAMP_HEADER,
            axum::http::HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert(
            WEBHOOK_DELIVERY_ID_HEADER,
            axum::http::HeaderValue::from_str(delivery_id).unwrap(),
        );
        headers
    }

    async fn event_and_receipt_counts(pool: &PgPool, connection_id: &str) -> (i64, i64) {
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM domain_events \
             WHERE aggregate_id = $1 AND event_type = 'integration.webhook-received'",
        )
        .bind(connection_id)
        .fetch_one(pool)
        .await
        .expect("count webhook events");
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM inbound_webhook_receipts WHERE connection_id = $1",
        )
        .bind(connection_id)
        .fetch_one(pool)
        .await
        .expect("count webhook receipts");
        (events, receipts)
    }

    async fn seed_bound_receipt(
        pool: &PgPool,
        connection_id: &str,
        delivery_id: &str,
        signed_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> i64 {
        let mut tx = pool.begin().await.expect("begin receipt seed transaction");
        inbound_webhook_receipts::enable_contract_v2(&mut tx)
            .await
            .expect("enable receipt contract");
        let secret_ref = "is-wh-synthetic-receipt";
        let authority_digest =
            webhook_authority_context_digest(connection_id, secret_ref, 1, "synthetic", None);
        let body_sha256 = ryuki_protocol::sha256_hex(b"synthetic seeded receipt");
        let lock_key = inbound_webhook_receipts::advisory_lock_key(connection_id, delivery_id);
        inbound_webhook_receipts::lock_delivery(&mut tx, lock_key)
            .await
            .expect("lock seeded delivery");
        let event_id = domain_events::insert(
            &mut *tx,
            NewEvent {
                event_type: "integration.webhook-received",
                aggregate_type: "integration_connection",
                aggregate_id: connection_id,
                site: None,
                environment: None,
                actor: "webhook:synthetic",
                payload: json!({
                    "connection_id": connection_id,
                    "signature_version": WEBHOOK_SIGNATURE_VERSION,
                    "webhook_secret_generation": 1,
                    "authority_context_sha256": &authority_digest,
                    "vendor_type": "synthetic",
                    "signed_at": signed_at,
                    "delivery_id": delivery_id,
                    "body_sha256": &body_sha256,
                }),
            },
        )
        .await
        .expect("insert seeded webhook event");
        assert!(
            inbound_webhook_receipts::try_claim(
                &mut tx,
                connection_id,
                delivery_id,
                WEBHOOK_SIGNATURE_VERSION,
                secret_ref,
                1,
                &authority_digest,
                "synthetic",
                None,
                signed_at,
                &body_sha256,
                lock_key,
                expires_at,
            )
            .await
            .expect("claim seeded receipt")
        );
        assert!(
            inbound_webhook_receipts::bind_event(&mut tx, connection_id, delivery_id, event_id,)
                .await
                .expect("bind seeded receipt")
        );
        tx.commit().await.expect("commit seeded receipt");
        event_id
    }

    fn peer(value: &str) -> SocketAddr {
        value.parse().expect("test peer address")
    }

    fn admission_headers(forwarded_for: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(forwarded_for) = forwarded_for {
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(forwarded_for).expect("test forwarded-for header"),
            );
        }
        headers
    }

    fn try_admit(
        admission: &WebhookAdmission,
        peer_addr: SocketAddr,
        forwarded_for: Option<&str>,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, AdmissionRejection> {
        admission.try_admit(peer_addr, &admission_headers(forwarded_for))
    }

    #[test]
    fn canonical_signature_binds_every_security_field() {
        let secret = rand::random::<[u8; 32]>();
        let connection_id = "ic-servicenow-canonical";
        let credential_generation = 7;
        let authority_context_sha256 = webhook_authority_context_digest(
            connection_id,
            "is-wh-canonical",
            credential_generation,
            "servicenow",
            Some("site-a"),
        );
        let delivery_id = "delivery-canonical-001";
        let signed_at = chrono::DateTime::<chrono::Utc>::from_timestamp(2_000_000_000, 0).unwrap();
        let body_digest = ryuki_protocol::sha256_hex(b"synthetic payload");
        let canonical = canonical_webhook_message(
            connection_id,
            credential_generation,
            &authority_context_sha256,
            signed_at,
            delivery_id,
            &body_digest,
        );
        let signature = sign_bytes(&secret, canonical.as_bytes());

        assert!(ryuki_engine::webhook_receipt::verify_hmac_sha256(
            &secret,
            canonical.as_bytes(),
            &signature,
        ));
        for changed in [
            canonical_webhook_message(
                connection_id,
                credential_generation + 1,
                &authority_context_sha256,
                signed_at,
                delivery_id,
                &body_digest,
            ),
            canonical_webhook_message(
                connection_id,
                credential_generation,
                &ryuki_protocol::sha256_hex(b"changed authority context"),
                signed_at,
                delivery_id,
                &body_digest,
            ),
            canonical_webhook_message(
                connection_id,
                credential_generation,
                &authority_context_sha256,
                signed_at + chrono::Duration::seconds(1),
                delivery_id,
                &body_digest,
            ),
            canonical_webhook_message(
                connection_id,
                credential_generation,
                &authority_context_sha256,
                signed_at,
                "delivery-other",
                &body_digest,
            ),
            canonical_webhook_message(
                connection_id,
                credential_generation,
                &authority_context_sha256,
                signed_at,
                delivery_id,
                &ryuki_protocol::sha256_hex(b"changed payload"),
            ),
            canonical.replacen(WEBHOOK_SIGNATURE_DOMAIN, "ryuki-webhook-v3", 1),
            canonical.replacen("method:POST", "method:PUT", 1),
        ] {
            assert!(!ryuki_engine::webhook_receipt::verify_hmac_sha256(
                &secret,
                changed.as_bytes(),
                &signature,
            ));
        }
    }

    #[test]
    fn timestamp_and_delivery_bounds_fail_closed() {
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp(2_000_000_000, 0).unwrap();
        for offset in [-WEBHOOK_MAX_CLOCK_SKEW_SECS, 0, WEBHOOK_MAX_CLOCK_SKEW_SECS] {
            let signed_at = parse_signed_timestamp(&(now.timestamp() + offset).to_string())
                .expect("boundary timestamp parses");
            assert!(timestamp_is_fresh(signed_at, now));
        }
        for offset in [
            -WEBHOOK_MAX_CLOCK_SKEW_SECS - 1,
            WEBHOOK_MAX_CLOCK_SKEW_SECS + 1,
        ] {
            let signed_at = parse_signed_timestamp(&(now.timestamp() + offset).to_string())
                .expect("outside timestamp parses");
            assert!(!timestamp_is_fresh(signed_at, now));
        }
        assert!(parse_signed_timestamp("02000000000").is_none());
        assert!(parse_signed_timestamp("not-a-time").is_none());
        assert!(identifier_is_canonical("delivery-ABC_123.4", 128));
        assert!(!identifier_is_canonical("delivery/escape", 128));
        assert!(!identifier_is_canonical("delivery\nsmuggle", 128));
        assert!(!identifier_is_canonical(&"d".repeat(129), 128));
        assert!(is_webhook_request(
            &Method::POST,
            "/api/integrations/ic-test/webhook"
        ));
        assert!(!is_webhook_request(
            &Method::GET,
            "/api/integrations/ic-test/webhook"
        ));
        assert!(!is_webhook_request(
            &Method::POST,
            "/api/integrations/ic-test/webhook/extra"
        ));
    }

    #[test]
    fn admission_has_per_client_global_and_in_flight_bounds() {
        let client_limited = WebhookAdmission::new(1, 2, 100, 100, 10, Vec::new());
        drop(try_admit(&client_limited, peer("198.51.100.10:443"), None).unwrap());
        drop(try_admit(&client_limited, peer("198.51.100.10:443"), None).unwrap());
        assert!(matches!(
            try_admit(
                &client_limited,
                peer("198.51.100.10:443"),
                Some("203.0.113.250, 203.0.113.251"),
            ),
            Err(AdmissionRejection::ClientRate)
        ));

        let global_limited = WebhookAdmission::new(100, 100, 1, 2, 10, Vec::new());
        drop(try_admit(&global_limited, peer("198.51.100.11:443"), None).unwrap());
        drop(try_admit(&global_limited, peer("198.51.100.12:443"), None).unwrap());
        assert!(matches!(
            try_admit(&global_limited, peer("198.51.100.13:443"), None),
            Err(AdmissionRejection::GlobalRate)
        ));

        let concurrent = WebhookAdmission::new(100, 100, 100, 100, 2, Vec::new());
        let first = try_admit(&concurrent, peer("198.51.100.21:443"), None).unwrap();
        let second = try_admit(&concurrent, peer("198.51.100.22:443"), None).unwrap();
        assert!(matches!(
            try_admit(&concurrent, peer("198.51.100.23:443"), None),
            Err(AdmissionRejection::InFlight)
        ));
        drop((first, second));
    }

    #[test]
    fn admission_client_store_cardinality_is_bounded() {
        let mut admission = WebhookAdmission::new(1, 1, 100, 100, 10, Vec::new());
        admission.bucket_salt = rand::random();

        for index in 0..(u32::from(crate::RATE_LIMIT_CLIENT_BUCKETS) * 2) {
            let client_key = format!("rotating-source-{index}");
            let bucket =
                crate::bounded_rate_limit_key("webhook", &client_key, &admission.bucket_salt);
            let _ = admission.per_client.check_key(&bucket);
        }

        assert!(
            admission.per_client.len() <= usize::from(crate::RATE_LIMIT_CLIENT_BUCKETS),
            "rotating sources must remain inside the fixed webhook bucket namespace"
        );
    }

    #[test]
    fn keyed_state_maintenance_reclaims_only_stale_entries() {
        use governor::clock::FakeRelativeClock;

        let clock = FakeRelativeClock::default();
        let limiter =
            RateLimiter::hashmap_with_clock(Quota::per_second(NonZeroU32::MIN), clock.clone());
        limiter.check_key(&"source-a".to_owned()).unwrap();
        limiter.check_key(&"source-b".to_owned()).unwrap();

        maintain_keyed_rate_limiter(&limiter);
        assert_eq!(limiter.len(), 2, "live budgets must survive maintenance");

        clock.advance(Duration::from_secs(2));
        maintain_keyed_rate_limiter(&limiter);
        assert!(
            limiter.is_empty(),
            "fully replenished client budgets must be evicted"
        );
    }

    #[test]
    fn client_rejection_does_not_spend_the_shared_budget() {
        let mut admission = WebhookAdmission::new(1, 1, 1, 1, 10, Vec::new());
        admission.bucket_salt = rand::random();
        admission.per_client = Arc::new(RateLimiter::keyed(
            Quota::per_hour(NonZeroU32::MIN).allow_burst(NonZeroU32::MIN),
        ));
        admission.global = Arc::new(RateLimiter::direct(
            Quota::per_hour(NonZeroU32::MIN)
                .allow_burst(NonZeroU32::new(2).unwrap_or(NonZeroU32::MIN)),
        ));

        drop(try_admit(&admission, peer("198.51.100.41:443"), None).unwrap());
        assert!(matches!(
            try_admit(&admission, peer("198.51.100.41:443"), None),
            Err(AdmissionRejection::ClientRate)
        ));
        drop(try_admit(&admission, peer("198.51.100.42:443"), None).unwrap());
        assert!(matches!(
            try_admit(&admission, peer("198.51.100.43:443"), None),
            Err(AdmissionRejection::GlobalRate)
        ));
    }

    #[test]
    fn admission_rejection_telemetry_is_aggregated_and_sampled() {
        let admission = WebhookAdmission::new(100, 100, 100, 100, 10, Vec::new());

        let first = admission
            .record_rejection(AdmissionRejection::ClientRate)
            .expect("the first rejection for a reason is logged");
        assert_eq!(
            first,
            WebhookAdmissionRejectionSnapshot {
                client_rate: 1,
                global_rate: 0,
                in_flight: 0,
            }
        );

        for count in 2..WEBHOOK_REJECTION_LOG_SAMPLE_EVERY {
            assert!(
                admission
                    .record_rejection(AdmissionRejection::ClientRate)
                    .is_none(),
                "rejection {count} must be aggregated without a per-request log"
            );
        }
        let sampled = admission
            .record_rejection(AdmissionRejection::ClientRate)
            .expect("the fixed aggregate interval emits one sample");
        assert_eq!(sampled.client_rate, WEBHOOK_REJECTION_LOG_SAMPLE_EVERY);

        let global = admission
            .record_rejection(AdmissionRejection::GlobalRate)
            .expect("the first global-rate rejection emits immediately");
        assert_eq!(global.client_rate, WEBHOOK_REJECTION_LOG_SAMPLE_EVERY);
        assert_eq!(global.global_rate, 1);
        assert_eq!(global.in_flight, 0);

        let in_flight = admission
            .record_rejection(AdmissionRejection::InFlight)
            .expect("the first in-flight rejection emits immediately");
        assert_eq!(in_flight.client_rate, WEBHOOK_REJECTION_LOG_SAMPLE_EVERY);
        assert_eq!(in_flight.global_rate, 1);
        assert_eq!(in_flight.in_flight, 1);
    }

    #[test]
    fn duplicate_or_malformed_forwarding_evidence_falls_back_to_peer_bucket() {
        let trusted = vec![
            ryuki_core::config::TrustedProxyNetwork::parse("10.0.0.0/8")
                .expect("trusted proxy fixture"),
        ];
        let admission = WebhookAdmission::new(1, 1, 100, 100, 10, trusted);
        let proxy = peer("10.0.0.5:443");

        let mut duplicate = HeaderMap::new();
        duplicate.append("x-forwarded-for", HeaderValue::from_static("198.51.100.40"));
        duplicate.append("x-forwarded-for", HeaderValue::from_static("198.51.100.41"));
        drop(admission.try_admit(proxy, &duplicate).unwrap());

        let malformed = admission_headers(Some("attacker-rotated-obfuscated-token"));
        assert!(matches!(
            admission.try_admit(proxy, &malformed),
            Err(AdmissionRejection::ClientRate)
        ));
    }

    #[tokio::test]
    async fn admission_middleware_fails_closed_and_precedes_handler() {
        async fn probe() -> StatusCode {
            StatusCode::NO_CONTENT
        }

        let admission = WebhookAdmission::new(1, 1, 1, 1, 1, Vec::new());
        let observed_admission = admission.clone();
        let app = Router::new()
            .route("/api/integrations/{connection_id}/webhook", post(probe))
            .layer(middleware::from_fn_with_state(
                admission,
                webhook_admission_middleware,
            ));

        let missing_context = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/integrations/ic-admission-test/webhook")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_context.status(), StatusCode::SERVICE_UNAVAILABLE);

        let request = || {
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/integrations/ic-admission-test/webhook")
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(peer("198.51.100.30:443")));
            request
        };
        assert_eq!(
            app.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        let rejected = app.oneshot(request()).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            observed_admission.telemetry.snapshot(),
            WebhookAdmissionRejectionSnapshot {
                client_rate: 1,
                global_rate: 0,
                in_flight: 0,
            },
            "middleware rejection must feed the aggregate telemetry"
        );
    }

    #[tokio::test]
    async fn exhausted_webhook_admission_rejects_before_global_concurrency_queue() {
        async fn blocking_probe(
            State((entered, release)): State<(Arc<Notify>, Arc<Notify>)>,
        ) -> StatusCode {
            entered.notify_one();
            release.notified().await;
            StatusCode::NO_CONTENT
        }

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let admission = WebhookAdmission::new(1, 1, 1, 1, 1, Vec::new());
        let app = Router::new()
            .route(
                "/api/integrations/{connection_id}/webhook",
                post(blocking_probe),
            )
            .with_state((entered.clone(), release.clone()))
            // This models the whole-app queue. The later-added webhook layer
            // must run first and reject an exhausted source without waiting.
            .layer(ConcurrencyLimitLayer::new(1))
            .layer(middleware::from_fn_with_state(
                admission,
                webhook_admission_middleware,
            ));
        let request = || {
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/integrations/ic-admission-queue-test/webhook")
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(peer("198.51.100.31:443")));
            request
        };

        let first_app = app.clone();
        let first = tokio::spawn(async move { first_app.oneshot(request()).await.unwrap() });
        entered.notified().await;
        let rejected = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            app.oneshot(request()),
        )
        .await
        .expect("exhausted webhook must not queue behind global concurrency")
        .unwrap();
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        release.notify_one();
        assert_eq!(first.await.unwrap().status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn webhook_route_enforces_feature_specific_body_cap_after_admission() {
        let admission = WebhookAdmission::new(100, 100, 100, 100, 10, Vec::new());
        let app = routes().layer(middleware::from_fn_with_state(
            admission,
            webhook_admission_middleware,
        ));
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/integrations/ic-body-cap-test/webhook")
            .body(Body::from(vec![b'x'; WEBHOOK_MAX_BODY_BYTES + 1]))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(peer("198.51.100.32:443")));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    async fn latest_event_for(
        pool: &PgPool,
        connection_id: &str,
    ) -> Option<(String, String, Option<String>, serde_json::Value)> {
        sqlx::query_as::<_, (String, String, Option<String>, serde_json::Value)>(
            "SELECT event_type, actor, site, payload FROM domain_events \
             WHERE aggregate_id = $1 AND event_type = 'integration.webhook-received' \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(connection_id)
        .fetch_optional(pool)
        .await
        .expect("query domain_events")
    }

    /// (i) Valid signature over the exact raw body -> 202 + a domain_events row
    /// with body_sha256 present.
    #[tokio::test]
    async fn valid_signature_records_event() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-recv-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, Some("site-a")).await;
        let secret = rand::random::<[u8; 32]>();
        let authority = provision_webhook_secret(pool, &conn_id, &secret).await;

        let body = Bytes::from_static(br#"{"event":"incident.created","id":"INC001"}"#);
        let timestamp = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-valid-001";
        let sig = sign_delivery(&secret, &authority, &conn_id, timestamp, delivery_id, &body);

        let result = webhook_receive_with_pool(
            conn_id.clone(),
            headers_for_delivery(Some(&sig), timestamp, delivery_id),
            body.clone(),
            pool,
        )
        .await;

        assert!(result.is_ok(), "expected 202, got {:?}", result.err());
        let (status, Json(payload)) = result.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["status"], "accepted");
        assert!(payload["event_id"].is_i64());

        let (event_type, actor, site, event_payload) = latest_event_for(pool, &conn_id)
            .await
            .expect("event must be recorded");
        assert_eq!(event_type, "integration.webhook-received");
        assert_eq!(actor, "webhook:servicenow");
        assert_eq!(site.as_deref(), Some("site-a"));
        assert_eq!(
            event_payload["body_sha256"],
            ryuki_protocol::sha256_hex(&body)
        );
        assert_eq!(event_payload["body_bytes"], body.len() as i64);
        assert_eq!(event_payload["delivery_id"], delivery_id);
        assert_eq!(
            event_payload["webhook_secret_generation"],
            authority.generation
        );
        assert_eq!(
            event_payload["authority_context_sha256"],
            authority.authority_context_sha256
        );
        let receipt: (i16, i64, String, String, Option<String>) = sqlx::query_as(
            "SELECT signature_version, webhook_secret_generation, \
                    authority_context_sha256, webhook_vendor_type, webhook_site_scope \
             FROM inbound_webhook_receipts \
             WHERE connection_id = $1 AND delivery_id = $2",
        )
        .bind(&conn_id)
        .bind(delivery_id)
        .fetch_one(pool)
        .await
        .expect("authority-bound receipt");
        assert_eq!(receipt.0, WEBHOOK_SIGNATURE_VERSION);
        assert_eq!(receipt.1, authority.generation);
        assert_eq!(receipt.2, authority.authority_context_sha256);
        assert_eq!(receipt.3, "servicenow");
        assert_eq!(receipt.4.as_deref(), Some("site-a"));
        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (1, 1));
        // The raw external payload must never appear verbatim in the stored event.
        assert!(!event_payload.to_string().contains("incident.created"));

        cleanup_connection(pool, &conn_id).await;
    }

    #[tokio::test]
    async fn metadata_reassignment_revokes_old_authority_until_reprovisioned() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-reassign-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, Some("site-a")).await;
        let old_secret = rand::random::<[u8; 32]>();
        let old_authority = provision_webhook_secret(pool, &conn_id, &old_secret).await;

        sqlx::query(
            "UPDATE integration_connections \
             SET vendor_type = 'grafana', site_scope = 'site-b', \
                 webhook_secret_ref = NULL \
             WHERE id = $1",
        )
        .bind(&conn_id)
        .execute(pool)
        .await
        .expect("metadata reassignment atomically revokes the active credential");

        let mut reuse_tx = pool.begin().await.expect("begin retired-secret check");
        sqlx::query("SELECT id FROM integration_connections WHERE id = $1 FOR UPDATE")
            .bind(&conn_id)
            .execute(&mut *reuse_tx)
            .await
            .expect("lock reassigned connection");
        assert!(
            webhook_secret_material_was_used(&mut reuse_tx, &conn_id, &old_secret)
                .await
                .expect("check revoked credential history"),
            "reassignment must not make old plaintext eligible for reuse"
        );
        reuse_tx
            .rollback()
            .await
            .expect("release retired-secret check");

        let body = Bytes::from_static(br#"{"event":"synthetic.reassignment"}"#);
        let timestamp = chrono::Utc::now().timestamp();
        let old_signature = sign_delivery(
            &old_secret,
            &old_authority,
            &conn_id,
            timestamp,
            "delivery-reassignment-old",
            &body,
        );
        let old_error = webhook_receive_with_pool(
            conn_id.clone(),
            headers_for_delivery(Some(&old_signature), timestamp, "delivery-reassignment-old"),
            body.clone(),
            pool,
        )
        .await
        .expect_err("an old sender must lose authority at reassignment");
        assert_eq!(old_error.0, StatusCode::UNAUTHORIZED);
        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (0, 0));

        let new_secret = rand::random::<[u8; 32]>();
        let new_authority = provision_webhook_secret(pool, &conn_id, &new_secret).await;
        assert_eq!(new_authority.generation, old_authority.generation + 1);
        assert_ne!(
            new_authority.authority_context_sha256,
            old_authority.authority_context_sha256
        );
        let new_signature = sign_delivery(
            &new_secret,
            &new_authority,
            &conn_id,
            timestamp,
            "delivery-reassignment-new",
            &body,
        );
        webhook_receive_with_pool(
            conn_id.clone(),
            headers_for_delivery(Some(&new_signature), timestamp, "delivery-reassignment-new"),
            body,
            pool,
        )
        .await
        .expect("fresh authority for the reassigned metadata is accepted");

        let (_, actor, site, _) = latest_event_for(pool, &conn_id)
            .await
            .expect("reprovisioned delivery records an event");
        assert_eq!(actor, "webhook:grafana");
        assert_eq!(site.as_deref(), Some("site-b"));
        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (1, 1));
        cleanup_connection(pool, &conn_id).await;
    }

    #[tokio::test]
    async fn authority_snapshot_serializes_reassignment_and_deletion() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-authority-lock-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, Some("site-a")).await;
        let secret = rand::random::<[u8; 32]>();
        provision_webhook_secret(pool, &conn_id, &secret).await;

        let mut receiver_tx = pool.begin().await.expect("begin receiver snapshot");
        resolve_webhook_authority(&mut receiver_tx, &conn_id)
            .await
            .expect("resolve locked authority")
            .expect("configured authority");

        let reassignment_started = Arc::new(Notify::new());
        let task_started = reassignment_started.clone();
        let reassigned_id = conn_id.clone();
        let mut reassignment = tokio::spawn(async move {
            task_started.notify_one();
            sqlx::query(
                "UPDATE integration_connections \
                 SET vendor_type = 'grafana', webhook_secret_ref = NULL \
                 WHERE id = $1",
            )
            .bind(&reassigned_id)
            .execute(pool)
            .await
        });
        reassignment_started.notified().await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), &mut reassignment,)
                .await
                .is_err(),
            "reassignment must wait while the receiver holds its authority snapshot"
        );
        receiver_tx
            .commit()
            .await
            .expect("release receiver authority snapshot");
        tokio::time::timeout(std::time::Duration::from_secs(5), reassignment)
            .await
            .expect("reassignment completes after receiver commit")
            .expect("reassignment task")
            .expect("reassignment query");

        let replacement_secret = rand::random::<[u8; 32]>();
        provision_webhook_secret(pool, &conn_id, &replacement_secret).await;
        let mut second_receiver_tx = pool.begin().await.expect("begin deletion snapshot");
        resolve_webhook_authority(&mut second_receiver_tx, &conn_id)
            .await
            .expect("resolve authority before deletion")
            .expect("reprovisioned authority");

        let deletion_started = Arc::new(Notify::new());
        let task_started = deletion_started.clone();
        let deleted_id = conn_id.clone();
        let mut deletion = tokio::spawn(async move {
            task_started.notify_one();
            sqlx::query("DELETE FROM integration_connections WHERE id = $1")
                .bind(&deleted_id)
                .execute(pool)
                .await
        });
        deletion_started.notified().await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), &mut deletion)
                .await
                .is_err(),
            "deletion must wait while the receiver holds its authority snapshot"
        );
        second_receiver_tx
            .commit()
            .await
            .expect("release deletion authority snapshot");
        tokio::time::timeout(std::time::Duration::from_secs(5), deletion)
            .await
            .expect("deletion completes after receiver commit")
            .expect("deletion task")
            .expect("deletion query");

        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM integration_connections WHERE id = $1")
                .bind(&conn_id)
                .fetch_one(pool)
                .await
                .expect("count deleted connection");
        assert_eq!(remaining, 0);
        assert!(latest_event_for(pool, &conn_id).await.is_none());
    }

    /// (ii) Tampered body / wrong signature -> 401, no event recorded.
    #[tokio::test]
    async fn tampered_body_rejected_no_event() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-tamper-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, None).await;
        let secret = rand::random::<[u8; 32]>();
        let authority = provision_webhook_secret(pool, &conn_id, &secret).await;

        let original = b"{\"a\":1}";
        let timestamp = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-tamper-001";
        let sig = sign_delivery(
            &secret,
            &authority,
            &conn_id,
            timestamp,
            delivery_id,
            original,
        );
        let tampered = Bytes::from_static(b"{\"a\":2}");

        let result = webhook_receive_with_pool(
            conn_id.clone(),
            headers_for_delivery(Some(&sig), timestamp, delivery_id),
            tampered,
            pool,
        )
        .await;

        assert!(result.is_err());
        let (status, Json(payload)) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(payload["error"], "signature verification failed");
        assert!(latest_event_for(pool, &conn_id).await.is_none());

        cleanup_connection(pool, &conn_id).await;
    }

    #[tokio::test]
    async fn stale_and_future_deliveries_create_no_receipt_or_event() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-freshness-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, None).await;
        let secret = rand::random::<[u8; 32]>();
        let authority = provision_webhook_secret(pool, &conn_id, &secret).await;
        let application_now = chrono::Utc::now();
        let body = Bytes::from_static(br#"{"event":"synthetic.freshness"}"#);

        for (label, offset) in [
            ("stale", -WEBHOOK_MAX_CLOCK_SKEW_SECS - 1),
            ("future", WEBHOOK_MAX_CLOCK_SKEW_SECS + 1),
        ] {
            let timestamp = application_now.timestamp() + offset;
            let delivery_id = format!("delivery-{label}-001");
            let signature = sign_delivery(
                &secret,
                &authority,
                &conn_id,
                timestamp,
                &delivery_id,
                &body,
            );
            let error = webhook_receive_with_pool_at(
                conn_id.clone(),
                headers_for_delivery(Some(&signature), timestamp, &delivery_id),
                body.clone(),
                pool,
                application_now,
            )
            .await
            .expect_err("out-of-window delivery must fail closed");
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            assert_eq!(error.1.0["error"], "signature verification failed");
        }

        // A skewed application clock alone is insufficient: make the envelope
        // appear current to the injected application clock while PostgreSQL's
        // live clock is already outside the window.
        let database_stale_timestamp =
            chrono::Utc::now().timestamp() - WEBHOOK_MAX_CLOCK_SKEW_SECS - 1;
        let skewed_application_now =
            chrono::DateTime::<chrono::Utc>::from_timestamp(database_stale_timestamp, 0)
                .expect("skewed application clock fixture");
        let delivery_id = "delivery-database-clock-stale-001";
        let signature = sign_delivery(
            &secret,
            &authority,
            &conn_id,
            database_stale_timestamp,
            delivery_id,
            &body,
        );
        let database_clock_error = webhook_receive_with_pool_at(
            conn_id.clone(),
            headers_for_delivery(Some(&signature), database_stale_timestamp, delivery_id),
            body,
            pool,
            skewed_application_now,
        )
        .await
        .expect_err("database clock must reject an application-clock bypass");
        assert_eq!(database_clock_error.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            database_clock_error.1.0["error"],
            "signature verification failed"
        );

        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (0, 0));
        cleanup_connection(pool, &conn_id).await;
    }

    /// (iii) Unknown connection id -> 401, SAME body as a bad signature (no-oracle).
    #[tokio::test]
    async fn unknown_connection_rejected_same_as_bad_signature() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-unknown-{}", uuid::Uuid::new_v4());
        let body = Bytes::from_static(b"whatever");
        // Any signature at all -- the connection doesn't exist so resolve
        // returns None regardless of what's supplied.
        let timestamp = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-unknown-001";
        let secret = rand::random::<[u8; 32]>();
        let authority = signing_context(&conn_id, "is-wh-unknown", "unknown", None, 1);
        let sig = sign_delivery(&secret, &authority, &conn_id, timestamp, delivery_id, &body);

        let result = webhook_receive_with_pool(
            conn_id,
            headers_for_delivery(Some(&sig), timestamp, delivery_id),
            body,
            pool,
        )
        .await;

        assert!(result.is_err());
        let (status, Json(payload)) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(payload["error"], "signature verification failed");
    }

    /// (iv) Missing signature header -> 400.
    #[tokio::test]
    async fn missing_signature_header_is_400() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let conn_id = format!("ic-webhook-nohdr-{}", uuid::Uuid::new_v4());
        let body = Bytes::from_static(b"whatever");
        let timestamp = chrono::Utc::now().timestamp();

        let result = webhook_receive_with_pool(
            conn_id,
            headers_for_delivery(None, timestamp, "delivery-missing-signature"),
            body,
            pool,
        )
        .await;

        assert!(result.is_err());
        let (status, Json(payload)) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(payload["error"], "missing or malformed X-Hub-Signature-256");
    }

    #[tokio::test]
    async fn exact_retry_returns_original_event_without_duplicate() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-replay-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, Some("site-a")).await;
        let secret = rand::random::<[u8; 32]>();
        let authority = provision_webhook_secret(pool, &conn_id, &secret).await;
        let timestamp = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-replay-001";
        let body = Bytes::from_static(br#"{"event":"synthetic.retry"}"#);
        let signature = sign_delivery(&secret, &authority, &conn_id, timestamp, delivery_id, &body);
        let headers = headers_for_delivery(Some(&signature), timestamp, delivery_id);

        let first = webhook_receive_with_pool(conn_id.clone(), headers.clone(), body.clone(), pool)
            .await
            .expect("first delivery accepted");
        let second = webhook_receive_with_pool(conn_id.clone(), headers, body, pool)
            .await
            .expect("exact retry is idempotently accepted");

        assert_eq!(first.0, StatusCode::ACCEPTED);
        assert_eq!(second.0, StatusCode::ACCEPTED);
        assert_eq!(first.1.0["event_id"], second.1.0["event_id"]);
        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (1, 1));
        cleanup_connection(pool, &conn_id).await;
    }

    #[tokio::test]
    async fn concurrent_replays_commit_one_receipt_and_event() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-race-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, None).await;
        let secret = rand::random::<[u8; 32]>();
        let authority = provision_webhook_secret(pool, &conn_id, &secret).await;
        let timestamp = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-race-001";
        let body = Bytes::from_static(br#"{"event":"synthetic.concurrent"}"#);
        let signature = sign_delivery(&secret, &authority, &conn_id, timestamp, delivery_id, &body);
        let headers = headers_for_delivery(Some(&signature), timestamp, delivery_id);
        let start = Arc::new(Barrier::new(2));
        let first_start = start.clone();
        let first_conn_id = conn_id.clone();
        let first_headers = headers.clone();
        let first_body = body.clone();
        let second_conn_id = conn_id.clone();

        let (first, second) = tokio::join!(
            async move {
                first_start.wait().await;
                webhook_receive_with_pool(first_conn_id, first_headers, first_body, pool).await
            },
            async move {
                start.wait().await;
                webhook_receive_with_pool(second_conn_id, headers, body, pool).await
            },
        );
        let first = first.expect("first concurrent copy accepted");
        let second = second.expect("second concurrent copy idempotently accepted");
        assert_eq!(first.1.0["event_id"], second.1.0["event_id"]);
        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (1, 1));
        cleanup_connection(pool, &conn_id).await;
    }

    #[tokio::test]
    async fn reused_delivery_id_with_different_body_is_rejected() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", test_encryption_key());

        let conn_id = format!("ic-webhook-collision-{}", uuid::Uuid::new_v4());
        insert_test_connection(pool, &conn_id, None).await;
        let secret = rand::random::<[u8; 32]>();
        let authority = provision_webhook_secret(pool, &conn_id, &secret).await;
        let timestamp = chrono::Utc::now().timestamp();
        let delivery_id = "delivery-collision-001";
        let first_body = Bytes::from_static(br#"{"state":"first"}"#);
        let first_signature = sign_delivery(
            &secret,
            &authority,
            &conn_id,
            timestamp,
            delivery_id,
            &first_body,
        );
        let _ = webhook_receive_with_pool(
            conn_id.clone(),
            headers_for_delivery(Some(&first_signature), timestamp, delivery_id),
            first_body,
            pool,
        )
        .await
        .expect("first delivery accepted");

        let changed_body = Bytes::from_static(br#"{"state":"changed"}"#);
        let changed_signature = sign_delivery(
            &secret,
            &authority,
            &conn_id,
            timestamp,
            delivery_id,
            &changed_body,
        );
        let error = webhook_receive_with_pool(
            conn_id.clone(),
            headers_for_delivery(Some(&changed_signature), timestamp, delivery_id),
            changed_body,
            pool,
        )
        .await
        .expect_err("delivery-id collision must fail closed");
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        assert_eq!(error.1.0["error"], "signature verification failed");
        assert_eq!(event_and_receipt_counts(pool, &conn_id).await, (1, 1));
        cleanup_connection(pool, &conn_id).await;
    }

    #[tokio::test]
    async fn rolled_back_claim_leaves_no_durable_receipt() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let connection_id = format!("ic-webhook-rollback-{}", uuid::Uuid::new_v4());
        let delivery_id = "delivery-rollback-001";
        let signed_at = chrono::Utc::now();
        let mut tx = pool.begin().await.expect("begin rollback test transaction");
        inbound_webhook_receipts::enable_contract_v2(&mut tx)
            .await
            .expect("enable receipt contract");
        let secret_ref = "is-wh-rollback";
        let authority_digest =
            webhook_authority_context_digest(&connection_id, secret_ref, 1, "synthetic", None);
        assert!(
            inbound_webhook_receipts::try_claim(
                &mut tx,
                &connection_id,
                delivery_id,
                WEBHOOK_SIGNATURE_VERSION,
                secret_ref,
                1,
                &authority_digest,
                "synthetic",
                None,
                signed_at,
                &ryuki_protocol::sha256_hex(b"synthetic rollback body"),
                inbound_webhook_receipts::advisory_lock_key(&connection_id, delivery_id),
                signed_at + chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS),
            )
            .await
            .expect("claim receipt")
        );
        tx.rollback().await.expect("roll back receipt claim");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM inbound_webhook_receipts \
             WHERE connection_id = $1 AND delivery_id = $2",
        )
        .bind(&connection_id)
        .bind(delivery_id)
        .fetch_one(pool)
        .await
        .expect("count rolled-back receipt");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn migration_fences_legacy_events_and_unbound_receipts() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let connection_id = format!("ic-webhook-fence-{}", uuid::Uuid::new_v4());

        let legacy_error = domain_events::insert(
            pool,
            NewEvent {
                event_type: "integration.webhook-received",
                aggregate_type: "integration_connection",
                aggregate_id: &connection_id,
                site: None,
                environment: None,
                actor: "webhook:synthetic",
                payload: json!({"synthetic": true}),
            },
        )
        .await
        .expect_err("legacy receipt-free webhook event must be rejected");
        let legacy_code = legacy_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(legacy_code.as_deref(), Some("55000"));

        let mut explicit_v1_tx = pool.begin().await.expect("begin explicit v1 fence test");
        sqlx::query("SELECT set_config('ryuki.inbound_webhook_contract', '1', true)")
            .execute(&mut *explicit_v1_tx)
            .await
            .expect("set legacy contract marker");
        let explicit_v1_error = domain_events::insert(
            &mut *explicit_v1_tx,
            NewEvent {
                event_type: "integration.webhook-received",
                aggregate_type: "integration_connection",
                aggregate_id: &connection_id,
                site: None,
                environment: None,
                actor: "webhook:synthetic",
                payload: json!({"synthetic": "explicit-v1"}),
            },
        )
        .await
        .expect_err("an explicit v1 marker must fail the rolling-deployment fence");
        let explicit_v1_code = explicit_v1_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(explicit_v1_code.as_deref(), Some("55000"));
        explicit_v1_tx.rollback().await.ok();

        let mut receipt_free_event_tx = pool.begin().await.expect("begin receipt-free event test");
        inbound_webhook_receipts::enable_contract_v2(&mut receipt_free_event_tx)
            .await
            .expect("enable v2 marker without receipt");
        domain_events::insert(
            &mut *receipt_free_event_tx,
            NewEvent {
                event_type: "integration.webhook-received",
                aggregate_type: "integration_connection",
                aggregate_id: &connection_id,
                site: None,
                environment: None,
                actor: "webhook:synthetic",
                payload: json!({"synthetic": "receipt-free"}),
            },
        )
        .await
        .expect("v2 marker admits the statement before the deferred proof");
        let receipt_free_commit_error = receipt_free_event_tx
            .commit()
            .await
            .expect_err("deferred invariant must reject a receipt-free event");
        let receipt_free_code = receipt_free_commit_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(receipt_free_code.as_deref(), Some("23514"));

        let delivery_id = "delivery-unbound-fence-001";
        let signed_at = chrono::Utc::now();
        let mut tx = pool.begin().await.expect("begin unbound receipt test");
        let secret_ref = "is-wh-unbound-fence";
        let authority_digest =
            webhook_authority_context_digest(&connection_id, secret_ref, 1, "synthetic", None);
        assert!(
            inbound_webhook_receipts::try_claim(
                &mut tx,
                &connection_id,
                delivery_id,
                WEBHOOK_SIGNATURE_VERSION,
                secret_ref,
                1,
                &authority_digest,
                "synthetic",
                None,
                signed_at,
                &ryuki_protocol::sha256_hex(b"synthetic unbound receipt"),
                inbound_webhook_receipts::advisory_lock_key(&connection_id, delivery_id),
                signed_at + chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS),
            )
            .await
            .expect("claim unbound receipt")
        );
        let commit_error = tx
            .commit()
            .await
            .expect_err("deferred constraint must reject an unbound receipt");
        let commit_code = commit_error
            .as_database_error()
            .and_then(|error| error.code())
            .map(|code| code.into_owned());
        assert_eq!(commit_code.as_deref(), Some("23514"));

        let receipt_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM inbound_webhook_receipts \
             WHERE connection_id = $1 AND delivery_id = $2",
        )
        .bind(&connection_id)
        .bind(delivery_id)
        .fetch_one(pool)
        .await
        .expect("count rejected unbound receipt");
        assert_eq!(receipt_count, 0);

        let mismatch_delivery_id = "delivery-authority-mismatch-001";
        let mut mismatch_tx = pool.begin().await.expect("begin authority mismatch test");
        inbound_webhook_receipts::enable_contract_v2(&mut mismatch_tx)
            .await
            .expect("enable v2 contract for mismatch test");
        let mismatch_secret_ref = "is-wh-authority-mismatch";
        let mismatch_digest = webhook_authority_context_digest(
            &connection_id,
            mismatch_secret_ref,
            1,
            "synthetic",
            None,
        );
        let mismatch_body_sha256 = ryuki_protocol::sha256_hex(b"synthetic authority mismatch");
        let mismatched_event_id = domain_events::insert(
            &mut *mismatch_tx,
            NewEvent {
                event_type: "integration.webhook-received",
                aggregate_type: "integration_connection",
                aggregate_id: &connection_id,
                site: None,
                environment: None,
                actor: "webhook:synthetic",
                payload: json!({
                    "connection_id": &connection_id,
                    "signature_version": WEBHOOK_SIGNATURE_VERSION,
                    "webhook_secret_generation": 1,
                    "authority_context_sha256": &mismatch_digest,
                    "vendor_type": "tampered-vendor",
                    "signed_at": signed_at,
                    "delivery_id": mismatch_delivery_id,
                    "body_sha256": &mismatch_body_sha256,
                }),
            },
        )
        .await
        .expect("statement-level v2 event insert");
        assert!(
            inbound_webhook_receipts::try_claim(
                &mut mismatch_tx,
                &connection_id,
                mismatch_delivery_id,
                WEBHOOK_SIGNATURE_VERSION,
                mismatch_secret_ref,
                1,
                &mismatch_digest,
                "synthetic",
                None,
                signed_at,
                &mismatch_body_sha256,
                inbound_webhook_receipts::advisory_lock_key(&connection_id, mismatch_delivery_id),
                signed_at + chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS),
            )
            .await
            .expect("claim mismatched receipt")
        );
        assert!(
            inbound_webhook_receipts::bind_event(
                &mut mismatch_tx,
                &connection_id,
                mismatch_delivery_id,
                mismatched_event_id,
            )
            .await
            .expect("bind mismatched receipt")
        );
        let mismatch_commit_error = mismatch_tx
            .commit()
            .await
            .expect_err("exact receipt/event authority mismatch must fail at commit");
        assert_eq!(
            mismatch_commit_error
                .as_database_error()
                .and_then(|error| error.constraint()),
            Some("domain_events_inbound_webhook_receipt_authority")
        );
    }

    #[tokio::test]
    async fn cleanup_cannot_reopen_a_delivery_locked_at_the_expiry_boundary() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let connection_id = format!("ic-webhook-expiry-race-{}", uuid::Uuid::new_v4());
        let delivery_id = "delivery-expiry-race-001";
        let signed_at = chrono::DateTime::<chrono::Utc>::from_timestamp(1_000_000_000, 0)
            .expect("synthetic expiry timestamp");
        let expires_at = signed_at + chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS);
        seed_bound_receipt(pool, &connection_id, delivery_id, signed_at, expires_at).await;

        // This models a replay transaction that has serialized the target but
        // has not yet read its final authoritative clock. Cleanup must not wait,
        // delete, or reopen the target while that transaction is in flight.
        let mut replay_tx = pool.begin().await.expect("begin replay-boundary tx");
        let lock_key = inbound_webhook_receipts::advisory_lock_key(&connection_id, delivery_id);
        inbound_webhook_receipts::lock_delivery(&mut replay_tx, lock_key)
            .await
            .expect("lock replay-boundary delivery");
        let _deleted_other_receipts = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            inbound_webhook_receipts::cleanup_expired(pool),
        )
        .await
        .expect("cleanup must not wait on an in-flight delivery lock")
        .expect("cleanup while delivery is locked");
        assert_eq!(event_and_receipt_counts(pool, &connection_id).await, (1, 1));
        replay_tx
            .rollback()
            .await
            .expect("release replay-boundary lock");

        inbound_webhook_receipts::cleanup_expired(pool)
            .await
            .expect("cleanup after delivery lock release");
        assert_eq!(event_and_receipt_counts(pool, &connection_id).await, (1, 0));
        cleanup_connection(pool, &connection_id).await;
    }

    #[tokio::test]
    async fn crossed_target_reuse_and_global_cleanup_do_not_deadlock() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let connection_id = format!("ic-webhook-cleanup-cross-{}", uuid::Uuid::new_v4());
        let signed_at = chrono::DateTime::<chrono::Utc>::from_timestamp(1_000_000_000, 0)
            .expect("synthetic cleanup timestamp");
        let expires_at = signed_at + chrono::Duration::seconds(WEBHOOK_MAX_CLOCK_SKEW_SECS);
        for delivery_id in ["delivery-cleanup-cross-a", "delivery-cleanup-cross-b"] {
            seed_bound_receipt(pool, &connection_id, delivery_id, signed_at, expires_at).await;
        }

        let start = Arc::new(Barrier::new(3));
        let recycle = |delivery_id: &'static str| {
            let connection_id = connection_id.clone();
            let start = start.clone();
            async move {
                let mut tx = pool.begin().await.expect("begin target recycle tx");
                let lock_key =
                    inbound_webhook_receipts::advisory_lock_key(&connection_id, delivery_id);
                inbound_webhook_receipts::lock_delivery(&mut tx, lock_key)
                    .await
                    .expect("lock target recycle delivery");
                start.wait().await;
                let now: chrono::DateTime<chrono::Utc> =
                    sqlx::query_scalar("SELECT clock_timestamp()")
                        .fetch_one(&mut *tx)
                        .await
                        .expect("read recycle clock");
                inbound_webhook_receipts::delete_expired_target(
                    &mut tx,
                    &connection_id,
                    delivery_id,
                    now,
                )
                .await
                .expect("delete expired target");
                tx.commit().await.expect("commit target recycle");
            }
        };
        let cleanup_start = start.clone();

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (_, _, cleanup_result) = tokio::join!(
                recycle("delivery-cleanup-cross-a"),
                recycle("delivery-cleanup-cross-b"),
                async {
                    cleanup_start.wait().await;
                    inbound_webhook_receipts::cleanup_expired(pool).await
                },
            );
            cleanup_result.expect("global cleanup during target reuse");
        })
        .await
        .expect("cleanup and target reuse must not deadlock");
        assert_eq!(event_and_receipt_counts(pool, &connection_id).await, (2, 0));
        cleanup_connection(pool, &connection_id).await;
    }
}
