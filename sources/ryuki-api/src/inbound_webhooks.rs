//! Inbound webhook RECEIVER (#18 slice 2b — FINAL slice) — the public handler.
//!
//! An external system (ServiceNow, monitoring, CI) POSTs a signed webhook to
//! `/api/integrations/{connection_id}/webhook`. This is a PUBLIC endpoint with NO
//! human session: it authenticates the caller ONLY via the HMAC-SHA256 signature
//! over the raw request body, verified against the connection's dedicated webhook
//! secret (slice 2a's `resolve_webhook_secret` / slice 1's `verify_hmac_sha256`).
//!
//! SECURITY-CRITICAL, fail-closed at every step:
//! - The body extractor is `axum::body::Bytes`, NOT `Json` — the HMAC covers the
//!   EXACT bytes the caller sent, so it MUST be read raw and MUST be the LAST
//!   extractor (axum consumes the body once).
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
//! PRODUCTION REQUIREMENT — RATE LIMITING: this is a PUBLIC, pre-authentication
//! endpoint, and authenticating a request inherently requires a DB lookup (the
//! webhook secret). The cheap signature-shape pre-check below rejects malformed
//! signatures with no DB cost, but a flood of well-formed-but-wrong signatures
//! still each cost one secret lookup. The app's per-client rate limiter
//! (`rate_limit_middleware`, which wraps this route via the outer `app`) is the
//! primary DoS control for that residual and MUST be enabled in any deployment
//! that exposes this endpoint — it is off in the default config. A dedicated
//! always-on per-IP webhook throttle would be a reasonable future hardening.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;

use crate::database::get_db;
use crate::integration::resolve_webhook_secret;
use crate::repos::domain_events::{self, NewEvent};

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

/// POST /api/integrations/{connection_id}/webhook
///
/// PUBLIC — no human session, no agent bearer token. Authenticates ONLY via the
/// `X-Hub-Signature-256` HMAC over the raw body, verified against the
/// connection's webhook secret. See module docs for the fail-closed / no-oracle
/// contract. A verified delivery is recorded as a domain event and returns
/// `202 Accepted` with `{ "status": "accepted", "event_id": "..." }`; the
/// external payload itself is never echoed or stored verbatim.
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
    // (a) Signature header must be present and a valid ASCII header value.
    let sig = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| bad_request("missing or malformed X-Hub-Signature-256"))?;

    // Cheap pre-DB gate: a valid HMAC-SHA256 is exactly 32 bytes = 64 hex chars
    // (optional "sha256=" prefix). Reject anything that cannot possibly be one
    // BEFORE touching the database, so garbage-signature spam is turned away at
    // ZERO db cost — this bounds the pre-auth DB-amplification surface of a public,
    // pre-auth endpoint. A well-formed-but-wrong signature still needs the secret
    // lookup below (authentication is inherently DB-backed); RATE LIMITING is the
    // primary DoS control for that residual (see the module docs). Returns the SAME
    // uniform 401 as every other auth failure, and runs before any connection
    // lookup, so it adds no connection-existence oracle.
    let hex_part = sig.strip_prefix("sha256=").unwrap_or(sig).trim();
    if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(signature_verification_failed());
    }

    // (c) NO-ORACLE MERGE POINT: unknown connection id, no webhook secret
    // configured, and a missing secret row all resolve to `Ok(None)` inside
    // `resolve_webhook_secret` and MUST all produce the identical 401 below as a
    // wrong signature (d) — this endpoint never reveals which connection ids
    // exist or are webhook-enabled.
    let secret = match resolve_webhook_secret(pool, &connection_id).await {
        Err(e) => return Err(generic_500("resolve_webhook_secret failed", e)),
        Ok(None) => return Err(signature_verification_failed()),
        Ok(Some(secret)) => secret,
    };

    // (d) Bad signature is INDISTINGUISHABLE from (c)'s None case — same status,
    // same body.
    if !ryuki_engine::webhook_receipt::verify_hmac_sha256(&secret, &body, sig) {
        return Err(signature_verification_failed());
    }

    // (e) SUCCESS: signature verified. Fetch scope for the event; if the
    // connection vanished between (c) and here, still record the event (the
    // signature verification already happened) with a degraded scope rather
    // than fail a request that was legitimately authenticated.
    let scope: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT site_scope, vendor_type FROM integration_connections WHERE id = $1")
            .bind(&connection_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| generic_500("connection scope lookup failed", e))?;
    let (site_scope, vendor_type) = scope.unwrap_or((None, "unknown".to_string()));

    let body_sha256 = ryuki_protocol::sha256_hex(&body);
    let event_id = domain_events::insert(
        pool,
        NewEvent {
            event_type: "integration.webhook-received",
            aggregate_type: "integration_connection",
            aggregate_id: &connection_id,
            site: site_scope.as_deref(),
            environment: None,
            actor: &format!("webhook:{vendor_type}"),
            // NEVER the raw external payload verbatim — only a hash + size, so
            // this event can never become a vector for storing/replaying
            // whatever the external system chose to send.
            payload: json!({
                "connection_id": connection_id,
                "vendor_type": vendor_type,
                "body_sha256": body_sha256,
                "body_bytes": body.len(),
            }),
        },
    )
    .await
    .map_err(|e| generic_500("domain event insert failed", e))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "accepted", "event_id": event_id})),
    ))
}

/// Router for the inbound webhook receiver. Merged as a SIBLING to
/// `agents::agent_routes()` in `main.rs` — BEFORE `human_gated_app` — so it
/// bypasses `auth_middleware` entirely (there is no human session to check).
/// It still inherits the OUTER app's body-limit / rate-limit / concurrency /
/// timeout layers, since those wrap the whole `app` router and this is merged
/// into it — that is the DoS protection for a pre-auth, public endpoint.
pub fn routes() -> Router {
    Router::new().route(
        "/api/integrations/{connection_id}/webhook",
        post(webhook_receive),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use sqlx::PgPool;

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
            // 32 bytes of obviously-fake test key (base64 of 0x41*32 = "AAA..."):
            // this is NOT a real secret, it's a test fixture.
            base64::engine::general_purpose::STANDARD.encode([0x41u8; 32])
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

    /// Provision a webhook secret directly (bypassing the admin HTTP handler,
    /// which requires a session) by calling `integration::set_webhook_secret`'s
    /// underlying encrypt+store logic inline. We can't call the handler (it
    /// needs an `AuthSession` Extension), so we replicate the minimal insert the
    /// same way `resolve_webhook_secret` expects to read it back.
    async fn provision_webhook_secret(pool: &PgPool, connection_id: &str, secret: &[u8]) {
        let (ciphertext, nonce, _key_id) =
            crate::integration::encrypt_secret(connection_id, secret)
                .expect("encrypt_secret must succeed with a valid test key");
        let secret_id = format!("is-wh-{}", uuid::Uuid::new_v4());
        let now = now_iso();
        sqlx::query(
            "INSERT INTO integration_secrets \
             (id, connection_id, ciphertext, nonce, key_id, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,'test-key',$5,$5)",
        )
        .bind(&secret_id)
        .bind(connection_id)
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&now)
        .execute(pool)
        .await
        .expect("insert secret");
        sqlx::query("UPDATE integration_connections SET webhook_secret_ref = $1 WHERE id = $2")
            .bind(&secret_id)
            .bind(connection_id)
            .execute(pool)
            .await
            .expect("link webhook_secret_ref");
    }

    fn sign(secret: &[u8], body: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn headers_with_sig(sig: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(sig) = sig {
            headers.insert(
                "X-Hub-Signature-256",
                axum::http::HeaderValue::from_str(sig).unwrap(),
            );
        }
        headers
    }

    async fn latest_event_for(
        pool: &PgPool,
        connection_id: &str,
    ) -> Option<(String, serde_json::Value)> {
        sqlx::query_as::<_, (String, serde_json::Value)>(
            "SELECT event_type, payload FROM domain_events \
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
        let secret = b"receiver-test-secret";
        provision_webhook_secret(pool, &conn_id, secret).await;

        let body = Bytes::from_static(br#"{"event":"incident.created","id":"INC001"}"#);
        let sig = sign(secret, &body);

        let result = webhook_receive_with_pool(
            conn_id.clone(),
            headers_with_sig(Some(&sig)),
            body.clone(),
            pool,
        )
        .await;

        assert!(result.is_ok(), "expected 202, got {:?}", result.err());
        let (status, Json(payload)) = result.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["status"], "accepted");
        assert!(payload["event_id"].is_i64());

        let (event_type, event_payload) = latest_event_for(pool, &conn_id)
            .await
            .expect("event must be recorded");
        assert_eq!(event_type, "integration.webhook-received");
        assert_eq!(
            event_payload["body_sha256"],
            ryuki_protocol::sha256_hex(&body)
        );
        assert_eq!(event_payload["body_bytes"], body.len() as i64);
        // The raw external payload must never appear verbatim in the stored event.
        assert!(!event_payload.to_string().contains("incident.created"));

        cleanup_connection(pool, &conn_id).await;
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
        let secret = b"another-receiver-secret";
        provision_webhook_secret(pool, &conn_id, secret).await;

        let original = b"{\"a\":1}";
        let sig = sign(secret, original);
        let tampered = Bytes::from_static(b"{\"a\":2}");

        let result = webhook_receive_with_pool(
            conn_id.clone(),
            headers_with_sig(Some(&sig)),
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
        let sig = sign(b"irrelevant", &body);

        let result =
            webhook_receive_with_pool(conn_id, headers_with_sig(Some(&sig)), body, pool).await;

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

        let result = webhook_receive_with_pool(conn_id, headers_with_sig(None), body, pool).await;

        assert!(result.is_err());
        let (status, Json(payload)) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(payload["error"], "missing or malformed X-Hub-Signature-256");
    }
}
