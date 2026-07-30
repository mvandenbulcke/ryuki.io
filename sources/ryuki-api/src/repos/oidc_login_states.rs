//! Single-use OIDC login-state store.
//!
//! Each row corresponds to one in-flight browser authorization-code flow bound
//! to the exact authenticator origin that initiated it. The `state` value is
//! the opaque CSPRNG token forwarded to the IdP as `?state=`; it is the primary
//! key and is deleted on first use (`take`) to enforce single-use semantics.
//!
//! Rows expire after 10 minutes (`expires_at`). Redemption always burns the row
//! first and exposes protocol material only when the caller presents the same
//! current authenticator-origin digest and the row is still live.

use axum::http::HeaderMap;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

/// Mandatory process-local admission for the two public login-initiation
/// routes. These limits remain active even when the optional general API rate
/// limiter is disabled. Both routes share the same buckets so switching
/// providers cannot multiply a caller's budget.
const LOGIN_CLIENT_REQUESTS_PER_SECOND: u32 = 2;
const LOGIN_CLIENT_BURST: u32 = 64;
const LOGIN_GLOBAL_REQUESTS_PER_SECOND: u32 = 50;
const LOGIN_GLOBAL_BURST: u32 = 256;
const LOGIN_MAX_IN_FLIGHT: usize = 16;
// Client identity is IP-derived, so users behind one NAT intentionally share
// this budget. The 64-request burst preserves ordinary corporate SSO fan-out;
// sustained admission remains two initiations per second per source.

/// Exact durable active-state ceilings. The per-origin quota prevents one
/// retained browser authenticator generation from consuming every slot; the
/// aggregate quota bounds the shared table across every origin and API replica.
const MAX_OUTSTANDING_LOGIN_STATES_PER_ORIGIN: i64 = 2_048;
const MAX_OUTSTANDING_LOGIN_STATES_GLOBAL: i64 = 4_096;
const LOGIN_STATE_CLEANUP_BATCH: i64 = 512;
const LOGIN_STATE_CONTRACT_VERSION: &str = "3";
const BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND: &str = "browser-derived-session";
const _: () = {
    assert!(LOGIN_CLIENT_REQUESTS_PER_SECOND > 0);
    assert!(LOGIN_CLIENT_BURST > 0);
    assert!(LOGIN_GLOBAL_REQUESTS_PER_SECOND > 0);
    assert!(LOGIN_GLOBAL_BURST > 0);
    assert!(LOGIN_MAX_IN_FLIGHT > 0);
    assert!(MAX_OUTSTANDING_LOGIN_STATES_PER_ORIGIN > 0);
    assert!(MAX_OUTSTANDING_LOGIN_STATES_GLOBAL >= MAX_OUTSTANDING_LOGIN_STATES_PER_ORIGIN);
    assert!(LOGIN_STATE_CLEANUP_BATCH > 0);
};

/// Stable transaction-scoped PostgreSQL advisory-lock namespace for all login
/// state cleanup/count/insert admission.
const LOGIN_STATE_ADVISORY_LOCK_KEY: i64 = 0x5259_554B_494F_4944;
const LOGIN_STATE_CONTRACT_SETTING: &str = "ryuki.oidc_login_state_contract";

type LoginClientRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

#[derive(Clone)]
struct LoginInitiationAdmission {
    per_client: Arc<LoginClientRateLimiter>,
    global: Arc<DefaultDirectRateLimiter>,
    in_flight: Arc<tokio::sync::Semaphore>,
    bucket_salt: [u8; 32],
    trusted_proxies: Arc<Vec<ryuki_core::config::TrustedProxyNetwork>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginInitiationAdmissionRejection {
    MissingPeer,
    Configuration,
    ClientRate,
    GlobalRate,
    InFlight,
}

impl LoginInitiationAdmission {
    fn production(trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>) -> Self {
        Self::new(
            LOGIN_CLIENT_REQUESTS_PER_SECOND,
            LOGIN_CLIENT_BURST,
            LOGIN_GLOBAL_REQUESTS_PER_SECOND,
            LOGIN_GLOBAL_BURST,
            LOGIN_MAX_IN_FLIGHT,
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
        Self::from_quotas(
            quota(client_per_second, client_burst),
            quota(global_per_second, global_burst),
            max_in_flight,
            trusted_proxies,
        )
    }

    fn from_quotas(
        client_quota: Quota,
        global_quota: Quota,
        max_in_flight: usize,
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> Self {
        Self {
            per_client: Arc::new(RateLimiter::keyed(client_quota)),
            global: Arc::new(RateLimiter::direct(global_quota)),
            in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight.max(1))),
            bucket_salt: rand::random(),
            trusted_proxies: Arc::new(trusted_proxies),
        }
    }

    #[cfg(test)]
    fn try_admit(
        &self,
        peer_addr: SocketAddr,
        forwarded_for: Option<&str>,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, LoginInitiationAdmissionRejection> {
        let (client_key, _) =
            crate::resolve_rate_limit_client_key(peer_addr, forwarded_for, &self.trusted_proxies);
        self.try_admit_client_key(&client_key)
    }

    fn try_admit_from_headers(
        &self,
        peer_addr: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, LoginInitiationAdmissionRejection> {
        let (client_key, _) = crate::resolve_rate_limit_client_key_from_headers(
            peer_addr,
            headers,
            &self.trusted_proxies,
        );
        self.try_admit_client_key(&client_key)
    }

    fn try_admit_client_key(
        &self,
        client_key: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, LoginInitiationAdmissionRejection> {
        // The bounded pseudorandom key space prevents rotating source
        // identities from creating unbounded governor state.
        let bucket =
            crate::bounded_rate_limit_key("login-initiation", client_key, &self.bucket_salt);
        // Source admission comes first so a throttled single peer cannot burn
        // the process-global budget with requests that were never eligible.
        // Rotating identities still cannot grow retained state without bound:
        // `bounded_rate_limit_key` maps them into a fixed bucket domain.
        self.per_client
            .check_key(&bucket)
            .map_err(|_| LoginInitiationAdmissionRejection::ClientRate)?;
        self.global
            .check()
            .map_err(|_| LoginInitiationAdmissionRejection::GlobalRate)?;
        self.in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| LoginInitiationAdmissionRejection::InFlight)
    }
}

static LOGIN_INITIATION_ADMISSION: OnceLock<LoginInitiationAdmission> = OnceLock::new();

/// Internal marker proving the request already crossed the outer, fail-fast
/// login-initiation admission layer. HTTP clients cannot create extensions;
/// handlers still run the same admission locally when composed without that
/// outer layer, preserving fail-closed behavior in alternate routers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoginInitiationPreAdmitted;

/// Admit one public OIDC/Entra initiation before database acquisition.
///
/// The TCP peer inserted by `into_make_service_with_connect_info` is mandatory;
/// a router served without it fails closed. `X-Forwarded-For` is considered
/// only through the repository's trusted-proxy resolver.
pub fn admit_public_login_initiation(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[ryuki_core::config::TrustedProxyNetwork],
) -> Result<tokio::sync::OwnedSemaphorePermit, LoginInitiationAdmissionRejection> {
    let peer_addr = peer_addr.ok_or(LoginInitiationAdmissionRejection::MissingPeer)?;
    let admission = LOGIN_INITIATION_ADMISSION
        .get_or_init(|| LoginInitiationAdmission::production(trusted_proxies.to_vec()));
    admission.try_admit_from_headers(peer_addr, headers)
}

#[derive(Debug, thiserror::Error)]
pub enum LoginStateInsertError {
    #[error("login-state admission is busy")]
    Busy,
    #[error("login-state authenticator-origin capacity is full")]
    OriginCapacity,
    #[error("login-state aggregate capacity is full")]
    GlobalCapacity,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Newly admitted protocol material. It is generated only after the serialized
/// durable capacity checks succeed, then inserted in that same transaction.
#[derive(Debug)]
pub struct LoginStateMaterial {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub binding: String,
}

/// Result of atomically burning one login-state row.
///
/// Protocol material exists only in `Redeemed`; origin mismatch, stale origin,
/// and expiry outcomes deliberately carry no nonce, PKCE verifier, or browser
/// binding. `OriginMismatch` intentionally covers an exact historical origin
/// that is no longer the active browser pointer.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginStateTakeOutcome {
    Redeemed {
        nonce: String,
        pkce_verifier: String,
        binding: String,
    },
    OriginMismatch,
    Expired,
    Absent,
}

fn random_b64url_256() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_login_state_material() -> LoginStateMaterial {
    LoginStateMaterial {
        state: random_b64url_256(),
        nonce: random_b64url_256(),
        pkce_verifier: random_b64url_256(),
        binding: random_b64url_256(),
    }
}

async fn set_login_state_contract_v3(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config($1, $2, TRUE)")
        .bind(LOGIN_STATE_CONTRACT_SETTING)
        .bind(LOGIN_STATE_CONTRACT_VERSION)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Admit and persist one new login-state row. The v3 database trigger owns the
/// exact 10-minute lifetime and derives both timestamps from database time.
/// The digest is an opaque, exact SHA-256 value for one retained
/// browser-derived authenticator origin; the database foreign key rejects
/// unknown origins and bearer-path substitution.
pub async fn create(
    pool: &PgPool,
    authenticator_origin_binding_digest: &[u8; 32],
) -> Result<LoginStateMaterial, LoginStateInsertError> {
    create_with_limits(
        pool,
        authenticator_origin_binding_digest,
        MAX_OUTSTANDING_LOGIN_STATES_PER_ORIGIN,
        MAX_OUTSTANDING_LOGIN_STATES_GLOBAL,
    )
    .await
}

/// Test-only fixture insertion for callback protocol tests that must control
/// the state and nonce echoed by a stub identity provider. Production builds
/// expose only [`create`], so every runtime producer uses bounded admission and
/// server-generated material.
#[cfg(test)]
pub async fn insert_test_material(
    pool: &PgPool,
    authenticator_origin_binding_digest: &[u8; 32],
    state: &str,
    login_nonce: &str,
    pkce_verifier: &str,
    binding: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_login_state_contract_v3(&mut tx).await?;
    sqlx::query(
        "INSERT INTO oidc_login_states_v3 \
         (state, nonce, pkce_verifier, binding, \
          authenticator_origin_binding_digest, authenticator_path_kind) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(state)
    .bind(login_nonce)
    .bind(pkce_verifier)
    .bind(binding)
    .bind(authenticator_origin_binding_digest.as_slice())
    .bind(BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Serialize cleanup, exact active-state quota checks, and insertion across
/// replicas. Every time predicate uses PostgreSQL `statement_timestamp()` so
/// API clock skew cannot create inconsistent admission decisions.
async fn create_with_limits(
    pool: &PgPool,
    authenticator_origin_binding_digest: &[u8; 32],
    max_per_origin: i64,
    max_global: i64,
) -> Result<LoginStateMaterial, LoginStateInsertError> {
    debug_assert!(max_per_origin > 0);
    debug_assert!(max_global >= max_per_origin);

    let mut tx = pool.begin().await?;
    set_login_state_contract_v3(&mut tx).await?;

    let lock_acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(LOGIN_STATE_ADVISORY_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await?;
    if !lock_acquired {
        tx.rollback().await?;
        return Err(LoginStateInsertError::Busy);
    }

    sqlx::query(
        "WITH expired AS ( \
             SELECT state FROM oidc_login_states_v3 \
             WHERE expires_at <= statement_timestamp() \
             ORDER BY expires_at, state \
             FOR UPDATE SKIP LOCKED \
             LIMIT $1 \
         ) \
         DELETE FROM oidc_login_states_v3 AS target \
         USING expired \
         WHERE target.state = expired.state",
    )
    .bind(LOGIN_STATE_CLEANUP_BATCH)
    .execute(&mut *tx)
    .await?;

    let active_global: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ( \
             SELECT 1 FROM oidc_login_states_v3 \
             WHERE expires_at > statement_timestamp() \
             LIMIT $1 \
         ) AS active",
    )
    .bind(max_global)
    .fetch_one(&mut *tx)
    .await?;
    if active_global >= max_global {
        tx.rollback().await?;
        return Err(LoginStateInsertError::GlobalCapacity);
    }

    let active_for_origin: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ( \
             SELECT 1 FROM oidc_login_states_v3 \
             WHERE authenticator_origin_binding_digest = $1 \
               AND expires_at > statement_timestamp() \
             LIMIT $2 \
         ) AS active",
    )
    .bind(authenticator_origin_binding_digest.as_slice())
    .bind(max_per_origin)
    .fetch_one(&mut *tx)
    .await?;
    if active_for_origin >= max_per_origin {
        tx.rollback().await?;
        return Err(LoginStateInsertError::OriginCapacity);
    }

    // Capacity is reserved under the still-held advisory lock before entropy
    // generation. A rejected request therefore creates no state, nonce,
    // verifier, binding, row, redirect, or cookie material.
    let material = generate_login_state_material();
    sqlx::query(
        "INSERT INTO oidc_login_states_v3 \
         (state, nonce, pkce_verifier, binding, \
          authenticator_origin_binding_digest, authenticator_path_kind) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&material.state)
    .bind(&material.nonce)
    .bind(&material.pkce_verifier)
    .bind(&material.binding)
    .bind(authenticator_origin_binding_digest.as_slice())
    .bind(BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(material)
}

#[derive(Debug, sqlx::FromRow)]
struct BurnedLoginStateRow {
    stored_origin_binding_digest: Vec<u8>,
    is_live: bool,
    is_current: bool,
    nonce: Option<String>,
    pkce_verifier: Option<String>,
    binding: Option<String>,
}

fn classify_burned_login_state(
    row: Option<BurnedLoginStateRow>,
    expected_origin_binding_digest: &[u8; 32],
) -> Result<LoginStateTakeOutcome, sqlx::Error> {
    let Some(row) = row else {
        return Ok(LoginStateTakeOutcome::Absent);
    };

    let exact_origin = row.stored_origin_binding_digest.len() == 32
        && bool::from(
            row.stored_origin_binding_digest
                .as_slice()
                .ct_eq(expected_origin_binding_digest.as_slice()),
        );
    if !exact_origin {
        return Ok(LoginStateTakeOutcome::OriginMismatch);
    }
    if !row.is_live {
        return Ok(LoginStateTakeOutcome::Expired);
    }
    if !row.is_current {
        return Ok(LoginStateTakeOutcome::OriginMismatch);
    }

    match (row.nonce, row.pkce_verifier, row.binding) {
        (Some(nonce), Some(pkce_verifier), Some(binding)) => Ok(LoginStateTakeOutcome::Redeemed {
            nonce,
            pkce_verifier,
            binding,
        }),
        _ => Err(sqlx::Error::Protocol(
            "live exact-origin login state returned incomplete protocol material".into(),
        )),
    }
}

/// Atomically burn a login-state row and classify the result against the exact
/// current browser authenticator origin. The current pointer is held `FOR
/// SHARE`, so redemption linearizes before or after a concurrent startup
/// epoch transition and never exposes material across that transition.
///
/// The `DELETE ... RETURNING` always deletes by state, so presenting a state at
/// the wrong origin cannot preserve it for a later retry. SQL conditionally
/// returns nonce/PKCE/binding only for an exact, live origin. A concurrent
/// second call therefore returns [`LoginStateTakeOutcome::Absent`].
///
/// `binding` is the per-browser CSRF token: the callback handler must compare it
/// to the mode-selected login-binding cookie that the login-initiation handler
/// set on the initiating browser, so a state stolen/forged by an attacker
/// cannot be redeemed in a victim's browser (login-CSRF / session-swapping
/// defense). HTTPS uses `__Host-oidc_login_csrf`; explicit loopback HTTP uses
/// the unprefixed compatibility name.
pub async fn take(
    pool: &PgPool,
    state: &str,
    expected_origin_binding_digest: &[u8; 32],
) -> Result<LoginStateTakeOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_login_state_contract_v3(&mut tx).await?;
    let row = sqlx::query_as::<_, BurnedLoginStateRow>(
        "WITH expected_current AS MATERIALIZED ( \
             SELECT current_path.current_origin_binding_digest \
             FROM authenticator_authority_current_paths AS current_path \
             WHERE current_path.path_kind = 'browser-derived-session' \
               AND current_path.path_status = 'active' \
               AND current_path.current_origin_binding_digest = $2 \
             FOR SHARE OF current_path \
         ), burned AS ( \
             DELETE FROM oidc_login_states_v3 \
             WHERE state = $1 \
             RETURNING authenticator_origin_binding_digest, expires_at, \
                       nonce, pkce_verifier, binding \
         ) \
         SELECT \
             burned.authenticator_origin_binding_digest \
                 AS stored_origin_binding_digest, \
             burned.expires_at > statement_timestamp() AS is_live, \
             burned.authenticator_origin_binding_digest = $2 \
                 AND EXISTS (SELECT 1 FROM expected_current) AS is_current, \
             CASE WHEN burned.authenticator_origin_binding_digest = $2 \
                       AND burned.expires_at > statement_timestamp() \
                       AND EXISTS (SELECT 1 FROM expected_current) \
                  THEN burned.nonce END AS nonce, \
             CASE WHEN burned.authenticator_origin_binding_digest = $2 \
                       AND burned.expires_at > statement_timestamp() \
                       AND EXISTS (SELECT 1 FROM expected_current) \
                  THEN burned.pkce_verifier END AS pkce_verifier, \
             CASE WHEN burned.authenticator_origin_binding_digest = $2 \
                       AND burned.expires_at > statement_timestamp() \
                       AND EXISTS (SELECT 1 FROM expected_current) \
                  THEN burned.binding END AS binding \
         FROM burned",
    )
    .bind(state)
    .bind(expected_origin_binding_digest.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    classify_burned_login_state(row, expected_origin_binding_digest)
}

/// Delete at most one bounded batch of expired rows using database time.
pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_login_state_contract_v3(&mut tx).await?;
    let lock_acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(LOGIN_STATE_ADVISORY_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await?;
    if !lock_acquired {
        tx.rollback().await?;
        return Ok(0);
    }
    let result = sqlx::query(
        "WITH expired AS ( \
             SELECT state FROM oidc_login_states_v3 \
             WHERE expires_at <= statement_timestamp() \
             ORDER BY expires_at, state \
             FOR UPDATE SKIP LOCKED \
             LIMIT $1 \
         ) \
         DELETE FROM oidc_login_states_v3 AS target \
         USING expired \
         WHERE target.state = expired.state",
    )
    .bind(LOGIN_STATE_CLEANUP_BATCH)
    .execute(&mut *tx)
    .await?;
    let deleted = result.rows_affected();
    tx.commit().await?;
    Ok(deleted)
}

/// Independently reclaim expired login state in bounded batches even when no
/// further public login requests arrive. The shared background-loop heartbeat
/// makes persistent cleanup failure visible through the platform health probe;
/// insert admission also runs the same bounded cleanup and fails closed if it
/// cannot complete.
pub fn spawn_expired_login_state_cleanup(pool: PgPool, interval_secs: u64) {
    const LOOP_NAME: &str = "oidc-login-state-cleanup";
    tokio::spawn(async move {
        crate::background::register_loop(LOOP_NAME, interval_secs);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        let timeout = crate::background::iteration_timeout(interval_secs);
        let mut consecutive_failures = 0u32;
        loop {
            ticker.tick().await;
            match crate::background::run_bounded(timeout, cleanup_expired(&pool)).await {
                Ok(deleted) => {
                    consecutive_failures = 0;
                    crate::background::record_loop_success(LOOP_NAME);
                    tracing::debug!(deleted, "expired OIDC login-state cleanup completed");
                }
                Err(error) => {
                    let backoff = crate::background::note_failure(&mut consecutive_failures);
                    match error {
                        crate::background::IterError::Failed(error) => tracing::error!(
                            error = %error,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "expired OIDC login-state cleanup failed; backing off"
                        ),
                        crate::background::IterError::TimedOut => tracing::error!(
                            timeout_secs = timeout.as_secs(),
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "expired OIDC login-state cleanup timed out; backing off"
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

// ─── DB Tests ─────────────────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --bins oidc_login_states_db_tests -- --test-threads=1
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.

#[cfg(test)]
mod oidc_login_states_db_tests {
    use super::*;
    use sqlx::PgPool;

    fn peer(ip: &str) -> SocketAddr {
        format!("{ip}:443").parse().expect("test peer")
    }

    fn slow_test_quota(burst: u32) -> Quota {
        // A one-hour refill makes rejection assertions independent of ordinary
        // scheduler stalls while keeping tests on governor's production clock.
        Quota::per_hour(NonZeroU32::MIN)
            .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN))
    }

    fn test_admission(
        client_burst: u32,
        global_burst: u32,
        max_in_flight: usize,
    ) -> LoginInitiationAdmission {
        test_admission_with_trust(client_burst, global_burst, max_in_flight, vec![])
    }

    fn test_admission_with_trust(
        client_burst: u32,
        global_burst: u32,
        max_in_flight: usize,
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> LoginInitiationAdmission {
        LoginInitiationAdmission::from_quotas(
            slow_test_quota(client_burst),
            slow_test_quota(global_burst),
            max_in_flight,
            trusted_proxies,
        )
    }

    fn trusted(networks: &[&str]) -> Vec<ryuki_core::config::TrustedProxyNetwork> {
        networks
            .iter()
            .map(|network| {
                ryuki_core::config::TrustedProxyNetwork::parse(network)
                    .expect("test trusted-proxy network")
            })
            .collect()
    }

    fn admission_bucket(admission: &LoginInitiationAdmission, peer_addr: SocketAddr) -> String {
        let (client_key, _) =
            crate::resolve_rate_limit_client_key(peer_addr, None, &admission.trusted_proxies);
        crate::bounded_rate_limit_key("login-initiation", &client_key, &admission.bucket_salt)
    }

    fn peer_in_distinct_bucket(
        admission: &LoginInitiationAdmission,
        first: SocketAddr,
    ) -> SocketAddr {
        let first_bucket = admission_bucket(admission, first);
        (1..=254)
            .map(|octet| peer(&format!("198.51.100.{octet}")))
            .find(|candidate| {
                candidate.ip() != first.ip()
                    && admission_bucket(admission, *candidate) != first_bucket
            })
            .expect("test address mapping to a distinct bounded bucket")
    }

    #[test]
    fn process_admission_fails_closed_without_peer_context() {
        let result = admit_public_login_initiation(None, &HeaderMap::new(), &[]);
        assert!(matches!(
            result,
            Err(LoginInitiationAdmissionRejection::MissingPeer)
        ));
    }

    #[test]
    fn generated_protocol_material_is_unique_and_base64url_256() {
        let first = generate_login_state_material();
        let second = generate_login_state_material();
        assert_ne!(first.state, second.state);
        let values = [first.state, first.nonce, first.pkce_verifier, first.binding];
        assert_eq!(
            values
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            values.len(),
            "the four protocol values must be independently generated"
        );
        for value in values {
            assert_eq!(value.len(), 43, "32 bytes encode to 43 base64url chars");
            assert!(value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'));
        }
    }

    #[test]
    fn process_admission_enforces_per_source_and_global_budgets() {
        let per_source = test_admission(1, 100, 8);
        let first_peer = peer("192.0.2.10");
        let _first = per_source
            .try_admit(first_peer, None)
            .expect("first request from a source is admitted");
        assert!(matches!(
            per_source.try_admit(first_peer, None),
            Err(LoginInitiationAdmissionRejection::ClientRate)
        ));
        let other_peer = peer_in_distinct_bucket(&per_source, first_peer);
        let _other_source = per_source
            .try_admit(other_peer, None)
            .expect("an independent source retains its own budget");

        let untrusted_forwarding = test_admission(1, 100, 8);
        let _first = untrusted_forwarding
            .try_admit(peer("192.0.2.20"), Some("198.51.100.20"))
            .expect("first untrusted-peer request is admitted");
        assert!(matches!(
            untrusted_forwarding.try_admit(peer("192.0.2.20"), Some("198.51.100.21")),
            Err(LoginInitiationAdmissionRejection::ClientRate)
        ));

        let global = test_admission(100, 1, 8);
        let _first = global
            .try_admit(peer("198.51.100.10"), None)
            .expect("first global request is admitted");
        assert!(matches!(
            global.try_admit(peer("198.51.100.11"), None),
            Err(LoginInitiationAdmissionRejection::GlobalRate)
        ));
    }

    #[test]
    fn process_admission_strictly_handles_all_forwarded_header_fields() {
        use axum::http::HeaderValue;

        let trusted_proxies = trusted(&["10.0.0.0/8"]);
        let proxy_peer = peer("10.0.0.5");

        let duplicate_admission = test_admission_with_trust(1, 100, 8, trusted_proxies.clone());
        let mut duplicate = HeaderMap::new();
        duplicate.append("x-forwarded-for", HeaderValue::from_static("198.51.100.10"));
        duplicate.append("x-forwarded-for", HeaderValue::from_static("198.51.100.11"));
        let _first = duplicate_admission
            .try_admit_from_headers(proxy_peer, &duplicate)
            .expect("duplicate fields fall back to the TCP peer bucket");
        assert!(matches!(
            duplicate_admission.try_admit_from_headers(proxy_peer, &HeaderMap::new()),
            Err(LoginInitiationAdmissionRejection::ClientRate)
        ));

        let malformed_admission = test_admission_with_trust(1, 100, 8, trusted_proxies.clone());
        let mut malformed = HeaderMap::new();
        malformed.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.12, definitely-not-an-ip"),
        );
        let _first = malformed_admission
            .try_admit_from_headers(proxy_peer, &malformed)
            .expect("malformed chains fall back to the TCP peer bucket");
        assert!(matches!(
            malformed_admission.try_admit_from_headers(proxy_peer, &HeaderMap::new()),
            Err(LoginInitiationAdmissionRejection::ClientRate)
        ));

        let trusted_admission = test_admission_with_trust(1, 100, 8, trusted_proxies);
        let first_client = peer("198.51.100.20");
        let second_client = peer_in_distinct_bucket(&trusted_admission, first_client);
        let mut first_chain = HeaderMap::new();
        first_chain.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.20, 10.0.0.6"),
        );
        let mut second_chain = HeaderMap::new();
        second_chain.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("{}, 10.0.0.6", second_client.ip()))
                .expect("valid forwarded chain"),
        );
        let _first = trusted_admission
            .try_admit_from_headers(proxy_peer, &first_chain)
            .expect("trusted proxy chain resolves the first client");
        let _ = trusted_admission
            .try_admit_from_headers(proxy_peer, &second_chain)
            .expect("a distinct trusted client retains its own budget");
    }

    #[test]
    fn process_admission_is_non_queueing_at_in_flight_limit() {
        let admission = test_admission(100, 100, 1);
        let first = admission
            .try_admit(peer("203.0.113.10"), None)
            .expect("first in-flight request is admitted");
        assert!(matches!(
            admission.try_admit(peer("203.0.113.11"), None),
            Err(LoginInitiationAdmissionRejection::InFlight)
        ));
        drop(first);
        let _ = admission
            .try_admit(peer("203.0.113.11"), None)
            .expect("releasing the permit restores legitimate admission");
    }

    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!(
                    "oidc_login_states_db_tests: RYUKI_DATABASE_URL not set — skipping DB tests"
                );
                return None;
            }
        };
        let pool = PgPool::connect(&url)
            .await
            .expect("oidc_login_states_db_tests: RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply cleanly when RYUKI_DATABASE_URL is set");
        Some(pool)
    }

    fn random_distinct_test_digest(excluded: &[[u8; 32]]) -> [u8; 32] {
        loop {
            let candidate: [u8; 32] = rand::random();
            if candidate.iter().any(|byte| *byte != 0) && !excluded.contains(&candidate) {
                return candidate;
            }
        }
    }

    async fn provision_test_browser_origin_fixture(
        pool: &PgPool,
    ) -> Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin> {
        let origin = crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
            &format!("test{}", uuid::Uuid::new_v4().simple()),
        );
        crate::identity_authority::reconcile_test_authenticator_runtime(pool, &origin)
            .await
            .expect("publish paired current authenticator fixture");
        origin
    }

    async fn provision_test_browser_origin(pool: &PgPool) -> [u8; 32] {
        let origin = provision_test_browser_origin_fixture(pool).await;
        *origin.origin_binding_digest_bytes()
    }

    async fn delete_test_states(pool: &PgPool, states: &[String]) {
        if states.is_empty() {
            return;
        }
        let mut tx = pool.begin().await.expect("begin login-state cleanup");
        set_login_state_contract_v3(&mut tx)
            .await
            .expect("activate v3 login-state contract for cleanup");
        sqlx::query("DELETE FROM oidc_login_states_v3 WHERE state = ANY($1)")
            .bind(states)
            .execute(&mut *tx)
            .await
            .expect("delete login-state test fixtures");
        tx.commit().await.expect("commit login-state cleanup");
    }

    #[test]
    fn burned_row_classification_never_exposes_non_success_material() {
        let expected_origin = random_distinct_test_digest(&[]);
        let other_origin = random_distinct_test_digest(&[expected_origin]);

        let mismatched = classify_burned_login_state(
            Some(BurnedLoginStateRow {
                stored_origin_binding_digest: other_origin.to_vec(),
                is_live: true,
                is_current: true,
                nonce: None,
                pkce_verifier: None,
                binding: None,
            }),
            &expected_origin,
        )
        .expect("classify mismatch");
        assert_eq!(mismatched, LoginStateTakeOutcome::OriginMismatch);

        let expired = classify_burned_login_state(
            Some(BurnedLoginStateRow {
                stored_origin_binding_digest: expected_origin.to_vec(),
                is_live: false,
                is_current: true,
                nonce: None,
                pkce_verifier: None,
                binding: None,
            }),
            &expected_origin,
        )
        .expect("classify expiry");
        assert_eq!(expired, LoginStateTakeOutcome::Expired);

        let stale = classify_burned_login_state(
            Some(BurnedLoginStateRow {
                stored_origin_binding_digest: expected_origin.to_vec(),
                is_live: true,
                is_current: false,
                nonce: None,
                pkce_verifier: None,
                binding: None,
            }),
            &expected_origin,
        )
        .expect("classify stale origin");
        assert_eq!(stale, LoginStateTakeOutcome::OriginMismatch);

        let absent = classify_burned_login_state(None, &expected_origin)
            .expect("classify absent login state");
        assert_eq!(absent, LoginStateTakeOutcome::Absent);
    }

    #[tokio::test]
    async fn test_create_then_take_returns_nonce_and_pkce() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let origin = provision_test_browser_origin(&pool).await;
        let material = create(&pool, &origin).await.expect("create should succeed");

        let result = take(&pool, &material.state, &origin)
            .await
            .expect("take should not error");
        let LoginStateTakeOutcome::Redeemed {
            nonce: got_nonce,
            pkce_verifier: got_pkce,
            binding: got_binding,
        } = result
        else {
            panic!("exact live origin must redeem its state")
        };
        assert_eq!(got_nonce, material.nonce);
        assert_eq!(got_pkce, material.pkce_verifier);
        assert_eq!(got_binding, material.binding);
    }

    #[tokio::test]
    async fn test_take_is_single_use() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let origin = provision_test_browser_origin(&pool).await;
        let material = create(&pool, &origin).await.expect("create");

        let first = take(&pool, &material.state, &origin)
            .await
            .expect("first take");
        assert!(matches!(first, LoginStateTakeOutcome::Redeemed { .. }));

        let second = take(&pool, &material.state, &origin)
            .await
            .expect("second take");
        assert_eq!(second, LoginStateTakeOutcome::Absent);
    }

    #[tokio::test]
    async fn wrong_origin_attempt_burns_state_without_protocol_material() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let issuing_origin = provision_test_browser_origin(&pool).await;
        let wrong_origin = provision_test_browser_origin(&pool).await;
        let material = create(&pool, &issuing_origin).await.expect("create state");

        let mismatch = take(&pool, &material.state, &wrong_origin)
            .await
            .expect("burn state at wrong origin");
        assert_eq!(mismatch, LoginStateTakeOutcome::OriginMismatch);

        let retry = take(&pool, &material.state, &issuing_origin)
            .await
            .expect("retry at issuing origin");
        assert_eq!(
            retry,
            LoginStateTakeOutcome::Absent,
            "wrong-origin redemption must burn the state"
        );
    }

    #[tokio::test]
    async fn rolled_origin_rejects_old_inserts_and_returns_no_old_protocol_material() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let origin = provision_test_browser_origin_fixture(&pool).await;
        let old_digest = *origin.origin_binding_digest_bytes();
        let material = create(&pool, &old_digest)
            .await
            .expect("create state under initial current origin");
        let reconciliation = crate::identity_authority::reconcile_test_authenticator_epoch(
            &pool,
            &origin,
            2,
            true,
            "oidc-state-rollover-v2",
        )
        .await
        .expect("advance the paired provider epoch");
        assert_eq!(reconciliation.stale_login_states_deleted, 1);

        let stale_insert = generate_login_state_material();
        let error = insert_test_material(
            &pool,
            &old_digest,
            &stale_insert.state,
            &stale_insert.nonce,
            &stale_insert.pkce_verifier,
            &stale_insert.binding,
        )
        .await
        .expect_err("an old browser origin may not create new login state");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database_error| database_error.constraint()),
            Some("oidc_login_states_v3_current_origin_binding")
        );

        let outcome = take(&pool, &material.state, &old_digest)
            .await
            .expect("old state lookup remains fail closed");
        assert_eq!(outcome, LoginStateTakeOutcome::Absent);
    }

    #[tokio::test]
    async fn cleanup_contract_preserves_live_rows() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let origin = provision_test_browser_origin(&pool).await;
        let material = create(&pool, &origin).await.expect("create live state");
        cleanup_expired(&pool)
            .await
            .expect("v3-marked cleanup succeeds");
        let outcome = take(&pool, &material.state, &origin)
            .await
            .expect("redeem state after cleanup");
        assert!(matches!(outcome, LoginStateTakeOutcome::Redeemed { .. }));
    }

    #[tokio::test]
    async fn db_unmarked_insert_is_rejected_for_rolling_deployment_safety() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let origin = provision_test_browser_origin(&pool).await;
        let material = generate_login_state_material();
        let result = sqlx::query(
            "INSERT INTO oidc_login_states_v3 \
             (state, nonce, pkce_verifier, binding, \
              authenticator_origin_binding_digest, authenticator_path_kind) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&material.state)
        .bind(&material.nonce)
        .bind(&material.pkce_verifier)
        .bind(&material.binding)
        .bind(origin.as_slice())
        .bind(BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND)
        .execute(&pool)
        .await;
        let error = result.expect_err("an unmarked writer must fail closed");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.constraint()),
            Some("oidc_login_states_v3_writer_contract")
        );
    }

    #[tokio::test]
    async fn db_origin_and_global_outstanding_quotas_reject_growth() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let first_origin = provision_test_browser_origin(&pool).await;
        let other_origin = provision_test_browser_origin(&pool).await;
        let active_global: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oidc_login_states_v3 \
             WHERE expires_at > statement_timestamp()",
        )
        .fetch_one(&pool)
        .await
        .expect("count global active login states");
        let active_first_origin: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oidc_login_states_v3 \
             WHERE authenticator_origin_binding_digest = $1 \
               AND expires_at > statement_timestamp()",
        )
        .bind(first_origin.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count first-origin active login states");
        let per_origin_limit = active_first_origin + 1;
        let global_limit = active_global + 2;

        let first = create_with_limits(&pool, &first_origin, per_origin_limit, global_limit)
            .await
            .expect("the final origin slot is admitted");

        let result = create_with_limits(&pool, &first_origin, per_origin_limit, global_limit).await;
        assert!(matches!(result, Err(LoginStateInsertError::OriginCapacity)));

        let other = create_with_limits(&pool, &other_origin, per_origin_limit, global_limit)
            .await
            .expect("an independent origin retains its own capacity");

        let result =
            create_with_limits(&pool, &other_origin, per_origin_limit + 1, global_limit).await;
        assert!(matches!(result, Err(LoginStateInsertError::GlobalCapacity)));

        delete_test_states(&pool, &[first.state, other.state]).await;
    }

    #[tokio::test]
    async fn db_outstanding_quota_is_atomic_under_concurrency() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let origin = provision_test_browser_origin(&pool).await;
        let active_global: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oidc_login_states_v3 \
             WHERE expires_at > statement_timestamp()",
        )
        .fetch_one(&pool)
        .await
        .expect("count global active login states");
        let active_origin: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oidc_login_states_v3 \
             WHERE authenticator_origin_binding_digest = $1 \
               AND expires_at > statement_timestamp()",
        )
        .bind(origin.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count origin active login states");
        let per_origin_limit = active_origin + 1;
        let global_limit = active_global + 1;

        const CALLERS: usize = 8;
        let mut tasks = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                create_with_limits(&pool, &origin, per_origin_limit, global_limit).await
            }));
        }

        let mut admitted = 0usize;
        let mut states = Vec::with_capacity(CALLERS);
        for task in tasks {
            let result = task.await.expect("join admission task");
            match result {
                Ok(material) => {
                    admitted += 1;
                    states.push(material.state);
                }
                Err(LoginStateInsertError::Busy)
                | Err(LoginStateInsertError::OriginCapacity)
                | Err(LoginStateInsertError::GlobalCapacity) => {}
                Err(error) => panic!("unexpected concurrent admission error: {error}"),
            }
        }
        assert_eq!(
            admitted, 1,
            "serialized count-and-insert must admit exactly the final slot"
        );

        let active_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oidc_login_states_v3 \
                 WHERE expires_at > statement_timestamp()",
        )
        .fetch_one(&pool)
        .await
        .expect("count active states after race");
        assert_eq!(active_after, active_global + 1);

        delete_test_states(&pool, &states).await;
    }
}
