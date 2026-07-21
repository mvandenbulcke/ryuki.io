//! Provider-neutral identity authority epochs for persisted browser sessions.
//!
//! A session is accepted only while its captured epoch matches the current
//! `(provider, issuer, subject)` projection. Local configuration reconciliation
//! and normalized provider lifecycle events advance the epoch monotonically;
//! restoring an older credential or role configuration therefore cannot make an
//! older session valid again.

use chrono::{DateTime, Utc};
use ryuki_core::config::{AuthMode, LocalAuthConfig, LocalAuthUser, RyukiConfig, SessionConfig};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub const LOCAL_PROVIDER: &str = "local";
pub const LOCAL_ISSUER: &str = "urn:ryuki:local";
#[cfg(test)]
pub const ACTIVE_AUTHORITY_STATUS: &str = "active-scoped-v2";

fn cache_binding(
    authority: &crate::human_authority::EffectiveHumanAuthority,
) -> crate::session_lookup_admission::SessionAuthorityCacheBinding {
    crate::session_lookup_admission::SessionAuthorityCacheBinding {
        authority_fingerprint: authority.authority_fingerprint,
        assignment_version: authority.assignment_version,
        assignment_status: crate::session_lookup_admission::CachedAssignmentStatus::Active,
        site_global: authority.site_mode == crate::human_authority::HumanAuthorityMode::Global,
        environment_global: authority.environment_mode
            == crate::human_authority::HumanAuthorityMode::Global,
    }
}

#[derive(Debug, Clone)]
pub struct CreatedHumanSession {
    pub expires_at: DateTime<Utc>,
    pub roles: Vec<String>,
}

pub(crate) struct AdmittedFederatedBearer {
    pub session: ryuki_engine::auth::AuthSession,
    pub authority: crate::human_authority::InteractiveHumanAuthorityContext,
    pub identity_authority_digest: [u8; 32],
    pub identity_last_asserted_at: DateTime<Utc>,
}

pub fn configured_entra_issuer(config: &RyukiConfig) -> String {
    format!(
        "{}/{}/v2.0",
        config.entra_authority.trim_end_matches('/'),
        config.entra_tenant_id
    )
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityAuthorityError {
    #[error("identity authority database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("identity authority credential key is unavailable")]
    Credential(#[from] crate::session_credentials::SessionCredentialError),
    #[error("identity authority input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("identity authority is revoked or the assertion is stale")]
    AssertionRejected,
    #[error("configured local identity authority was not reconciled")]
    LocalAuthorityMissing,
    #[error("interactive human authority was rejected")]
    HumanAuthority(#[from] crate::human_authority::HumanAuthorityError),
}

fn validate_identity_key(
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), IdentityAuthorityError> {
    if provider.is_empty()
        || provider.len() > 64
        || !provider.as_bytes().iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(*byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(IdentityAuthorityError::InvalidInput("provider"));
    }
    if issuer.is_empty() || issuer.len() > 2048 {
        return Err(IdentityAuthorityError::InvalidInput("issuer"));
    }
    if subject.is_empty() || subject.len() > 512 {
        return Err(IdentityAuthorityError::InvalidInput("subject"));
    }
    Ok(())
}

/// Reconciles the complete immutable startup local-account configuration with
/// the durable authority projection. Changed or removed accounts advance their
/// epoch inside one serialized transaction. Startup must fail if this cannot be
/// completed before local-auth traffic is served.
pub async fn reconcile_local_authorities(
    pool: &PgPool,
    local_auth: &LocalAuthConfig,
    session: &SessionConfig,
) -> Result<(), IdentityAuthorityError> {
    let mut digests = Vec::with_capacity(local_auth.users.len());
    for user in local_auth.users.users() {
        validate_identity_key(LOCAL_PROVIDER, LOCAL_ISSUER, &user.username)?;
        let digest = crate::session_credentials::local_identity_authority_digest(user, session)?;
        let assignment =
            crate::human_authority::HumanAuthorityAssignmentSpec::local(local_auth, &user.roles)?;
        digests.push((user, digest, assignment));
    }

    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock( \
             hashtextextended('ryuki:local-authority-reconciliation:v2', 0) \
         )",
    )
    .execute(&mut *tx)
    .await?;
    crate::human_authority::mark_governed_identity_reactivation_tx(&mut tx).await?;

    // Digests were precomputed before the transaction so a key/configuration
    // error cannot leave a partially reconciled authority set.
    for (user, digest, assignment) in digests {
        crate::human_authority::prepare_writer_tx(
            &mut tx,
            LOCAL_PROVIDER,
            LOCAL_ISSUER,
            &user.username,
        )
        .await?;
        let _epoch = sqlx::query_scalar::<_, i64>(
            "INSERT INTO identity_authorities \
             (provider, issuer, subject, authority_epoch, authority_digest, authority_status, \
              source_watermark, last_asserted_at, updated_at) \
             VALUES ($1, $2, $3, 1, $4, 'active-scoped-v2', 0, NOW(), NOW()) \
             ON CONFLICT (provider, issuer, subject) DO UPDATE SET \
               authority_epoch = CASE \
                 WHEN identity_authorities.authority_status <> 'active-scoped-v2' \
                   OR identity_authorities.authority_digest <> EXCLUDED.authority_digest \
                 THEN identity_authorities.authority_epoch + 1 \
                 ELSE identity_authorities.authority_epoch \
               END, \
               authority_digest = EXCLUDED.authority_digest, \
               authority_status = 'active-scoped-v2', \
               source_watermark = 0, \
               last_asserted_at = NOW(), \
               updated_at = CASE \
                 WHEN identity_authorities.authority_status <> 'active-scoped-v2' \
                   OR identity_authorities.authority_digest <> EXCLUDED.authority_digest \
                 THEN NOW() ELSE identity_authorities.updated_at \
               END \
             RETURNING authority_epoch",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&user.username)
        .bind(digest.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        crate::human_authority::reconcile_assignment_tx(
            &mut tx,
            LOCAL_PROVIDER,
            LOCAL_ISSUER,
            &user.username,
            assignment,
        )
        .await?;
    }

    let configured_subjects: Vec<String> = local_auth
        .users
        .users()
        .iter()
        .map(|user| user.username.clone())
        .collect();
    let removed_subjects = sqlx::query_scalar::<_, String>(
        "SELECT subject FROM ( \
           SELECT subject FROM identity_authorities \
           WHERE provider = $1 AND issuer = $2 AND NOT (subject = ANY($3)) \
           UNION \
           SELECT subject FROM human_authority_assignments \
           WHERE provider = $1 AND issuer = $2 AND NOT (subject = ANY($3)) \
         ) removed ORDER BY subject",
    )
    .bind(LOCAL_PROVIDER)
    .bind(LOCAL_ISSUER)
    .bind(&configured_subjects)
    .fetch_all(&mut *tx)
    .await?;
    for subject in removed_subjects {
        crate::human_authority::prepare_writer_tx(&mut tx, LOCAL_PROVIDER, LOCAL_ISSUER, &subject)
            .await?;
        sqlx::query(
            "UPDATE identity_authorities SET \
               authority_epoch = authority_epoch + 1, \
               authority_status = 'revoked', \
               source_watermark = 0, \
               updated_at = NOW() \
             WHERE provider = $1 AND issuer = $2 AND subject = $3 \
               AND authority_status = 'active-scoped-v2'",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&subject)
        .execute(&mut *tx)
        .await?;
        crate::human_authority::reconcile_assignment_tx(
            &mut tx,
            LOCAL_PROVIDER,
            LOCAL_ISSUER,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "local-config",
                "local-config",
            ),
        )
        .await?;
    }

    tx.commit().await?;
    // Startup/config reconciliation runs before serving requests. Clearing the
    // bounded positive admission cache synchronously covers password, role,
    // scope, removal, and mode changes; every request still performs SQL.
    crate::session_lookup_admission::clear_positive_global();
    Ok(())
}

/// Removes persisted sessions whose provider/issuer tuple is no longer
/// admitted by the immutable startup configuration. This makes provider
/// disablement, tenant/issuer rotation, mode switches, and later configuration
/// rollback non-resurrecting: re-enabling a provider requires a new login.
///
/// The SQL consumes parallel provider/issuer arrays so a future provider
/// registry can supply more tuples without widening the session repository to
/// vendor-specific columns or fallback behavior.
pub async fn reconcile_session_provider_admission(
    pool: &PgPool,
    config: &RyukiConfig,
) -> Result<u64, IdentityAuthorityError> {
    let mut providers = Vec::new();
    let mut issuers = Vec::new();
    match &config.auth_mode {
        AuthMode::Local => {
            providers.push(LOCAL_PROVIDER.to_string());
            issuers.push(LOCAL_ISSUER.to_string());
        }
        AuthMode::EntraId => {
            providers.push("entra-id".to_string());
            issuers.push(configured_entra_issuer(config));
            if config.oidc.enabled {
                providers.push("oidc".to_string());
                issuers.push(config.oidc.issuer.clone());
            }
        }
        AuthMode::MockDryRun | AuthMode::StaticDryRun => {}
    }

    let mut tx = pool.begin().await?;
    let removed = sqlx::query(
        "DELETE FROM sessions s \
         WHERE NOT EXISTS ( \
           SELECT 1 \
           FROM UNNEST($1::TEXT[], $2::TEXT[]) AS admitted(provider, issuer) \
           WHERE admitted.provider = s.provider \
             AND admitted.issuer = s.identity_issuer \
         )",
    )
    .bind(&providers)
    .bind(&issuers)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    if removed > 0 {
        crate::session_lookup_admission::clear_positive_global();
    }
    Ok(removed)
}

/// Creates a local session only against an already reconciled, current account
/// projection. The authority read and session insert share one transaction.
pub async fn create_local_session(
    pool: &PgPool,
    user: &LocalAuthUser,
    session_record_id: Uuid,
    bearer_verifier: &[u8],
    max_age_secs: u64,
    session: &SessionConfig,
) -> Result<CreatedHumanSession, IdentityAuthorityError> {
    validate_identity_key(LOCAL_PROVIDER, LOCAL_ISSUER, &user.username)?;
    let digest = crate::session_credentials::local_identity_authority_digest(user, session)?;
    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(
        &mut tx,
        LOCAL_PROVIDER,
        LOCAL_ISSUER,
        &user.username,
    )
    .await?;
    let authority_epoch = sqlx::query_scalar::<_, i64>(
        "SELECT authority_epoch FROM identity_authorities \
         WHERE provider = $1 AND issuer = $2 AND subject = $3 \
           AND authority_status = 'active-scoped-v2' AND authority_digest = $4 \
         FOR SHARE",
    )
    .bind(LOCAL_PROVIDER)
    .bind(LOCAL_ISSUER)
    .bind(&user.username)
    .bind(digest.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(IdentityAuthorityError::LocalAuthorityMissing)?;

    let authority = crate::human_authority::resolve_assignment_tx(
        &mut tx,
        LOCAL_PROVIDER,
        LOCAL_ISSUER,
        &user.username,
        &crate::human_authority::HumanAuthorityAssertion::role_assertion(&user.roles),
    )
    .await?;
    let expires_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        "INSERT INTO sessions \
         (session_record_id, bearer_verifier, user_id, display_name, roles, provider, \
          identity_issuer, identity_subject, identity_authority_epoch, human_authority_version, \
          site_authority_mode, site_scope, environment_authority_mode, environment_scope, \
          expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                 NOW() + make_interval(secs => $15)) \
         RETURNING expires_at",
    )
    .bind(session_record_id)
    .bind(bearer_verifier)
    .bind(&user.username)
    .bind(&user.username)
    .bind(&authority.roles)
    .bind(LOCAL_PROVIDER)
    .bind(LOCAL_ISSUER)
    .bind(&user.username)
    .bind(authority_epoch)
    .bind(authority.assignment_version)
    .bind(authority.site_mode.as_db())
    .bind(&authority.site_scope)
    .bind(authority.environment_mode.as_db())
    .bind(&authority.environment_scope)
    .bind(max_age_secs as f64)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    let valid_for = (expires_at - Utc::now())
        .to_std()
        .unwrap_or(std::time::Duration::ZERO);
    crate::session_lookup_admission::register_positive_global(
        bearer_verifier,
        valid_for,
        cache_binding(&authority),
    );
    Ok(CreatedHumanSession {
        expires_at,
        roles: authority.roles,
    })
}

pub(crate) async fn assert_federated_authority_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    roles: &[String],
    session: &SessionConfig,
) -> Result<i64, IdentityAuthorityError> {
    validate_identity_key(provider, issuer, subject)?;
    if provider == LOCAL_PROVIDER {
        return Err(IdentityAuthorityError::InvalidInput(
            "local authority is configuration-owned",
        ));
    }
    let digest = crate::session_credentials::identity_authority_digest(
        provider, issuer, subject, roles, session,
    )?;
    crate::human_authority::prepare_writer_tx(tx, provider, issuer, subject).await?;
    let epoch = sqlx::query_scalar::<_, i64>(
        "INSERT INTO identity_authorities \
         (provider, issuer, subject, authority_epoch, authority_digest, authority_status, \
          source_watermark, last_asserted_at, updated_at) \
         VALUES ($1, $2, $3, 1, $4, 'active-scoped-v2', 0, NOW(), NOW()) \
         ON CONFLICT (provider, issuer, subject) DO UPDATE SET \
           authority_epoch = CASE \
             WHEN identity_authorities.authority_digest <> EXCLUDED.authority_digest \
             THEN identity_authorities.authority_epoch + 1 \
             ELSE identity_authorities.authority_epoch \
           END, \
           authority_digest = EXCLUDED.authority_digest, \
           last_asserted_at = NOW(), \
           updated_at = CASE \
             WHEN identity_authorities.authority_digest <> EXCLUDED.authority_digest \
             THEN NOW() ELSE identity_authorities.updated_at \
           END \
         WHERE identity_authorities.authority_status = 'active-scoped-v2' \
           AND (identity_authorities.source_watermark = 0 \
                OR identity_authorities.authority_digest = EXCLUDED.authority_digest) \
         RETURNING authority_epoch",
    )
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .bind(digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(IdentityAuthorityError::AssertionRejected)?;
    Ok(epoch)
}

/// Atomically advances/checks a validated federated assertion and creates its
/// session. Once a normalized lifecycle watermark has been observed, callback
/// assertions may match the projection but may not rewrite it.
#[allow(clippy::too_many_arguments)]
pub async fn create_federated_session(
    pool: &PgPool,
    provider: &str,
    issuer: &str,
    subject: &str,
    display_name: &str,
    email: Option<&str>,
    roles: &[String],
    session_record_id: Uuid,
    bearer_verifier: &[u8],
    max_age_secs: u64,
    session: &SessionConfig,
) -> Result<(), IdentityAuthorityError> {
    let mut tx = pool.begin().await?;
    let authority_epoch =
        assert_federated_authority_tx(&mut tx, provider, issuer, subject, roles, session).await?;
    let authority = crate::human_authority::resolve_assignment_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        &crate::human_authority::HumanAuthorityAssertion::role_assertion(roles),
    )
    .await?;

    sqlx::query(
        "INSERT INTO sessions \
         (session_record_id, bearer_verifier, user_id, display_name, email, roles, provider, \
          identity_issuer, identity_subject, identity_authority_epoch, human_authority_version, \
          site_authority_mode, site_scope, environment_authority_mode, environment_scope, \
          expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                 NOW() + make_interval(secs => $16))",
    )
    .bind(session_record_id)
    .bind(bearer_verifier)
    .bind(subject)
    .bind(display_name)
    .bind(email)
    .bind(&authority.roles)
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .bind(authority_epoch)
    .bind(authority.assignment_version)
    .bind(authority.site_mode.as_db())
    .bind(&authority.site_scope)
    .bind(authority.environment_mode.as_db())
    .bind(&authority.environment_scope)
    .bind(max_age_secs as f64)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    crate::session_lookup_admission::register_positive_global(
        bearer_verifier,
        std::time::Duration::from_secs(max_age_secs),
        cache_binding(&authority),
    );
    Ok(())
}

/// Normalizes a cryptographically verified direct bearer through the same
/// provider-neutral identity and human-assignment transaction as browser
/// callbacks. Provider claims are only an upper bound; Unknown/Revoked/missing
/// assignments and empty role/scope intersections fail closed.
#[allow(clippy::too_many_arguments)]
pub async fn admit_federated_bearer(
    pool: &PgPool,
    provider: &str,
    issuer: &str,
    subject: &str,
    display_name: &str,
    asserted_roles: &[String],
    actor_class: ryuki_engine::auth::ActorClass,
    session: &SessionConfig,
) -> Result<AdmittedFederatedBearer, IdentityAuthorityError> {
    if actor_class != ryuki_engine::auth::ActorClass::VerifiedHuman {
        return Err(IdentityAuthorityError::AssertionRejected);
    }
    let mut tx = pool.begin().await?;
    let authority_epoch =
        assert_federated_authority_tx(&mut tx, provider, issuer, subject, asserted_roles, session)
            .await?;
    let authority = crate::human_authority::resolve_assignment_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        &crate::human_authority::HumanAuthorityAssertion::role_assertion(asserted_roles),
    )
    .await?;
    let (identity_authority_digest, identity_last_asserted_at) =
        sqlx::query_as::<_, (Vec<u8>, Option<DateTime<Utc>>)>(
            "SELECT authority_digest, last_asserted_at \
             FROM identity_authorities \
             WHERE provider = $1 AND issuer = $2 AND subject = $3 \
               AND authority_epoch = $4 AND authority_status = 'active-scoped-v2' \
             FOR SHARE",
        )
        .bind(provider)
        .bind(issuer)
        .bind(subject)
        .bind(authority_epoch)
        .fetch_one(&mut *tx)
        .await?;
    let identity_authority_digest: [u8; 32] = identity_authority_digest
        .as_slice()
        .try_into()
        .map_err(|_| IdentityAuthorityError::AssertionRejected)?;
    let identity_last_asserted_at =
        identity_last_asserted_at.ok_or(IdentityAuthorityError::AssertionRejected)?;
    let authority_context =
        crate::human_authority::InteractiveHumanAuthorityContext::from_effective(
            provider,
            issuer,
            subject,
            authority_epoch,
            &authority,
        );
    tx.commit().await?;
    Ok(AdmittedFederatedBearer {
        session: ryuki_engine::auth::AuthSession {
            user_id: subject.to_string(),
            display_name: display_name.to_string(),
            roles: authority.roles,
            token_valid: true,
            actor_class,
            provider_mode: provider.to_string(),
            site_scope: authority.site_scope,
            environment_scope: authority.environment_scope,
        },
        authority: authority_context,
        identity_authority_digest,
        identity_last_asserted_at,
    })
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityLifecycleState {
    Active,
    Revoked,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityLifecycleOutcome {
    pub applied: bool,
    pub authority_epoch: i64,
    pub state: AuthorityLifecycleState,
}

#[cfg(test)]
#[derive(sqlx::FromRow)]
struct AuthorityProjectionRow {
    authority_epoch: i64,
    authority_status: String,
    source_watermark: i64,
}

/// Test-only lifecycle kernel. Production provider activation stays unavailable
/// until authenticated event ordering, maker-checker review, expiry, and an
/// atomic audit/outbox contract are implemented together.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn apply_lifecycle_event(
    pool: &PgPool,
    provider: &str,
    issuer: &str,
    subject: &str,
    state: AuthorityLifecycleState,
    roles: &[String],
    source_watermark: i64,
    session: &SessionConfig,
) -> Result<AuthorityLifecycleOutcome, IdentityAuthorityError> {
    validate_identity_key(provider, issuer, subject)?;
    if provider == LOCAL_PROVIDER {
        return Err(IdentityAuthorityError::InvalidInput(
            "local authority is configuration-owned",
        ));
    }
    if source_watermark <= 0 {
        return Err(IdentityAuthorityError::InvalidInput("source watermark"));
    }
    if state == AuthorityLifecycleState::Revoked && !roles.is_empty() {
        return Err(IdentityAuthorityError::InvalidInput(
            "revoked event must not carry roles",
        ));
    }

    let digest = match state {
        AuthorityLifecycleState::Active => crate::session_credentials::identity_authority_digest(
            provider, issuer, subject, roles, session,
        )?,
        AuthorityLifecycleState::Revoked => [0_u8; 32],
    };
    let status = match state {
        AuthorityLifecycleState::Active => ACTIVE_AUTHORITY_STATUS,
        AuthorityLifecycleState::Revoked => "revoked",
    };

    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(&mut tx, provider, issuer, subject).await?;
    if state == AuthorityLifecycleState::Active {
        crate::human_authority::mark_governed_identity_reactivation_tx(&mut tx).await?;
    }
    let current = sqlx::query_as::<_, AuthorityProjectionRow>(
        "SELECT authority_epoch, authority_status, source_watermark \
         FROM identity_authorities \
         WHERE provider = $1 AND issuer = $2 AND subject = $3 \
         FOR UPDATE",
    )
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = if let Some(current) = current {
        if source_watermark <= current.source_watermark {
            AuthorityLifecycleOutcome {
                applied: false,
                authority_epoch: current.authority_epoch,
                state: if current.authority_status == ACTIVE_AUTHORITY_STATUS {
                    AuthorityLifecycleState::Active
                } else {
                    AuthorityLifecycleState::Revoked
                },
            }
        } else {
            let authority_epoch = current.authority_epoch.checked_add(1).ok_or(
                IdentityAuthorityError::InvalidInput("authority epoch exhausted"),
            )?;
            if state == AuthorityLifecycleState::Revoked {
                crate::human_authority::reconcile_assignment_tx(
                    &mut tx,
                    provider,
                    issuer,
                    subject,
                    crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                        "provider-lifecycle",
                        "provider-lifecycle",
                    ),
                )
                .await?;
            }
            sqlx::query(
                "UPDATE identity_authorities SET \
                   authority_epoch = $4, authority_digest = $5, authority_status = $6, \
                   source_watermark = $7, \
                   last_asserted_at = CASE WHEN $6 = 'active-scoped-v2' THEN NOW() ELSE NULL END, \
                   updated_at = NOW() \
                 WHERE provider = $1 AND issuer = $2 AND subject = $3",
            )
            .bind(provider)
            .bind(issuer)
            .bind(subject)
            .bind(authority_epoch)
            .bind(digest.as_slice())
            .bind(status)
            .bind(source_watermark)
            .execute(&mut *tx)
            .await?;
            AuthorityLifecycleOutcome {
                applied: true,
                authority_epoch,
                state,
            }
        }
    } else {
        if state == AuthorityLifecycleState::Revoked {
            crate::human_authority::reconcile_assignment_tx(
                &mut tx,
                provider,
                issuer,
                subject,
                crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                    "provider-lifecycle",
                    "provider-lifecycle",
                ),
            )
            .await?;
        }
        sqlx::query(
            "INSERT INTO identity_authorities \
             (provider, issuer, subject, authority_epoch, authority_digest, authority_status, \
              source_watermark, last_asserted_at, updated_at) \
             VALUES ($1, $2, $3, 1, $4, $5, $6, \
                     CASE WHEN $5 = 'active-scoped-v2' THEN NOW() ELSE NULL END, NOW())",
        )
        .bind(provider)
        .bind(issuer)
        .bind(subject)
        .bind(digest.as_slice())
        .bind(status)
        .bind(source_watermark)
        .execute(&mut *tx)
        .await?;
        AuthorityLifecycleOutcome {
            applied: true,
            authority_epoch: 1,
            state,
        }
    };

    tx.commit().await?;
    if outcome.applied {
        crate::session_lookup_admission::evict_authority_global(
            crate::human_authority::authority_fingerprint(provider, issuer, subject),
        );
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn session_config() -> SessionConfig {
        SessionConfig {
            credential_hmac_key: "placeholder-session-authority-key".repeat(2),
            federated_authority_max_staleness_secs: 60,
            ..Default::default()
        }
    }

    fn local_config(raw: &str) -> LocalAuthConfig {
        serde_json::from_value(serde_json::json!({
            "users": raw,
            "site_authority": "global",
            "environment_authority": "global"
        }))
        .unwrap()
    }

    fn scoped_local_config(raw: &str, sites: &str, environments: &str) -> LocalAuthConfig {
        serde_json::from_value(serde_json::json!({
            "users": raw,
            "site_authority": "scoped",
            "site_scope": sites,
            "environment_authority": "scoped",
            "environment_scope": environments
        }))
        .unwrap()
    }

    #[test]
    fn migration_invalidates_unversioned_sessions_without_legacy_defaults() {
        let migration = include_str!("../../../migrations/165_identity_authority_epochs.sql");
        let lock = migration.find("LOCK TABLE sessions").unwrap();
        let delete = migration.find("DELETE FROM sessions").unwrap();
        let issuer = migration
            .find("ADD COLUMN identity_issuer TEXT NOT NULL")
            .unwrap();
        assert!(lock < delete && delete < issuer);
        assert!(migration.contains("sessions_identity_authority_fk"));
        assert!(migration.contains("identity_authority_epoch BIGINT NOT NULL"));
        assert!(
            !migration.contains("identity_authority_epoch BIGINT NOT NULL DEFAULT"),
            "old writers must fail instead of inheriting an authority epoch"
        );
    }

    #[test]
    fn human_authority_migration_fences_old_replicas_and_orders_security_locks() {
        let migration = include_str!("../../../migrations/182_interactive_human_authority.sql");
        assert!(migration.contains("DELETE FROM sessions"));
        assert!(migration.contains("active-scoped-v2"));
        assert!(migration.contains("ALTER COLUMN authority_status DROP DEFAULT"));
        assert!(migration.contains("human_authority_assignment_delete_guard"));
        assert!(migration.contains("human_authority_assignment_truncate_guard"));
        assert!(migration.contains("identity_authorities_delete_guard"));
        assert!(migration.contains("identity_authorities_truncate_guard"));
        assert!(migration.contains("held.mode = 'ExclusiveLock'"));
        assert!(migration.contains("NEW.token_hash IS DISTINCT FROM OLD.token_hash"));
        assert!(migration.contains("NEW.expires_at IS DISTINCT FROM OLD.expires_at"));
        assert!(migration.contains("NEW.id IS DISTINCT FROM OLD.id"));
        assert!(migration.contains("api_tokens_revocation_shape_check"));
        assert!(migration.contains("expires_at <= created_at + INTERVAL '24 hours'"));
        assert!(migration.contains("API token revocation time may not be in the future"));
        assert!(migration.contains(
            "interactive session credentials and authority are immutable; revoke and reissue"
        ));
        assert!(migration.contains("CREATE FUNCTION enforce_api_token_last_used_at()"));
        assert!(migration.contains("NEW.last_used_at := GREATEST("));
        assert!(migration.contains("BEFORE INSERT OR UPDATE OF last_used_at ON api_tokens"));
        assert!(migration.contains("api_tokens_delete_guard"));
        assert!(migration.contains("api_tokens_truncate_guard"));
        assert!(migration.contains("DELETE FROM sessions\n        WHERE provider = OLD.provider"));
        let identity_lock = migration
            .find("FROM identity_authorities\n    WHERE provider = NEW.provider")
            .unwrap();
        let assignment_lock = migration
            .find("FROM human_authority_assignments\n    WHERE provider = NEW.provider")
            .unwrap();
        assert!(
            identity_lock < assignment_lock,
            "mint lock order is identity then assignment"
        );
        assert!(migration.contains("ADD COLUMN human_authority_version BIGINT NOT NULL"));
        assert!(
            !migration.contains("human_authority_version BIGINT NOT NULL DEFAULT"),
            "old session writers must not inherit an assignment generation"
        );
    }

    async fn global_pool() -> Option<&'static PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(url) if !url.is_empty() => url,
            _ => {
                eprintln!(
                    "identity_authority tests: RYUKI_DATABASE_URL not set -- skipping DB tests"
                );
                return None;
            }
        };
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()?;
        crate::database::run_migrations(pool).await.ok()?;
        Some(pool)
    }

    async fn session_is_current(pool: &PgPool, session_record_id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
               SELECT 1 FROM sessions s \
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
              WHERE s.session_record_id = $1 \
                AND a.authority_status = 'active-scoped-v2' \
                AND h.assignment_status = 'active' \
            )",
        )
        .bind(session_record_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn session_row_exists(pool: &PgPool, session_record_id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM sessions WHERE session_record_id = $1)",
        )
        .bind(session_record_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn carrier_results(config: &RyukiConfig, bearer: &str) -> [bool; 3] {
        let mut header = axum::http::HeaderMap::new();
        header.insert("X-Ryuki-Session-Id", bearer.parse().unwrap());
        let header_result = crate::auth_session_from_persisted_session(&header, None, config)
            .await
            .unwrap()
            .0
            .token_valid;

        let authorization = format!("Bearer {bearer}");
        let bearer_result = crate::auth_session_from_persisted_session(
            &axum::http::HeaderMap::new(),
            Some(&authorization),
            config,
        )
        .await
        .unwrap()
        .0
        .token_valid;

        let mut cookie = axum::http::HeaderMap::new();
        cookie.insert(
            axum::http::header::COOKIE,
            format!("__Host-ryuki_session={bearer}").parse().unwrap(),
        );
        let cookie_result = crate::auth_session_from_persisted_session(&cookie, None, config)
            .await
            .unwrap()
            .0
            .token_valid;
        [header_result, bearer_result, cookie_result]
    }

    async fn carrier_results_with_admission(
        config: &RyukiConfig,
        bearer: &str,
        admission: &std::sync::Arc<crate::session_lookup_admission::SessionLookupAdmission>,
    ) -> [bool; 3] {
        let mut header = axum::http::HeaderMap::new();
        header.insert("X-Ryuki-Session-Id", bearer.parse().unwrap());
        let header_result = crate::auth_session_from_persisted_session_with_admission(
            &header, None, config, admission, None,
        )
        .await
        .unwrap()
        .0
        .token_valid;

        let authorization = format!("Bearer {bearer}");
        let bearer_result = crate::auth_session_from_persisted_session_with_admission(
            &axum::http::HeaderMap::new(),
            Some(&authorization),
            config,
            admission,
            None,
        )
        .await
        .unwrap()
        .0
        .token_valid;

        let mut cookie = axum::http::HeaderMap::new();
        cookie.insert(
            axum::http::header::COOKIE,
            format!("__Host-ryuki_session={bearer}").parse().unwrap(),
        );
        let cookie_result = crate::auth_session_from_persisted_session_with_admission(
            &cookie, None, config, admission, None,
        )
        .await
        .unwrap()
        .0
        .token_valid;
        [header_result, bearer_result, cookie_result]
    }

    async fn cleanup_identity(pool: &PgPool, provider: &str, issuer: &str, subject: &str) {
        sqlx::query(
            "DELETE FROM sessions \
             WHERE provider = $1 AND identity_issuer = $2 AND identity_subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(subject)
        .execute(pool)
        .await
        .unwrap();
        // Identity authority rows are monotonic security tombstones. Tests
        // retire only ephemeral sessions; subsequent setup uses the governed
        // reactivation contract when it intentionally reuses a principal.
    }

    async fn provision_global_assignment(
        pool: &PgPool,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) {
        crate::human_authority::persist_governed_assignment(
            pool,
            provider,
            issuer,
            subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::test_global(roles),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn lookup_admission_bounds_database_misses_without_starving_valid_carriers() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let username = format!("lookup-admission-user-{}", Uuid::new_v4());
        let local = local_config(&format!("{username}:placeholder-pass-1:Auditor"));
        let config = RyukiConfig {
            auth_mode: AuthMode::Local,
            session: session.clone(),
            ..Default::default()
        };
        reconcile_local_authorities(pool, &local, &session)
            .await
            .unwrap();
        let credential = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_local_session(
            pool,
            &local.users.users()[0],
            Uuid::new_v4(),
            credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();

        // Emulate startup prewarm/session creation in an isolated admission
        // instance, then exhaust its new-miss window. All three supported
        // credential carriers remain available and still execute the complete
        // authority SQL check; a positive cache entry never authenticates.
        let valid_admission =
            crate::session_lookup_admission::SessionLookupAdmission::for_tests(8, 8, 1, 1);
        let assignment_version: i64 = sqlx::query_scalar(
            "SELECT assignment_version FROM human_authority_assignments \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        valid_admission.record_hit(
            *credential.verifier(),
            std::time::Duration::from_secs(3600),
            crate::session_lookup_admission::SessionAuthorityCacheBinding {
                authority_fingerprint: crate::human_authority::authority_fingerprint(
                    LOCAL_PROVIDER,
                    LOCAL_ISSUER,
                    &username,
                ),
                assignment_version,
                assignment_status: crate::session_lookup_admission::CachedAssignmentStatus::Active,
                site_global: true,
                environment_global: true,
            },
        );
        let random = crate::session_credentials::issue_session_credential(&session).unwrap();
        let consumed = valid_admission.try_admit(*random.verifier());
        assert!(matches!(
            consumed,
            crate::session_lookup_admission::SessionLookupDecision::Unknown(_)
        ));
        drop(consumed);
        assert_eq!(
            carrier_results_with_admission(&config, credential.bearer(), &valid_admission).await,
            [true, true, true]
        );
        assert_eq!(
            valid_admission.database_lookup_count(),
            3,
            "each valid carrier performs authority SQL even when miss admission is exhausted"
        );

        let stale_admission =
            crate::session_lookup_admission::SessionLookupAdmission::for_tests(8, 8, 2, 8);
        stale_admission.record_hit(
            *credential.verifier(),
            std::time::Duration::from_secs(3600),
            crate::session_lookup_admission::SessionAuthorityCacheBinding {
                authority_fingerprint: crate::human_authority::authority_fingerprint(
                    LOCAL_PROVIDER,
                    LOCAL_ISSUER,
                    &username,
                ),
                assignment_version: assignment_version + 1,
                assignment_status: crate::session_lookup_admission::CachedAssignmentStatus::Active,
                site_global: true,
                environment_global: true,
            },
        );
        assert_eq!(
            carrier_results_with_admission(&config, credential.bearer(), &stale_admission).await,
            [false, true, true],
            "stale assignment provenance denies once, evicts, and then requires a fresh SQL admission"
        );

        // The first random bearer performs one indexed lookup and establishes
        // a verifier-only negative entry. Replays through every other carrier
        // are rejected without another database call.
        let miss_admission =
            crate::session_lookup_admission::SessionLookupAdmission::for_tests(8, 8, 2, 8);
        assert_eq!(
            carrier_results_with_admission(&config, random.bearer(), &miss_admission).await,
            [false, false, false]
        );
        assert_eq!(
            miss_admission.database_lookup_count(),
            1,
            "a confirmed miss is shared across header, bearer, and cookie carriers"
        );

        cleanup_identity(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
    }

    #[tokio::test]
    async fn explicit_local_scopes_persist_and_deny_cross_site_or_environment() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let username = format!("scoped-local-{}", Uuid::new_v4());
        let local = scoped_local_config(
            &format!("{username}:placeholder-pass-1:PlatformAdmin|Auditor"),
            "SITE-A,SITE-B",
            "prod",
        );
        reconcile_local_authorities(pool, &local, &session)
            .await
            .unwrap();
        let credential = crate::session_credentials::issue_session_credential(&session).unwrap();
        let session_record_id = Uuid::new_v4();
        let created = create_local_session(
            pool,
            &local.users.users()[0],
            session_record_id,
            credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        assert_eq!(created.roles, ["Auditor", "PlatformAdmin"]);

        let config = RyukiConfig {
            auth_mode: AuthMode::Local,
            session: session.clone(),
            ..Default::default()
        };
        let resolved = crate::auth_session_from_persisted_session(
            &axum::http::HeaderMap::from_iter([(
                "X-Ryuki-Session-Id".parse().unwrap(),
                credential.bearer().parse().unwrap(),
            )]),
            None,
            &config,
        )
        .await
        .unwrap()
        .0;
        assert!(crate::contracts::row_scope_permits(
            &resolved, "SITE-A", "prod"
        ));
        assert!(!crate::contracts::row_scope_permits(
            &resolved, "SITE-C", "prod"
        ));
        assert!(!crate::contracts::row_scope_permits(
            &resolved, "SITE-A", "stage"
        ));

        let version_before_scope_change: i64 = sqlx::query_scalar(
            "SELECT assignment_version FROM human_authority_assignments \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        let narrowed = scoped_local_config(
            &format!("{username}:placeholder-pass-1:PlatformAdmin|Auditor"),
            "SITE-B",
            "prod",
        );
        reconcile_local_authorities(pool, &narrowed, &session)
            .await
            .unwrap();
        let version_after_scope_change: i64 = sqlx::query_scalar(
            "SELECT assignment_version FROM human_authority_assignments \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(version_after_scope_change > version_before_scope_change);
        assert!(!session_row_exists(pool, session_record_id).await);
        assert_eq!(
            carrier_results(&config, credential.bearer()).await,
            [false, false, false],
            "scope-version changes invalidate every carrier"
        );
        cleanup_identity(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
    }

    #[tokio::test]
    async fn direct_entra_bearer_is_intersected_and_unknown_or_revoked_fails_closed() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let provider = "entra-id";
        let issuer = "https://login.microsoftonline.example/tenant/v2.0";
        let subject = format!("direct-entra-{}", Uuid::new_v4());
        let assignment = crate::human_authority::HumanAuthorityAssignmentSpec {
            status: crate::human_authority::HumanAssignmentStatus::Active,
            role_allowlist: vec!["Auditor".to_string()],
            site_mode: crate::human_authority::HumanAuthorityMode::Scoped,
            site_scope: vec!["SITE-A".to_string()],
            environment_mode: crate::human_authority::HumanAuthorityMode::Scoped,
            environment_scope: vec!["prod".to_string()],
            source_kind: "governed",
            updated_by: "direct-bearer-test".to_string(),
        };
        crate::human_authority::persist_governed_assignment(
            pool, provider, issuer, &subject, assignment,
        )
        .await
        .unwrap();
        let asserted = vec!["PlatformAdmin".to_string(), "Auditor".to_string()];
        for actor_class in [
            ryuki_engine::auth::ActorClass::Workload,
            ryuki_engine::auth::ActorClass::Unknown,
        ] {
            assert!(matches!(
                admit_federated_bearer(
                    pool,
                    provider,
                    issuer,
                    &subject,
                    "Non-human bearer",
                    &asserted,
                    actor_class,
                    &session,
                )
                .await,
                Err(IdentityAuthorityError::AssertionRejected)
            ));
        }
        let admitted = admit_federated_bearer(
            pool,
            provider,
            issuer,
            &subject,
            "Direct Entra User",
            &asserted,
            ryuki_engine::auth::ActorClass::VerifiedHuman,
            &session,
        )
        .await
        .unwrap();
        assert_eq!(admitted.session.roles, ["Auditor"]);
        assert_eq!(admitted.session.site_scope, ["SITE-A"]);
        assert_eq!(admitted.session.environment_scope, ["prod"]);

        let unknown_subject = format!("unknown-entra-{}", Uuid::new_v4());
        assert!(matches!(
            admit_federated_bearer(
                pool,
                provider,
                issuer,
                &unknown_subject,
                "Unknown Entra User",
                &asserted,
                ryuki_engine::auth::ActorClass::VerifiedHuman,
                &session,
            )
            .await,
            Err(IdentityAuthorityError::HumanAuthority(
                crate::human_authority::HumanAuthorityError::NotActive
            ))
        ));

        crate::human_authority::persist_governed_assignment(
            pool,
            provider,
            issuer,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "governed",
                "direct-bearer-test",
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            admit_federated_bearer(
                pool,
                provider,
                issuer,
                &subject,
                "Direct Entra User",
                &asserted,
                ryuki_engine::auth::ActorClass::VerifiedHuman,
                &session,
            )
            .await,
            Err(IdentityAuthorityError::HumanAuthority(
                crate::human_authority::HumanAuthorityError::NotActive
            )) | Err(IdentityAuthorityError::AssertionRejected)
        ));
        cleanup_identity(pool, provider, issuer, &subject).await;
        cleanup_identity(pool, provider, issuer, &unknown_subject).await;
    }

    #[tokio::test]
    async fn local_password_role_removal_and_rollback_never_restore_old_session() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let username = format!("epoch-user-{}", Uuid::new_v4());
        let original = local_config(&format!(
            "{username}:placeholder-pass-1:PlatformAdmin|Auditor"
        ));
        let changed = local_config(&format!("{username}:placeholder-pass-2:Auditor"));
        let resolution_config = RyukiConfig {
            auth_mode: AuthMode::Local,
            session: session.clone(),
            ..Default::default()
        };

        reconcile_local_authorities(pool, &original, &session)
            .await
            .unwrap();
        let old_session = Uuid::new_v4();
        let old_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_local_session(
            pool,
            &original.users.users()[0],
            old_session,
            old_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        assert!(session_is_current(pool, old_session).await);
        let original_assignment_version: i64 = sqlx::query_scalar(
            "SELECT assignment_version FROM human_authority_assignments \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            carrier_results(&resolution_config, old_credential.bearer()).await,
            [true, true, true]
        );

        reconcile_local_authorities(pool, &changed, &session)
            .await
            .unwrap();
        let changed_assignment_version: i64 = sqlx::query_scalar(
            "SELECT assignment_version FROM human_authority_assignments \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(LOCAL_PROVIDER)
        .bind(LOCAL_ISSUER)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(changed_assignment_version > original_assignment_version);
        assert!(!session_is_current(pool, old_session).await);
        assert!(
            !session_row_exists(pool, old_session).await,
            "assignment version changes synchronously delete prior sessions"
        );
        assert_eq!(
            carrier_results(&resolution_config, old_credential.bearer()).await,
            [false, false, false],
            "all persisted-session carriers must enforce the same local epoch"
        );

        reconcile_local_authorities(pool, &original, &session)
            .await
            .unwrap();
        assert!(
            !session_is_current(pool, old_session).await,
            "rolling configuration back must not resurrect the old epoch"
        );

        let empty = local_config("");
        reconcile_local_authorities(pool, &empty, &session)
            .await
            .unwrap();
        assert!(!session_is_current(pool, old_session).await);
        cleanup_identity(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
    }

    #[tokio::test]
    async fn provider_disable_issuer_rotation_and_mode_rollback_delete_old_sessions() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();

        let username = format!("mode-user-{}", Uuid::new_v4());
        let local = local_config(&format!("{username}:placeholder-pass-1:PlatformAdmin"));
        reconcile_local_authorities(pool, &local, &session)
            .await
            .unwrap();
        let local_session = Uuid::new_v4();
        let local_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_local_session(
            pool,
            &local.users.users()[0],
            local_session,
            local_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();

        let disabled_local_config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            session: session.clone(),
            ..Default::default()
        };
        reconcile_local_authorities(pool, &LocalAuthConfig::default(), &session)
            .await
            .unwrap();
        let removed = reconcile_session_provider_admission(pool, &disabled_local_config)
            .await
            .unwrap();
        assert!(removed >= 1);
        assert!(!session_row_exists(pool, local_session).await);

        let local_enabled_again = RyukiConfig {
            auth_mode: AuthMode::Local,
            session: session.clone(),
            ..Default::default()
        };
        reconcile_local_authorities(pool, &local, &session)
            .await
            .unwrap();
        reconcile_session_provider_admission(pool, &local_enabled_again)
            .await
            .unwrap();
        assert!(
            !session_row_exists(pool, local_session).await,
            "Local -> Entra -> Local must not resurrect the pre-switch row"
        );

        let provider = "oidc";
        let issuer = "https://identity.example.test/provider-admission";
        let rotated_issuer = "https://identity.example.test/provider-admission-v2";
        let subject = format!("admission-subject-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &roles).await;
        let oidc_session = Uuid::new_v4();
        let oidc_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Admission Test",
            None,
            &roles,
            oidc_session,
            oidc_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        let mut oidc_enabled = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            session: session.clone(),
            ..Default::default()
        };
        oidc_enabled.oidc.enabled = true;
        oidc_enabled.oidc.issuer = issuer.to_string();
        reconcile_session_provider_admission(pool, &oidc_enabled)
            .await
            .unwrap();
        assert!(session_row_exists(pool, oidc_session).await);

        let mut issuer_rotated = oidc_enabled.clone();
        issuer_rotated.oidc.issuer = rotated_issuer.to_string();
        let removed = reconcile_session_provider_admission(pool, &issuer_rotated)
            .await
            .unwrap();
        assert!(removed >= 1);
        assert!(!session_row_exists(pool, oidc_session).await);
        reconcile_session_provider_admission(pool, &oidc_enabled)
            .await
            .unwrap();
        assert!(
            !session_row_exists(pool, oidc_session).await,
            "issuer rollback must require a new login rather than restore the old row"
        );

        cleanup_identity(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
        cleanup_identity(pool, provider, issuer, &subject).await;
    }

    #[tokio::test]
    async fn federated_lifecycle_events_reject_stale_roles_revocation_and_rollback() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let provider = "oidc";
        let issuer = "https://identity.example.test/tenant";
        let subject = format!("subject-{}", Uuid::new_v4());
        let mut resolution_config = ryuki_core::config::RyukiConfig {
            auth_mode: ryuki_core::config::AuthMode::EntraId,
            session: session.clone(),
            ..Default::default()
        };
        resolution_config.oidc.enabled = true;
        resolution_config.oidc.issuer = issuer.to_string();
        let privileged = vec!["PlatformAdmin".to_string()];
        let reduced = vec!["Auditor".to_string()];
        let assignment_roles = vec!["Auditor".to_string(), "PlatformAdmin".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &assignment_roles).await;

        let first = Uuid::new_v4();
        let first_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Test User",
            None,
            &privileged,
            first,
            first_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        assert!(session_is_current(pool, first).await);
        assert_eq!(
            carrier_results(&resolution_config, first_credential.bearer()).await,
            [true, true, true]
        );

        let sibling = Uuid::new_v4();
        let sibling_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Test User",
            None,
            &privileged,
            sibling,
            sibling_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();

        let other_issuer = "https://identity.example.test/other-tenant";
        provision_global_assignment(pool, provider, other_issuer, &subject, &assignment_roles)
            .await;
        let namespace_session = Uuid::new_v4();
        let namespace_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            other_issuer,
            &subject,
            "Same Subject, Other Issuer",
            None,
            &privileged,
            namespace_session,
            namespace_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        let mut namespace_config = resolution_config.clone();
        namespace_config.oidc.issuer = other_issuer.to_string();

        // The authority upsert and session insert are one transaction. Reuse
        // the different-issuer session ID because the epoch trigger removes
        // same-authority sessions before the insert. The surviving row still
        // forces a post-upsert primary-key failure, which must roll the epoch
        // change back and leave every previously valid session usable.
        let failed_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        let failed_role_change = create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Test User",
            None,
            &reduced,
            namespace_session,
            failed_credential.verifier(),
            3600,
            &session,
        )
        .await;
        assert!(matches!(
            failed_role_change,
            Err(IdentityAuthorityError::Database(_))
        ));
        assert!(session_is_current(pool, first).await);
        assert!(session_is_current(pool, sibling).await);

        let reduced_event = apply_lifecycle_event(
            pool,
            provider,
            issuer,
            &subject,
            AuthorityLifecycleState::Active,
            &reduced,
            10,
            &session,
        )
        .await
        .unwrap();
        assert!(reduced_event.applied);
        assert!(!session_is_current(pool, first).await);
        assert!(!session_is_current(pool, sibling).await);
        assert!(
            session_is_current(pool, namespace_session).await,
            "same subject text under another issuer must remain isolated"
        );
        assert_eq!(
            carrier_results(&namespace_config, namespace_credential.bearer()).await,
            [true, true, true]
        );

        let stale_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        let stale_assertion = create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Test User",
            None,
            &privileged,
            Uuid::new_v4(),
            stale_credential.verifier(),
            3600,
            &session,
        )
        .await;
        assert!(matches!(
            stale_assertion,
            Err(IdentityAuthorityError::AssertionRejected)
        ));

        let current = Uuid::new_v4();
        let current_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Test User",
            None,
            &reduced,
            current,
            current_credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        assert!(session_is_current(pool, current).await);
        assert_eq!(
            carrier_results(&resolution_config, current_credential.bearer()).await,
            [true, true, true]
        );

        let mut stale_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut stale_tx, provider, issuer, &subject)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE identity_authorities SET \
               last_asserted_at = NOW() - make_interval(secs => $4) \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .bind((session.federated_authority_max_staleness_secs + 1) as f64)
        .execute(&mut *stale_tx)
        .await
        .unwrap();
        stale_tx.commit().await.unwrap();
        assert_eq!(
            carrier_results(&resolution_config, current_credential.bearer()).await,
            [false, false, false],
            "a delayed lifecycle feed must fail closed for every carrier"
        );

        let revoked = apply_lifecycle_event(
            pool,
            provider,
            issuer,
            &subject,
            AuthorityLifecycleState::Revoked,
            &[],
            11,
            &session,
        )
        .await
        .unwrap();
        assert!(revoked.applied);
        assert!(!session_is_current(pool, current).await);

        let stale_rollback = apply_lifecycle_event(
            pool,
            provider,
            issuer,
            &subject,
            AuthorityLifecycleState::Active,
            &privileged,
            10,
            &session,
        )
        .await
        .unwrap();
        assert!(!stale_rollback.applied);
        assert_eq!(stale_rollback.state, AuthorityLifecycleState::Revoked);
        assert!(!session_is_current(pool, current).await);

        cleanup_identity(pool, provider, issuer, &subject).await;
        cleanup_identity(pool, provider, other_issuer, &subject).await;
    }

    #[tokio::test]
    async fn assignment_revoke_commits_while_concurrent_session_mint_fails() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let provider = "brokered-saml";
        let issuer = "urn:ryuki:test:concurrent-revoke";
        let subject = format!("race-subject-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &roles).await;

        let initial = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Race Subject",
            None,
            &roles,
            Uuid::new_v4(),
            initial.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();

        // The updater locks assignment -> deletes sessions -> advances the
        // tombstone version. A mint on another connection may lock identity,
        // but must wait for this assignment lock and then observe Revoked.
        let mut revoke_tx = pool.begin().await.unwrap();
        crate::human_authority::reconcile_assignment_tx(
            &mut revoke_tx,
            provider,
            issuer,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "governed",
                "two-connection-test",
            ),
        )
        .await
        .unwrap();

        let mint_pool = pool.clone();
        let mint_session = session.clone();
        let mint_subject = subject.clone();
        let mint_roles = roles.clone();
        let mut mint = tokio::spawn(async move {
            let credential =
                crate::session_credentials::issue_session_credential(&mint_session).unwrap();
            create_federated_session(
                &mint_pool,
                provider,
                issuer,
                &mint_subject,
                "Race Subject",
                None,
                &mint_roles,
                Uuid::new_v4(),
                credential.verifier(),
                3600,
                &mint_session,
            )
            .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut mint)
                .await
                .is_err(),
            "mint must wait while the authority revoke transaction owns the writer order"
        );
        revoke_tx.commit().await.unwrap();

        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), mint)
                .await
                .expect("mint must finish without a database deadlock")
                .unwrap(),
            Err(IdentityAuthorityError::HumanAuthority(
                crate::human_authority::HumanAuthorityError::NotActive
            ))
        ));
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions \
             WHERE provider = $1 AND identity_issuer = $2 AND identity_subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0, "revoke must win without rolling back");
        cleanup_identity(pool, provider, issuer, &subject).await;
    }

    #[tokio::test]
    async fn assignment_revoke_and_lifecycle_revoke_serialize_without_deadlock() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let provider = "brokered-saml";
        let issuer = "urn:ryuki:test:lifecycle-assignment-order";
        let subject = format!("lifecycle-order-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &roles).await;
        let credential = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Lifecycle Order Subject",
            None,
            &roles,
            Uuid::new_v4(),
            credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();

        let mut assignment_tx = pool.begin().await.unwrap();
        crate::human_authority::reconcile_assignment_tx(
            &mut assignment_tx,
            provider,
            issuer,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "governed",
                "deadlock-regression",
            ),
        )
        .await
        .unwrap();

        let lifecycle_pool = pool.clone();
        let lifecycle_subject = subject.clone();
        let lifecycle_session = session.clone();
        let mut lifecycle = tokio::spawn(async move {
            apply_lifecycle_event(
                &lifecycle_pool,
                provider,
                issuer,
                &lifecycle_subject,
                AuthorityLifecycleState::Revoked,
                &[],
                1,
                &lifecycle_session,
            )
            .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut lifecycle)
                .await
                .is_err(),
            "the second authority writer must wait on the per-identity writer order"
        );
        assignment_tx.commit().await.unwrap();

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), lifecycle)
            .await
            .expect("lifecycle writer must complete without a database deadlock")
            .unwrap()
            .unwrap();
        assert!(outcome.applied);
        assert_eq!(outcome.state, AuthorityLifecycleState::Revoked);
        let states: (String, String) = sqlx::query_as(
            "SELECT a.authority_status, h.assignment_status \
             FROM identity_authorities a \
             JOIN human_authority_assignments h USING (provider, issuer, subject) \
             WHERE a.provider = $1 AND a.issuer = $2 AND a.subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(states, ("revoked".to_string(), "revoked".to_string()));
        cleanup_identity(pool, provider, issuer, &subject).await;
    }

    #[tokio::test]
    async fn direct_writer_cannot_preseed_future_or_revoked_identity_epoch() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let provider = "passkey";
        let issuer = "urn:ryuki:test:passkey";
        let subject = format!("future-epoch-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &roles).await;
        let credential = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            provider,
            issuer,
            &subject,
            "Passkey Subject",
            None,
            &roles,
            Uuid::new_v4(),
            credential.verifier(),
            3600,
            &session,
        )
        .await
        .unwrap();
        let (epoch, version): (i64, i64) = sqlx::query_as(
            "SELECT a.authority_epoch, h.assignment_version \
             FROM identity_authorities a \
             JOIN human_authority_assignments h USING (provider, issuer, subject) \
             WHERE a.provider = $1 AND a.issuer = $2 AND a.subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();

        let old_reader_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions s \
             JOIN identity_authorities a \
               ON a.provider = s.provider AND a.issuer = s.identity_issuer \
              AND a.subject = s.identity_subject \
              AND a.authority_epoch = s.identity_authority_epoch \
             WHERE s.provider = $1 AND s.identity_issuer = $2 AND s.identity_subject = $3 \
               AND a.authority_status = 'active'",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            old_reader_count, 0,
            "pre-182 readers are fenced by v2 status"
        );

        let old_writer = sqlx::query(
            "INSERT INTO sessions \
             (session_record_id, bearer_verifier, user_id, display_name, roles, provider, \
              identity_issuer, identity_subject, identity_authority_epoch, expires_at) \
             VALUES ($1, $2, $3, 'Old Replica', ARRAY['Auditor']::TEXT[], $4, $5, $3, $6, \
                     NOW() + INTERVAL '1 hour')",
        )
        .bind(Uuid::new_v4())
        .bind(Sha256::digest(Uuid::new_v4().as_bytes()).to_vec())
        .bind(&subject)
        .bind(provider)
        .bind(issuer)
        .bind(epoch)
        .execute(pool)
        .await;
        assert!(
            old_writer.is_err(),
            "pre-182 session writers must be fenced"
        );

        let mut future_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut future_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let future = sqlx::query(
            "INSERT INTO sessions \
             (session_record_id, bearer_verifier, user_id, display_name, roles, provider, \
              identity_issuer, identity_subject, identity_authority_epoch, human_authority_version, \
              site_authority_mode, site_scope, environment_authority_mode, environment_scope, expires_at) \
             VALUES ($1, $2, $3, 'Direct Writer', ARRAY['Auditor']::TEXT[], $4, $5, $3, $6, $7, \
                     'global', ARRAY[]::TEXT[], 'global', ARRAY[]::TEXT[], NOW() + INTERVAL '1 hour')",
        )
        .bind(Uuid::new_v4())
        .bind(Sha256::digest(Uuid::new_v4().as_bytes()).to_vec())
        .bind(&subject)
        .bind(provider)
        .bind(issuer)
        .bind(epoch + 1)
        .bind(version)
        .execute(&mut *future_tx)
        .await
        .unwrap_err();
        assert_eq!(
            future
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(future_tx);

        let mut same_epoch_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut same_epoch_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let same_epoch = sqlx::query(
            "UPDATE identity_authorities SET authority_digest = $4 \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .bind(Sha256::digest(b"same-epoch-mutation").to_vec())
        .execute(&mut *same_epoch_tx)
        .await
        .unwrap_err();
        assert_eq!(
            same_epoch
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(same_epoch_tx);

        let mut jump_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut jump_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let jump = sqlx::query(
            "UPDATE identity_authorities SET authority_epoch = authority_epoch + 2, \
                    authority_digest = $4 \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .bind(Sha256::digest(b"epoch-jump").to_vec())
        .execute(&mut *jump_tx)
        .await
        .unwrap_err();
        assert_eq!(
            jump.as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(jump_tx);

        apply_lifecycle_event(
            pool,
            provider,
            issuer,
            &subject,
            AuthorityLifecycleState::Revoked,
            &[],
            1,
            &session,
        )
        .await
        .unwrap();
        let (revoked_epoch, revoked_version): (i64, i64) = sqlx::query_as(
            "SELECT a.authority_epoch, h.assignment_version \
             FROM identity_authorities a \
             JOIN human_authority_assignments h USING (provider, issuer, subject) \
             WHERE a.provider = $1 AND a.issuer = $2 AND a.subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();

        let mut rewind_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut rewind_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let rewind = sqlx::query(
            "UPDATE identity_authorities SET authority_epoch = authority_epoch - 1 \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .execute(&mut *rewind_tx)
        .await
        .unwrap_err();
        assert_eq!(
            rewind
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(rewind_tx);

        let mut watermark_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut watermark_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let watermark = sqlx::query(
            "UPDATE identity_authorities SET authority_epoch = authority_epoch + 1, \
                    source_watermark = source_watermark - 1 \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .execute(&mut *watermark_tx)
        .await
        .unwrap_err();
        assert_eq!(
            watermark
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(watermark_tx);

        let mut reactivation_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut reactivation_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let reactivation = sqlx::query(
            "UPDATE identity_authorities SET authority_epoch = authority_epoch + 1, \
                    authority_status = 'active-scoped-v2', \
                    source_watermark = source_watermark + 1 \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .execute(&mut *reactivation_tx)
        .await
        .unwrap_err();
        assert_eq!(
            reactivation
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(reactivation_tx);

        let delete = sqlx::query(
            "DELETE FROM identity_authorities \
             WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(&subject)
        .execute(pool)
        .await
        .unwrap_err();
        assert_eq!(
            delete
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        let mut revoked_tx = pool.begin().await.unwrap();
        crate::human_authority::prepare_writer_tx(&mut revoked_tx, provider, issuer, &subject)
            .await
            .unwrap();
        let revoked = sqlx::query(
            "INSERT INTO sessions \
             (session_record_id, bearer_verifier, user_id, display_name, roles, provider, \
              identity_issuer, identity_subject, identity_authority_epoch, human_authority_version, \
              site_authority_mode, site_scope, environment_authority_mode, environment_scope, expires_at) \
             VALUES ($1, $2, $3, 'Direct Writer', ARRAY['Auditor']::TEXT[], $4, $5, $3, $6, $7, \
                     'global', ARRAY[]::TEXT[], 'global', ARRAY[]::TEXT[], NOW() + INTERVAL '1 hour')",
        )
        .bind(Uuid::new_v4())
        .bind(Sha256::digest(Uuid::new_v4().as_bytes()).to_vec())
        .bind(&subject)
        .bind(provider)
        .bind(issuer)
        .bind(revoked_epoch)
        .bind(revoked_version)
        .execute(&mut *revoked_tx)
        .await
        .unwrap_err();
        assert_eq!(
            revoked
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        drop(revoked_tx);
        cleanup_identity(pool, provider, issuer, &subject).await;
    }
}
