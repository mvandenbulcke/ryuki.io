//! Interactive identity admission through the opaque principal registry.
//!
//! Provider-qualified subjects remain credential provenance only. Local,
//! federated-session, and direct-bearer paths must resolve an exact active
//! principal/key/link generation before they can mint authority, and lifecycle
//! revocation tombstones that key instead of deriving or relinking an identity.

use chrono::{DateTime, Utc};
#[cfg(test)]
use ryuki_core::config::{AuthMode, RyukiConfig, SessionConfig};
use ryuki_core::config::{LocalAuthConfig, LocalAuthUser};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const LOCAL_PROVIDER: &str = "local";
pub const LOCAL_ISSUER: &str = "urn:ryuki:local";

const BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND: &str = "browser-derived-session";
const DIRECT_BEARER_AUTHENTICATOR_PATH_KIND: &str = "bearer";
const AUTHENTICATOR_PATH_STATUS_ACTIVE: &str = "active";
const AUTHENTICATOR_PATH_STATUS_DISABLED: &str = "disabled";
const PRINCIPAL_BEARER_ORIGIN_CONTRACT_SETTING: &str =
    "ryuki.principal_bearer_origin_binding_digest_v3";
const AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH: i64 = 512;
const AUTHENTICATOR_ORIGIN_ROLLOVER_MAX_DELETE_BATCHES: usize = 128;
const AUTHENTICATOR_AUTHORITY_GENERATION_INSERT_SQL: &str =
    "INSERT INTO authenticator_authority_generations ( \
         authenticator_origin_binding_digest, deployment_id, trust_domain_id, tenant_id, \
         provider_id, provider_configuration_version, \
         provider_configuration_payload_digest, provider_lifecycle_record_version, \
         provider_lifecycle_state, binding_document_id, binding_document_version, \
         binding_document_digest, binding_document_locator, provider_policy_binding_digest, \
         runtime_binding_digest, path_id, path_version, path_kind \
     ) VALUES ( \
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18 \
     ) ON CONFLICT DO NOTHING";
const AUTHENTICATOR_AUTHORITY_GENERATION_SELECT_SQL: &str =
    "SELECT authenticator_origin_binding_digest, deployment_id, trust_domain_id, tenant_id, \
            provider_id, provider_configuration_version, \
            provider_configuration_payload_digest, provider_lifecycle_record_version, \
            provider_lifecycle_state, binding_document_id, binding_document_version, \
            binding_document_digest, binding_document_locator, provider_policy_binding_digest, \
            runtime_binding_digest, path_id, path_version, path_kind \
     FROM authenticator_authority_generations \
     WHERE authenticator_origin_binding_digest = $1";
const FEDERATED_SESSION_INSERT_SQL: &str = "INSERT INTO sessions \
     (session_record_id, session_bearer_verifier_v3, principal_id, \
      principal_lifecycle_version, principal_authority_version, principal_key_id, \
      principal_key_version, principal_link_id, principal_link_version, \
      display_name, email, roles, site_authority_mode, site_scope, \
      environment_authority_mode, environment_scope, expires_at, \
      authenticator_origin_binding_digest) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             NOW() + make_interval(secs => $17), $18)";
const LOCAL_SESSION_INSERT_SQL: &str = "INSERT INTO sessions \
     (session_record_id, session_bearer_verifier_v3, principal_id, \
      principal_lifecycle_version, principal_authority_version, principal_key_id, \
      principal_key_version, principal_link_id, principal_link_version, \
      display_name, roles, site_authority_mode, site_scope, \
      environment_authority_mode, environment_scope, expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
             NOW() + make_interval(secs => $16)) \
     RETURNING expires_at";

#[derive(Debug, Clone, sqlx::FromRow)]
struct AuthenticatorAuthorityGenerationRow {
    authenticator_origin_binding_digest: Vec<u8>,
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    provider_id: String,
    provider_configuration_version: i64,
    provider_configuration_payload_digest: Vec<u8>,
    provider_lifecycle_record_version: i64,
    provider_lifecycle_state: String,
    binding_document_id: String,
    binding_document_version: i64,
    binding_document_digest: Vec<u8>,
    binding_document_locator: String,
    provider_policy_binding_digest: Vec<u8>,
    runtime_binding_digest: Vec<u8>,
    path_id: String,
    path_version: i64,
    path_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatorRuntimeReconciliation {
    pub provider_id: String,
    pub bearer_origin_binding_digest: [u8; 32],
    pub browser_origin_binding_digest: Option<[u8; 32]>,
    pub stale_login_states_deleted: u64,
    pub stale_federated_sessions_deleted: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DisabledAuthenticatorRuntimesReconciliation {
    pub providers_disabled: u64,
    pub stale_login_states_deleted: u64,
    pub stale_federated_sessions_deleted: u64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct AuthenticatorAuthorityCurrentPathRow {
    path_kind: String,
    path_status: String,
    current_origin_binding_digest: Option<Vec<u8>>,
    provider_epoch_origin_binding_digest: Vec<u8>,
    provider_epoch_path_kind: String,
}

fn cache_binding(
    authority: &crate::human_authority::EffectiveHumanAuthority,
) -> crate::session_lookup_admission::SessionAuthorityCacheBinding {
    let binding = authority.principal_binding;
    crate::session_lookup_admission::SessionAuthorityCacheBinding {
        principal_id: binding.principal_id,
        principal_lifecycle_version: binding.principal_lifecycle_version,
        principal_authority_version: binding.principal_authority_version,
        principal_key_id: binding.principal_key_id,
        principal_key_version: binding.principal_key_version,
        principal_link_id: binding.principal_link_id,
        principal_link_version: binding.principal_link_version,
    }
}

#[derive(Debug, Clone)]
pub struct CreatedHumanSession {
    pub principal_id: ryuki_core::PrincipalId,
    pub expires_at: DateTime<Utc>,
    pub roles: Vec<String>,
}

pub(crate) struct AdmittedFederatedBearer {
    pub session: ryuki_engine::auth::AuthSession,
    pub authority: crate::human_authority::InteractiveHumanAuthorityContext,
    pub authenticator_origin:
        Arc<crate::authenticator_runtime::VerifiedDirectBearerAuthenticatorOrigin>,
    pub identity_authority_digest: [u8; 32],
    pub identity_last_asserted_at: DateTime<Utc>,
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
    #[error("interactive human authority was rejected")]
    HumanAuthority(#[from] crate::human_authority::HumanAuthorityError),
    #[error("opaque principal binding was rejected")]
    PrincipalRegistry(#[from] crate::principal_registry::PrincipalRegistryError),
    #[error("verified authenticator origin was rejected: {0}")]
    AuthenticatorOrigin(&'static str),
}

struct VerifiedAuthenticatorAuthorityGeneration<'a> {
    origin_binding_digest: &'a [u8; 32],
    projection: &'a ryuki_core::security_profile::AuthenticatorOriginProjection,
    provider_configuration_payload_digest: [u8; 32],
    binding_document_digest: [u8; 32],
    provider_policy_binding_digest: [u8; 32],
    runtime_binding_digest: [u8; 32],
    provider_configuration_version: i64,
    provider_lifecycle_record_version: i64,
    binding_document_version: i64,
    path_version: i64,
    path_kind: &'static str,
}

struct VerifiedAuthenticatorAuthorityParts<'a> {
    projection: &'a ryuki_core::security_profile::AuthenticatorOriginProjection,
    encoded_origin_binding_digest: &'a str,
    origin_binding_digest: &'a [u8; 32],
    provider_id: &'a str,
    path_id: &'a str,
    path_version: u64,
    actual_path_kind: &'a str,
    expected_path_kind: &'static str,
}

fn decode_sha256_digest(value: &str) -> Result<[u8; 32], IdentityAuthorityError> {
    let encoded =
        value
            .strip_prefix("sha256:")
            .ok_or(IdentityAuthorityError::AuthenticatorOrigin(
                "non-canonical digest encoding",
            ))?;
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut digest).map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin("non-canonical digest encoding")
    })?;
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        || digest.iter().all(|byte| *byte == 0)
    {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "non-canonical digest encoding",
        ));
    }
    Ok(digest)
}

fn checked_generation_version(version: u64) -> Result<i64, IdentityAuthorityError> {
    i64::try_from(version).map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin("generation version exceeds database range")
    })
}

fn digest_matches(actual: &[u8], expected: &[u8; 32]) -> bool {
    actual.len() == expected.len() && bool::from(actual.ct_eq(expected.as_slice()))
}

impl<'a> VerifiedAuthenticatorAuthorityGeneration<'a> {
    fn from_verified_parts(
        parts: VerifiedAuthenticatorAuthorityParts<'a>,
    ) -> Result<Self, IdentityAuthorityError> {
        let VerifiedAuthenticatorAuthorityParts {
            projection,
            encoded_origin_binding_digest,
            origin_binding_digest,
            provider_id,
            path_id,
            path_version,
            actual_path_kind,
            expected_path_kind,
        } = parts;
        let encoded_origin_digest = decode_sha256_digest(encoded_origin_binding_digest)?;
        if !digest_matches(encoded_origin_digest.as_slice(), origin_binding_digest)
            || projection.provider_id.as_str() != provider_id
            || projection.path_id.as_str() != path_id
            || projection.path_version != path_version
            || actual_path_kind != expected_path_kind
        {
            return Err(IdentityAuthorityError::AuthenticatorOrigin(
                "sealed origin accessor reconciliation",
            ));
        }

        Ok(Self {
            origin_binding_digest,
            provider_configuration_payload_digest: decode_sha256_digest(
                &projection.provider_configuration_payload_digest,
            )?,
            binding_document_digest: decode_sha256_digest(
                &projection.binding_document_reference.content_digest,
            )?,
            provider_policy_binding_digest: decode_sha256_digest(
                &projection.provider_policy_binding_digest,
            )?,
            runtime_binding_digest: decode_sha256_digest(&projection.runtime_binding_digest)?,
            provider_configuration_version: checked_generation_version(
                projection.provider_configuration_version,
            )?,
            provider_lifecycle_record_version: checked_generation_version(
                projection.provider_lifecycle_record_version,
            )?,
            binding_document_version: checked_generation_version(
                projection.binding_document_reference.document_version,
            )?,
            path_version: checked_generation_version(projection.path_version)?,
            projection,
            path_kind: expected_path_kind,
        })
    }

    fn from_browser_origin(
        origin: &'a Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
    ) -> Result<Self, IdentityAuthorityError> {
        origin
            .verify_integrity()
            .map_err(|_| IdentityAuthorityError::AuthenticatorOrigin("sealed origin integrity"))?;
        Self::from_verified_parts(VerifiedAuthenticatorAuthorityParts {
            projection: origin.origin_projection(),
            encoded_origin_binding_digest: origin.origin_binding_digest(),
            origin_binding_digest: origin.origin_binding_digest_bytes(),
            provider_id: origin.provider_id(),
            path_id: origin.path_id(),
            path_version: origin.path_version(),
            actual_path_kind: origin.path_kind(),
            expected_path_kind: BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND,
        })
    }

    fn from_direct_bearer_origin(
        origin: &'a Arc<crate::authenticator_runtime::VerifiedDirectBearerAuthenticatorOrigin>,
    ) -> Result<Self, IdentityAuthorityError> {
        origin
            .verify_integrity()
            .map_err(|_| IdentityAuthorityError::AuthenticatorOrigin("sealed origin integrity"))?;
        let provider_binding = origin.provider_binding();
        let projection = origin.origin_projection();
        if provider_binding.provider_id.as_str() != origin.provider_id()
            || provider_binding.provider_id.as_str() != projection.provider_id.as_str()
            || provider_binding.configuration_version != projection.provider_configuration_version
            || provider_binding.configuration_payload_digest.as_str()
                != projection.provider_configuration_payload_digest.as_str()
            || provider_binding.lifecycle_record_version
                != projection.provider_lifecycle_record_version
            || provider_binding.lifecycle_state != projection.provider_lifecycle_state
        {
            return Err(IdentityAuthorityError::AuthenticatorOrigin(
                "sealed origin provider-binding reconciliation",
            ));
        }
        Self::from_verified_parts(VerifiedAuthenticatorAuthorityParts {
            projection: origin.origin_projection(),
            encoded_origin_binding_digest: origin.origin_binding_digest(),
            origin_binding_digest: origin.origin_binding_digest_bytes(),
            provider_id: origin.provider_id(),
            path_id: origin.path_id(),
            path_version: origin.path_version(),
            actual_path_kind: origin.path_kind(),
            expected_path_kind: DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
        })
    }

    fn matches_row(&self, row: &AuthenticatorAuthorityGenerationRow) -> bool {
        digest_matches(
            &row.authenticator_origin_binding_digest,
            self.origin_binding_digest,
        ) && row.deployment_id == self.projection.deployment_id
            && row.trust_domain_id == self.projection.trust_domain_id
            && row.tenant_id == self.projection.tenant_id
            && row.provider_id == self.projection.provider_id
            && row.provider_configuration_version == self.provider_configuration_version
            && digest_matches(
                &row.provider_configuration_payload_digest,
                &self.provider_configuration_payload_digest,
            )
            && row.provider_lifecycle_record_version == self.provider_lifecycle_record_version
            && row.provider_lifecycle_state == "active"
            && row.binding_document_id == self.projection.binding_document_reference.document_id
            && row.binding_document_version == self.binding_document_version
            && digest_matches(&row.binding_document_digest, &self.binding_document_digest)
            && row.binding_document_locator
                == self.projection.binding_document_reference.artifact_locator
            && digest_matches(
                &row.provider_policy_binding_digest,
                &self.provider_policy_binding_digest,
            )
            && digest_matches(&row.runtime_binding_digest, &self.runtime_binding_digest)
            && row.path_id == self.projection.path_id
            && row.path_version == self.path_version
            && row.path_kind == self.path_kind
    }
}

/// Register one exact, append-only browser-authenticator origin and prove that
/// the row read back under its canonical digest contains the complete sealed
/// D/P/Q/R preimage. `recorded_at` is intentionally excluded: it is
/// database-owned insertion metadata, never evidence that an origin is current.
async fn register_verified_authenticator_authority_generation_tx(
    tx: &mut Transaction<'_, Postgres>,
    generation: &VerifiedAuthenticatorAuthorityGeneration<'_>,
) -> Result<(), IdentityAuthorityError> {
    let projection = generation.projection;
    sqlx::query(AUTHENTICATOR_AUTHORITY_GENERATION_INSERT_SQL)
        .bind(generation.origin_binding_digest.as_slice())
        .bind(&projection.deployment_id)
        .bind(&projection.trust_domain_id)
        .bind(projection.tenant_id.as_deref())
        .bind(&projection.provider_id)
        .bind(generation.provider_configuration_version)
        .bind(generation.provider_configuration_payload_digest.as_slice())
        .bind(generation.provider_lifecycle_record_version)
        .bind("active")
        .bind(&projection.binding_document_reference.document_id)
        .bind(generation.binding_document_version)
        .bind(generation.binding_document_digest.as_slice())
        .bind(&projection.binding_document_reference.artifact_locator)
        .bind(generation.provider_policy_binding_digest.as_slice())
        .bind(generation.runtime_binding_digest.as_slice())
        .bind(&projection.path_id)
        .bind(generation.path_version)
        .bind(generation.path_kind)
        .execute(&mut **tx)
        .await?;

    let row = sqlx::query_as::<_, AuthenticatorAuthorityGenerationRow>(
        AUTHENTICATOR_AUTHORITY_GENERATION_SELECT_SQL,
    )
    .bind(generation.origin_binding_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(IdentityAuthorityError::AuthenticatorOrigin(
        "canonical origin row is absent after registration",
    ))?;
    if !generation.matches_row(&row) {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "canonical origin row differs from the sealed preimage",
        ));
    }
    Ok(())
}

async fn set_principal_bearer_origin_contract_tx(
    tx: &mut Transaction<'_, Postgres>,
    bearer_origin_binding_digest: &[u8; 32],
) -> Result<(), IdentityAuthorityError> {
    sqlx::query("SELECT set_config($1, $2, TRUE)")
        .bind(PRINCIPAL_BEARER_ORIGIN_CONTRACT_SETTING)
        .bind(hex::encode(bearer_origin_binding_digest))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
async fn set_test_current_bearer_origin_contract_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider_id: &str,
) -> Result<[u8; 32], IdentityAuthorityError> {
    let bearer_digest = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT current_origin_binding_digest \
         FROM authenticator_authority_current_paths \
         WHERE provider_id = $1 \
           AND path_kind = 'bearer' \
           AND path_status = 'active' \
           AND current_origin_binding_digest = provider_epoch_origin_binding_digest \
           AND provider_epoch_path_kind = 'bearer' \
         FOR SHARE",
    )
    .bind(provider_id)
    .fetch_one(&mut **tx)
    .await?;
    let bearer_digest: [u8; 32] = bearer_digest.try_into().map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin(
            "test current bearer origin has a non-canonical digest",
        )
    })?;
    set_principal_bearer_origin_contract_tx(tx, &bearer_digest).await?;
    Ok(bearer_digest)
}

/// Hold the exact active direct-bearer pointer while a principal assertion is
/// reconciled. This is assertion-only: request traffic can neither append a
/// generation nor advance the durable current-path pointer.
async fn assert_current_direct_bearer_origin_tx(
    tx: &mut Transaction<'_, Postgres>,
    generation: &VerifiedAuthenticatorAuthorityGeneration<'_>,
) -> Result<(), IdentityAuthorityError> {
    if generation.path_kind != DIRECT_BEARER_AUTHENTICATOR_PATH_KIND {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "direct-bearer currentness received the wrong path kind",
        ));
    }
    let current_digest = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT current_origin_binding_digest \
         FROM authenticator_authority_current_paths \
         WHERE provider_id = $1 \
           AND path_kind = 'bearer' \
           AND path_status = 'active' \
           AND current_origin_binding_digest = $2 \
           AND provider_epoch_origin_binding_digest = $2 \
           AND provider_epoch_path_kind = 'bearer' \
         FOR SHARE",
    )
    .bind(&generation.projection.provider_id)
    .bind(generation.origin_binding_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(IdentityAuthorityError::AssertionRejected)?;
    if !digest_matches(&current_digest, generation.origin_binding_digest) {
        return Err(IdentityAuthorityError::AssertionRejected);
    }
    set_principal_bearer_origin_contract_tx(tx, generation.origin_binding_digest).await
}

/// Hold the exact active browser pointer and its matching bearer epoch anchor
/// while a federated session is minted. The returned bearer digest is used
/// only for the principal-writer fence; the session copies the browser digest.
async fn assert_current_browser_authenticator_origin_tx(
    tx: &mut Transaction<'_, Postgres>,
    generation: &VerifiedAuthenticatorAuthorityGeneration<'_>,
) -> Result<(), IdentityAuthorityError> {
    if generation.path_kind != BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "browser currentness received the wrong path kind",
        ));
    }
    let bearer_digest = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT bearer.current_origin_binding_digest \
         FROM authenticator_authority_current_paths AS browser \
         JOIN authenticator_authority_current_paths AS bearer \
           ON bearer.provider_id = browser.provider_id \
          AND bearer.path_kind = 'bearer' \
          AND bearer.path_status = 'active' \
          AND bearer.current_origin_binding_digest = \
              browser.provider_epoch_origin_binding_digest \
          AND bearer.provider_epoch_origin_binding_digest = \
              bearer.current_origin_binding_digest \
          AND bearer.provider_epoch_path_kind = 'bearer' \
         WHERE browser.provider_id = $1 \
           AND browser.path_kind = 'browser-derived-session' \
           AND browser.path_status = 'active' \
           AND browser.current_origin_binding_digest = $2 \
           AND browser.provider_epoch_path_kind = 'bearer' \
         FOR SHARE OF browser, bearer",
    )
    .bind(&generation.projection.provider_id)
    .bind(generation.origin_binding_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(IdentityAuthorityError::AssertionRejected)?;
    let bearer_digest: [u8; 32] = bearer_digest.try_into().map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin(
            "current bearer epoch anchor has a non-canonical digest",
        )
    })?;
    set_principal_bearer_origin_contract_tx(tx, &bearer_digest).await
}

async fn set_login_state_writer_contract_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), IdentityAuthorityError> {
    sqlx::query("SELECT set_config('ryuki.oidc_login_state_contract', '3', TRUE)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn delete_browser_login_states_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider_id: &str,
    retained_origin_binding_digest: Option<&[u8; 32]>,
) -> Result<u64, IdentityAuthorityError> {
    let retained_origin = retained_origin_binding_digest.map(|digest| digest.as_slice());
    let mut deleted_total = 0_u64;
    for _ in 0..AUTHENTICATOR_ORIGIN_ROLLOVER_MAX_DELETE_BATCHES {
        let deleted = sqlx::query(
            "WITH stale AS ( \
                 SELECT login_state.state \
                 FROM oidc_login_states_v3 AS login_state \
                 JOIN authenticator_authority_generations AS registered_origin \
                   ON registered_origin.authenticator_origin_binding_digest = \
                      login_state.authenticator_origin_binding_digest \
                 WHERE registered_origin.provider_id = $1 \
                   AND ($2::BYTEA IS NULL OR \
                        login_state.authenticator_origin_binding_digest <> $2) \
                 ORDER BY login_state.created_at, login_state.state \
                 FOR UPDATE OF login_state \
                 LIMIT $3 \
             ) \
             DELETE FROM oidc_login_states_v3 AS login_state \
             USING stale \
             WHERE login_state.state = stale.state",
        )
        .bind(provider_id)
        .bind(retained_origin)
        .bind(AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        deleted_total = deleted_total.saturating_add(deleted);
        if deleted < AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH as u64 {
            return Ok(deleted_total);
        }
    }

    let deletion_incomplete: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 \
             FROM oidc_login_states_v3 AS login_state \
             JOIN authenticator_authority_generations AS registered_origin \
               ON registered_origin.authenticator_origin_binding_digest = \
                  login_state.authenticator_origin_binding_digest \
             WHERE registered_origin.provider_id = $1 \
               AND ($2::BYTEA IS NULL OR \
                    login_state.authenticator_origin_binding_digest <> $2) \
         )",
    )
    .bind(provider_id)
    .bind(retained_origin)
    .fetch_one(&mut **tx)
    .await?;
    if deletion_incomplete {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "browser login-state reconciliation exceeded its hard deletion ceiling",
        ));
    }
    Ok(deleted_total)
}

async fn delete_federated_sessions_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider_id: &str,
    retained_origin_binding_digest: Option<&[u8; 32]>,
) -> Result<u64, IdentityAuthorityError> {
    let retained_origin = retained_origin_binding_digest.map(|digest| digest.as_slice());
    let mut deleted_total = 0_u64;
    for _ in 0..AUTHENTICATOR_ORIGIN_ROLLOVER_MAX_DELETE_BATCHES {
        let deleted = sqlx::query(
            "WITH stale AS ( \
                 SELECT session_row.session_record_id \
                 FROM sessions AS session_row \
                 JOIN authenticator_authority_generations AS registered_origin \
                   ON registered_origin.authenticator_origin_binding_digest = \
                      session_row.authenticator_origin_binding_digest \
                 WHERE registered_origin.provider_id = $1 \
                   AND ($2::BYTEA IS NULL OR \
                        session_row.authenticator_origin_binding_digest IS DISTINCT FROM $2) \
                 ORDER BY session_row.expires_at, session_row.session_record_id \
                 FOR UPDATE OF session_row \
                 LIMIT $3 \
             ) \
             DELETE FROM sessions AS session_row \
             USING stale \
             WHERE session_row.session_record_id = stale.session_record_id",
        )
        .bind(provider_id)
        .bind(retained_origin)
        .bind(AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        deleted_total = deleted_total.saturating_add(deleted);
        if deleted < AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH as u64 {
            return Ok(deleted_total);
        }
    }

    let deletion_incomplete: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 \
             FROM sessions AS session_row \
             JOIN authenticator_authority_generations AS registered_origin \
               ON registered_origin.authenticator_origin_binding_digest = \
                  session_row.authenticator_origin_binding_digest \
             WHERE registered_origin.provider_id = $1 \
               AND ($2::BYTEA IS NULL OR \
                    session_row.authenticator_origin_binding_digest IS DISTINCT FROM $2) \
         )",
    )
    .bind(provider_id)
    .bind(retained_origin)
    .fetch_one(&mut **tx)
    .await?;
    if deletion_incomplete {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "federated-session reconciliation exceeded its hard deletion ceiling",
        ));
    }
    Ok(deleted_total)
}

async fn delete_all_browser_login_states_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<u64, IdentityAuthorityError> {
    let mut deleted_total = 0_u64;
    for _ in 0..AUTHENTICATOR_ORIGIN_ROLLOVER_MAX_DELETE_BATCHES {
        let deleted = sqlx::query(
            "WITH stale AS ( \
                 SELECT state \
                 FROM oidc_login_states_v3 \
                 ORDER BY created_at, state \
                 FOR UPDATE \
                 LIMIT $1 \
             ) \
             DELETE FROM oidc_login_states_v3 AS login_state \
             USING stale \
             WHERE login_state.state = stale.state",
        )
        .bind(AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        deleted_total = deleted_total.saturating_add(deleted);
        if deleted < AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH as u64 {
            return Ok(deleted_total);
        }
    }
    let deletion_incomplete: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oidc_login_states_v3)")
            .fetch_one(&mut **tx)
            .await?;
    if deletion_incomplete {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "global browser login-state disable exceeded its hard deletion ceiling",
        ));
    }
    Ok(deleted_total)
}

async fn delete_all_federated_sessions_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<u64, IdentityAuthorityError> {
    let mut deleted_total = 0_u64;
    for _ in 0..AUTHENTICATOR_ORIGIN_ROLLOVER_MAX_DELETE_BATCHES {
        let deleted = sqlx::query(
            "WITH stale AS ( \
                 SELECT session_record_id \
                 FROM sessions \
                 WHERE authenticator_origin_binding_digest IS NOT NULL \
                 ORDER BY expires_at, session_record_id \
                 FOR UPDATE \
                 LIMIT $1 \
             ) \
             DELETE FROM sessions AS session_row \
             USING stale \
             WHERE session_row.session_record_id = stale.session_record_id",
        )
        .bind(AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        deleted_total = deleted_total.saturating_add(deleted);
        if deleted < AUTHENTICATOR_ORIGIN_ROLLOVER_DELETE_BATCH as u64 {
            return Ok(deleted_total);
        }
    }
    let deletion_incomplete: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM sessions \
             WHERE authenticator_origin_binding_digest IS NOT NULL \
         )",
    )
    .fetch_one(&mut **tx)
    .await?;
    if deletion_incomplete {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "global federated-session disable exceeded its hard deletion ceiling",
        ));
    }
    Ok(deleted_total)
}

fn current_path_row_matches(
    row: &AuthenticatorAuthorityCurrentPathRow,
    expected_path_kind: &str,
    expected_status: &str,
    expected_current_digest: Option<&[u8; 32]>,
    expected_bearer_epoch_digest: &[u8; 32],
) -> bool {
    row.path_kind == expected_path_kind
        && row.path_status == expected_status
        && row.provider_epoch_path_kind == DIRECT_BEARER_AUTHENTICATOR_PATH_KIND
        && digest_matches(
            &row.provider_epoch_origin_binding_digest,
            expected_bearer_epoch_digest,
        )
        && match (
            row.current_origin_binding_digest.as_deref(),
            expected_current_digest,
        ) {
            (Some(actual), Some(expected)) => digest_matches(actual, expected),
            (None, None) => true,
            _ => false,
        }
}

async fn reconcile_authenticator_generations(
    pool: &PgPool,
    bearer_generation: &VerifiedAuthenticatorAuthorityGeneration<'_>,
    browser_generation: Option<&VerifiedAuthenticatorAuthorityGeneration<'_>>,
) -> Result<AuthenticatorRuntimeReconciliation, IdentityAuthorityError> {
    let provider_id = bearer_generation.projection.provider_id.clone();
    let bearer_origin_binding_digest = *bearer_generation.origin_binding_digest;
    let browser_origin_binding_digest =
        browser_generation.map(|generation| *generation.origin_binding_digest);
    let mut tx = pool.begin().await?;
    register_verified_authenticator_authority_generation_tx(&mut tx, bearer_generation).await?;
    if let Some(browser_generation) = browser_generation {
        register_verified_authenticator_authority_generation_tx(&mut tx, browser_generation)
            .await?;
    }

    let reconciled_provider = sqlx::query_scalar::<_, String>(
        "SELECT public.reconcile_authenticator_authority_current_paths_v3($1, $2)",
    )
    .bind(bearer_origin_binding_digest.as_slice())
    .bind(
        browser_origin_binding_digest
            .as_ref()
            .map(|digest| digest.as_slice()),
    )
    .fetch_one(&mut *tx)
    .await?;
    if reconciled_provider != provider_id {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "current-path reconciliation returned a different provider",
        ));
    }
    let (runtime_mode, minimum_provider_configuration_version) =
        sqlx::query_as::<_, (String, Option<i64>)>(
            "SELECT mode_status, minimum_provider_configuration_version \
             FROM authenticator_authority_runtime_mode \
             WHERE singleton \
             FOR SHARE",
        )
        .fetch_one(&mut *tx)
        .await?;
    if runtime_mode != "enabled"
        || minimum_provider_configuration_version.is_none_or(|floor| {
            floor < 1 || bearer_generation.provider_configuration_version < floor
        })
    {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "active authenticator reconciliation did not enable the durable mode fence",
        ));
    }

    set_login_state_writer_contract_tx(&mut tx).await?;
    let stale_login_states_deleted = delete_browser_login_states_tx(
        &mut tx,
        &provider_id,
        browser_origin_binding_digest.as_ref(),
    )
    .await?;
    let stale_federated_sessions_deleted = delete_federated_sessions_tx(
        &mut tx,
        &provider_id,
        browser_origin_binding_digest.as_ref(),
    )
    .await?;

    let current_rows = sqlx::query_as::<_, AuthenticatorAuthorityCurrentPathRow>(
        "SELECT path_kind, path_status, current_origin_binding_digest, \
                provider_epoch_origin_binding_digest, provider_epoch_path_kind \
         FROM authenticator_authority_current_paths \
         WHERE provider_id = $1 \
         ORDER BY path_kind \
         FOR SHARE",
    )
    .bind(&provider_id)
    .fetch_all(&mut *tx)
    .await?;
    let bearer_row = current_rows
        .iter()
        .find(|row| row.path_kind == DIRECT_BEARER_AUTHENTICATOR_PATH_KIND);
    let browser_row = current_rows
        .iter()
        .find(|row| row.path_kind == BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND);
    let browser_status = if browser_origin_binding_digest.is_some() {
        AUTHENTICATOR_PATH_STATUS_ACTIVE
    } else {
        AUTHENTICATOR_PATH_STATUS_DISABLED
    };
    if current_rows.len() != 2
        || !bearer_row.is_some_and(|row| {
            current_path_row_matches(
                row,
                DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
                AUTHENTICATOR_PATH_STATUS_ACTIVE,
                Some(&bearer_origin_binding_digest),
                &bearer_origin_binding_digest,
            )
        })
        || !browser_row.is_some_and(|row| {
            current_path_row_matches(
                row,
                BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND,
                browser_status,
                browser_origin_binding_digest.as_ref(),
                &bearer_origin_binding_digest,
            )
        })
    {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "current-path readback differs from the sealed runtime",
        ));
    }

    tx.commit().await?;
    crate::session_lookup_admission::clear_positive_global();
    Ok(AuthenticatorRuntimeReconciliation {
        provider_id,
        bearer_origin_binding_digest,
        browser_origin_binding_digest,
        stale_login_states_deleted,
        stale_federated_sessions_deleted,
    })
}

/// Atomically publish both credential paths for one exact sealed live Entra R.
///
/// Provider configuration version is the primary epoch in the database
/// transition function. A lower epoch is rejected; an equal epoch is accepted
/// only as byte-for-byte idempotency; a higher epoch advances bearer and
/// browser (or the explicit disabled-browser marker) together. Request paths
/// never invoke this API.
pub(crate) async fn reconcile_current_authenticator_runtime(
    pool: &PgPool,
    runtime_binding: &Arc<crate::authenticator_runtime::VerifiedEntraAuthenticatorRuntimeBinding>,
) -> Result<AuthenticatorRuntimeReconciliation, IdentityAuthorityError> {
    runtime_binding.verify_integrity().map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin("sealed Entra runtime integrity")
    })?;
    let bearer_origin = runtime_binding
        .direct_bearer_origin()
        .map_err(|_| IdentityAuthorityError::AuthenticatorOrigin("sealed direct-bearer origin"))?;
    let browser_origin = runtime_binding
        .browser_origin()
        .map_err(|_| IdentityAuthorityError::AuthenticatorOrigin("sealed browser origin"))?;
    let bearer_generation =
        VerifiedAuthenticatorAuthorityGeneration::from_direct_bearer_origin(&bearer_origin)?;
    let browser_generation = browser_origin
        .as_ref()
        .map(VerifiedAuthenticatorAuthorityGeneration::from_browser_origin)
        .transpose()?;
    let provider_id = bearer_generation.projection.provider_id.clone();

    if browser_origin.as_ref().is_some_and(|origin| {
        !origin.retains_entra_runtime_binding(runtime_binding)
            || origin.provider_id() != provider_id
    }) || browser_generation.as_ref().is_some_and(|generation| {
        generation.projection.runtime_binding_digest
            != bearer_generation.projection.runtime_binding_digest
            || generation.projection.provider_configuration_version
                != bearer_generation.projection.provider_configuration_version
    }) {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "bearer and browser origins do not come from the same sealed runtime epoch",
        ));
    }
    reconcile_authenticator_generations(pool, &bearer_generation, browser_generation.as_ref()).await
}

/// Persist the global non-federated mode fence and disable every previously
/// current authenticator path before a Local/disabled process can serve.
/// Pointer changes and bounded physical credential purge share one
/// transaction; any ceiling or readback failure rolls the durable disable back.
pub(crate) async fn disable_current_authenticator_runtimes(
    pool: &PgPool,
) -> Result<DisabledAuthenticatorRuntimesReconciliation, IdentityAuthorityError> {
    let mut tx = pool.begin().await?;
    let providers_disabled: i64 =
        sqlx::query_scalar("SELECT public.disable_all_authenticator_authority_current_paths_v3()")
            .fetch_one(&mut *tx)
            .await?;
    let providers_disabled = u64::try_from(providers_disabled).map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin(
            "global authenticator disable returned an invalid provider count",
        )
    })?;
    let (runtime_mode, minimum_provider_configuration_version) =
        sqlx::query_as::<_, (String, Option<i64>)>(
            "SELECT mode_status, minimum_provider_configuration_version \
             FROM authenticator_authority_runtime_mode \
             WHERE singleton \
             FOR SHARE",
        )
        .fetch_one(&mut *tx)
        .await?;
    if runtime_mode != "disabled"
        || minimum_provider_configuration_version.is_some_and(|floor| floor < 1)
    {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "global authenticator disable did not persist the durable mode fence",
        ));
    }

    set_login_state_writer_contract_tx(&mut tx).await?;
    let stale_login_states_deleted = delete_all_browser_login_states_tx(&mut tx).await?;
    let stale_federated_sessions_deleted = delete_all_federated_sessions_tx(&mut tx).await?;

    let (provider_count, total_path_count, exact_disabled_path_count) =
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT COUNT(DISTINCT provider_id), COUNT(*), \
                    COUNT(*) FILTER ( \
                        WHERE path_status = 'disabled' \
                          AND current_origin_binding_digest IS NULL \
                          AND provider_epoch_path_kind = 'bearer' \
                          AND octet_length(provider_epoch_origin_binding_digest) = 32 \
                    ) \
             FROM authenticator_authority_current_paths",
        )
        .fetch_one(&mut *tx)
        .await?;
    let provider_count = u64::try_from(provider_count).map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin(
            "global authenticator disable read back an invalid provider count",
        )
    })?;
    let expected_path_count =
        provider_count
            .checked_mul(2)
            .ok_or(IdentityAuthorityError::AuthenticatorOrigin(
                "global authenticator disable path count overflowed",
            ))?;
    if provider_count != providers_disabled
        || u64::try_from(total_path_count).ok() != Some(expected_path_count)
        || u64::try_from(exact_disabled_path_count).ok() != Some(expected_path_count)
    {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "global authenticator disable readback is incomplete",
        ));
    }

    tx.commit().await?;
    crate::session_lookup_admission::clear_positive_global();
    Ok(DisabledAuthenticatorRuntimesReconciliation {
        providers_disabled,
        stale_login_states_deleted,
        stale_federated_sessions_deleted,
    })
}

/// Seed a coherent current bearer/browser pair for protocol integration tests
/// that intentionally use the opaque synthetic browser-origin fixture. This
/// helper is absent from production builds and must be called by test setup,
/// never by a login-initiation or callback handler.
#[cfg(test)]
pub(crate) async fn reconcile_test_authenticator_runtime(
    pool: &PgPool,
    browser_origin: &Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
) -> Result<[u8; 32], IdentityAuthorityError> {
    let browser_generation =
        VerifiedAuthenticatorAuthorityGeneration::from_browser_origin(browser_origin)?;
    let mut bearer_projection = browser_generation.projection.clone();
    let provider_suffix = bearer_projection
        .provider_id
        .strip_prefix("provider:")
        .ok_or(IdentityAuthorityError::AuthenticatorOrigin(
            "synthetic provider is not canonical",
        ))?
        .to_owned();
    bearer_projection.path_id = format!("authenticator-path:{provider_suffix}-bearer");
    let bearer_origin_binding_digest =
        ryuki_core::security_profile::authenticator_origin_binding_digest(&bearer_projection)
            .map_err(|_| {
                IdentityAuthorityError::AuthenticatorOrigin(
                    "synthetic direct-bearer origin projection is invalid",
                )
            })?;
    let bearer_origin_binding_digest_bytes = decode_sha256_digest(&bearer_origin_binding_digest)?;
    let bearer_generation = VerifiedAuthenticatorAuthorityGeneration::from_verified_parts(
        VerifiedAuthenticatorAuthorityParts {
            projection: &bearer_projection,
            encoded_origin_binding_digest: &bearer_origin_binding_digest,
            origin_binding_digest: &bearer_origin_binding_digest_bytes,
            provider_id: &bearer_projection.provider_id,
            path_id: &bearer_projection.path_id,
            path_version: bearer_projection.path_version,
            actual_path_kind: DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
            expected_path_kind: DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
        },
    )?;

    let reconciliation =
        reconcile_authenticator_generations(pool, &bearer_generation, Some(&browser_generation))
            .await?;
    if reconciliation.bearer_origin_binding_digest != bearer_origin_binding_digest_bytes
        || reconciliation.browser_origin_binding_digest
            != Some(*browser_generation.origin_binding_digest)
    {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "synthetic current-path readback differs from the paired fixture",
        ));
    }
    Ok(reconciliation.bearer_origin_binding_digest)
}

#[cfg(test)]
fn test_epoch_digest(epoch_label: &str, component: &str) -> String {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(
        format!("ryuki-current-authenticator-test-epoch:{epoch_label}:{component}").as_bytes(),
    );
    format!("sha256:{}", hex::encode(digest))
}

/// Exercise database anti-rollback transitions without manufacturing a
/// production runtime witness. The projections remain one coherent paired
/// provider epoch and flow through the same append, transition, purge, and
/// readback implementation as the sealed-R startup API.
#[cfg(test)]
pub(crate) async fn reconcile_test_authenticator_epoch(
    pool: &PgPool,
    seed_browser_origin: &Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
    provider_configuration_version: u64,
    browser_enabled: bool,
    epoch_label: &str,
) -> Result<AuthenticatorRuntimeReconciliation, IdentityAuthorityError> {
    seed_browser_origin.verify_integrity().map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin("synthetic epoch seed integrity")
    })?;
    if provider_configuration_version == 0 || epoch_label.is_empty() {
        return Err(IdentityAuthorityError::AuthenticatorOrigin(
            "synthetic epoch input is invalid",
        ));
    }

    let mut browser_projection = seed_browser_origin.origin_projection().clone();
    browser_projection.provider_configuration_version = provider_configuration_version;
    browser_projection.provider_configuration_payload_digest = test_epoch_digest(epoch_label, "p");
    browser_projection.provider_lifecycle_record_version = 1;
    browser_projection
        .binding_document_reference
        .document_version = 1;
    browser_projection.binding_document_reference.content_digest =
        test_epoch_digest(epoch_label, "d");
    browser_projection.provider_policy_binding_digest = test_epoch_digest(epoch_label, "q");
    browser_projection.runtime_binding_digest = test_epoch_digest(epoch_label, "r");
    browser_projection.path_version = 1;

    let mut bearer_projection = browser_projection.clone();
    let provider_suffix = bearer_projection
        .provider_id
        .strip_prefix("provider:")
        .ok_or(IdentityAuthorityError::AuthenticatorOrigin(
            "synthetic provider is not canonical",
        ))?
        .to_owned();
    bearer_projection.path_id = format!("authenticator-path:{provider_suffix}-bearer");

    let bearer_digest =
        ryuki_core::security_profile::authenticator_origin_binding_digest(&bearer_projection)
            .map_err(|_| {
                IdentityAuthorityError::AuthenticatorOrigin(
                    "synthetic epoch bearer origin is invalid",
                )
            })?;
    let bearer_digest_bytes = decode_sha256_digest(&bearer_digest)?;
    let bearer_generation = VerifiedAuthenticatorAuthorityGeneration::from_verified_parts(
        VerifiedAuthenticatorAuthorityParts {
            projection: &bearer_projection,
            encoded_origin_binding_digest: &bearer_digest,
            origin_binding_digest: &bearer_digest_bytes,
            provider_id: &bearer_projection.provider_id,
            path_id: &bearer_projection.path_id,
            path_version: bearer_projection.path_version,
            actual_path_kind: DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
            expected_path_kind: DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
        },
    )?;

    let browser_digest =
        ryuki_core::security_profile::authenticator_origin_binding_digest(&browser_projection)
            .map_err(|_| {
                IdentityAuthorityError::AuthenticatorOrigin(
                    "synthetic epoch browser origin is invalid",
                )
            })?;
    let browser_digest_bytes = decode_sha256_digest(&browser_digest)?;
    let browser_generation = VerifiedAuthenticatorAuthorityGeneration::from_verified_parts(
        VerifiedAuthenticatorAuthorityParts {
            projection: &browser_projection,
            encoded_origin_binding_digest: &browser_digest,
            origin_binding_digest: &browser_digest_bytes,
            provider_id: &browser_projection.provider_id,
            path_id: &browser_projection.path_id,
            path_version: browser_projection.path_version,
            actual_path_kind: BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND,
            expected_path_kind: BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND,
        },
    )?;

    reconcile_authenticator_generations(
        pool,
        &bearer_generation,
        browser_enabled.then_some(&browser_generation),
    )
    .await
}

/// Provision a governed global assignment for browser protocol integration
/// tests while holding the exact current browser/bearer pointer pair. The
/// placeholder authority digest is rotated by the real verified callback
/// before any session is minted.
#[cfg(test)]
pub(crate) async fn provision_test_authenticator_assignment(
    pool: &PgPool,
    browser_origin: &Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
    issuer: &str,
    subject: &str,
    roles: &[String],
) -> Result<(), IdentityAuthorityError> {
    let generation = VerifiedAuthenticatorAuthorityGeneration::from_browser_origin(browser_origin)?;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut authority_digest = [0_u8; 32];
    authority_digest[..16].copy_from_slice(first.as_bytes());
    authority_digest[16..].copy_from_slice(second.as_bytes());

    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(
        &mut tx,
        &generation.projection.provider_id,
        issuer,
        subject,
    )
    .await?;
    assert_current_browser_authenticator_origin_tx(&mut tx, &generation).await?;
    let changed = crate::human_authority::reconcile_assignment_tx(
        &mut tx,
        &generation.projection.provider_id,
        issuer,
        subject,
        crate::human_authority::HumanAuthorityAssignmentSpec::test_global(roles),
        Some(&authority_digest),
    )
    .await?;
    tx.commit().await?;
    if changed {
        crate::session_lookup_admission::clear_positive_global();
    }
    Ok(())
}

fn validate_identity_key(
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), IdentityAuthorityError> {
    // Migration 201 preserves legacy principal-key evidence while all new
    // federated session issuance moves to the canonical provider registry
    // namespace. Accepting both key shapes here keeps tombstoning and lookup
    // available during that non-overlap cutover; the session-origin guard is
    // what prevents a legacy alias from minting new authority.
    let legacy_provider = (1..=64).contains(&provider.len())
        && provider.as_bytes().iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        });
    let canonical_scoped_provider = provider.strip_prefix("provider:").is_some_and(|suffix| {
        let bytes = suffix.as_bytes();
        (3..=127).contains(&bytes.len())
            && bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
    });
    if !legacy_provider && !canonical_scoped_provider {
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
/// opaque principals. Removed accounts are terminally tombstoned under the
/// same provider/key lock order used by session admission.
pub(crate) async fn reconcile_local_authorities<A>(
    pool: &PgPool,
    local_auth: &LocalAuthConfig,
    credential_authority: &A,
) -> Result<(), IdentityAuthorityError>
where
    A: crate::session_credentials::SessionCredentialAuthority + ?Sized,
{
    let mut assignments = Vec::with_capacity(local_auth.users.len());
    for user in local_auth.users.users() {
        validate_identity_key(LOCAL_PROVIDER, LOCAL_ISSUER, &user.username)?;
        // Validate the credential-key configuration before opening the
        // reconciliation transaction. Password material is never persisted in
        // or used to derive the opaque principal registry identifier.
        let digest = credential_authority.local_authority_digest(user)?;
        let assignment =
            crate::human_authority::HumanAuthorityAssignmentSpec::local(local_auth, &user.roles)?;
        assignments.push((user, digest, assignment));
    }

    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock( \
             hashtextextended('ryuki:local-authority-reconciliation:v2', 0) \
         )",
    )
    .execute(&mut *tx)
    .await?;
    for (user, digest, assignment) in assignments {
        crate::human_authority::reconcile_assignment_tx(
            &mut tx,
            LOCAL_PROVIDER,
            LOCAL_ISSUER,
            &user.username,
            assignment,
            Some(&digest),
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
        "SELECT subject FROM principal_keys \
         WHERE provider_id = $1 AND issuer = $2 AND key_state = 'active' \
           AND NOT (subject = ANY($3)) \
         ORDER BY subject",
    )
    .bind(LOCAL_PROVIDER)
    .bind(LOCAL_ISSUER)
    .bind(&configured_subjects)
    .fetch_all(&mut *tx)
    .await?;
    for subject in removed_subjects {
        crate::human_authority::reconcile_assignment_tx(
            &mut tx,
            LOCAL_PROVIDER,
            LOCAL_ISSUER,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "local-config",
                "local-config",
            ),
            None,
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

/// Creates a local session only against an already reconciled, current account
/// projection. The authority read and session insert share one transaction.
pub(crate) async fn create_local_session<A>(
    pool: &PgPool,
    user: &LocalAuthUser,
    session_record_id: Uuid,
    bearer_verifier: &[u8],
    max_age_secs: u64,
    credential_authority: &A,
) -> Result<CreatedHumanSession, IdentityAuthorityError>
where
    A: crate::session_credentials::SessionCredentialAuthority + ?Sized,
{
    validate_identity_key(LOCAL_PROVIDER, LOCAL_ISSUER, &user.username)?;
    if max_age_secs != credential_authority.maximum_session_age_seconds() {
        return Err(IdentityAuthorityError::InvalidInput(
            "session maximum age differs from retained credential authority",
        ));
    }
    let digest = credential_authority.local_authority_digest(user)?;
    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(
        &mut tx,
        LOCAL_PROVIDER,
        LOCAL_ISSUER,
        &user.username,
    )
    .await?;
    crate::principal_registry::reconcile_authority_digest_tx(
        &mut tx,
        LOCAL_PROVIDER,
        LOCAL_ISSUER,
        &user.username,
        &digest,
        "verified-local-login",
    )
    .await?;
    let authority = crate::human_authority::resolve_assignment_tx(
        &mut tx,
        LOCAL_PROVIDER,
        LOCAL_ISSUER,
        &user.username,
        &crate::human_authority::HumanAuthorityAssertion::role_assertion(&user.roles),
    )
    .await?;
    let principal_binding = authority.principal_binding;
    let expires_at = sqlx::query_scalar::<_, DateTime<Utc>>(LOCAL_SESSION_INSERT_SQL)
        .bind(session_record_id)
        .bind(bearer_verifier)
        .bind(principal_binding.principal_id.into_uuid())
        .bind(principal_binding.principal_lifecycle_version)
        .bind(principal_binding.principal_authority_version)
        .bind(principal_binding.principal_key_id)
        .bind(principal_binding.principal_key_version)
        .bind(principal_binding.principal_link_id)
        .bind(principal_binding.principal_link_version)
        .bind(&user.username)
        .bind(&authority.roles)
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
        principal_id: principal_binding.principal_id,
        expires_at,
        roles: authority.roles,
    })
}

pub(crate) async fn assert_federated_authority_tx<A>(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    roles: &[String],
    credential_authority: &A,
) -> Result<[u8; 32], IdentityAuthorityError>
where
    A: crate::session_credentials::SessionCredentialAuthority + ?Sized,
{
    validate_identity_key(provider, issuer, subject)?;
    if provider == LOCAL_PROVIDER {
        return Err(IdentityAuthorityError::InvalidInput(
            "local authority is configuration-owned",
        ));
    }
    let digest =
        credential_authority.federated_authority_digest(provider, issuer, subject, roles)?;
    crate::human_authority::prepare_writer_tx(tx, provider, issuer, subject).await?;
    crate::principal_registry::reconcile_authority_digest_tx(
        tx,
        provider,
        issuer,
        subject,
        &digest,
        "verified-federated-assertion",
    )
    .await?;
    Ok(digest)
}

/// Validates a federated assertion and creates a session against the exact
/// active opaque binding while holding its registry writer contract.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_federated_session<A>(
    pool: &PgPool,
    authenticator_origin: &Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
    issuer: &str,
    subject: &str,
    display_name: &str,
    email: Option<&str>,
    roles: &[String],
    session_record_id: Uuid,
    bearer_verifier: &[u8],
    max_age_secs: u64,
    credential_authority: &A,
) -> Result<(), IdentityAuthorityError>
where
    A: crate::session_credentials::SessionCredentialAuthority + ?Sized,
{
    if max_age_secs != credential_authority.maximum_session_age_seconds() {
        return Err(IdentityAuthorityError::InvalidInput(
            "session maximum age differs from retained credential authority",
        ));
    }
    let generation =
        VerifiedAuthenticatorAuthorityGeneration::from_browser_origin(authenticator_origin)?;
    let provider = generation.projection.provider_id.as_str();
    validate_identity_key(provider, issuer, subject)?;
    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(&mut tx, provider, issuer, subject).await?;
    assert_current_browser_authenticator_origin_tx(&mut tx, &generation).await?;
    assert_federated_authority_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        roles,
        credential_authority,
    )
    .await?;
    let authority = crate::human_authority::resolve_assignment_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        &crate::human_authority::HumanAuthorityAssertion::role_assertion(roles),
    )
    .await?;
    let principal_binding = authority.principal_binding;

    sqlx::query(FEDERATED_SESSION_INSERT_SQL)
        .bind(session_record_id)
        .bind(bearer_verifier)
        .bind(principal_binding.principal_id.into_uuid())
        .bind(principal_binding.principal_lifecycle_version)
        .bind(principal_binding.principal_authority_version)
        .bind(principal_binding.principal_key_id)
        .bind(principal_binding.principal_key_version)
        .bind(principal_binding.principal_link_id)
        .bind(principal_binding.principal_link_version)
        .bind(display_name)
        .bind(email)
        .bind(&authority.roles)
        .bind(authority.site_mode.as_db())
        .bind(&authority.site_scope)
        .bind(authority.environment_mode.as_db())
        .bind(&authority.environment_scope)
        .bind(max_age_secs as f64)
        .bind(generation.origin_binding_digest.as_slice())
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

/// Normalize one opaque, cryptographically verified Entra bearer through the
/// same provider-neutral identity and human-assignment transaction as browser
/// callbacks. Provider/configuration/runtime identity comes exclusively from
/// the sealed live R allocation. The signed issuer and canonical subject are
/// accepted only when they came from the exact validator retained by that R.
pub(crate) async fn admit_federated_bearer(
    pool: &PgPool,
    runtime_binding: &Arc<crate::authenticator_runtime::VerifiedEntraAuthenticatorRuntimeBinding>,
    identity: &crate::entra_auth::VerifiedEntraBearerIdentity,
) -> Result<AdmittedFederatedBearer, IdentityAuthorityError> {
    let authenticator_origin = runtime_binding
        .verify_direct_bearer_identity(identity)
        .map_err(|_| {
            IdentityAuthorityError::AuthenticatorOrigin(
                "direct-bearer identity/runtime reconciliation",
            )
        })?;
    let generation =
        VerifiedAuthenticatorAuthorityGeneration::from_direct_bearer_origin(&authenticator_origin)?;
    let provider = generation.projection.provider_id.as_str();
    let issuer = identity.issuer();
    let subject = identity.subject();
    let asserted_roles = identity.roles();
    let actor_class = identity.actor_class();
    if actor_class != ryuki_engine::auth::ActorClass::VerifiedHuman {
        return Err(IdentityAuthorityError::AssertionRejected);
    }
    let credential_authority = runtime_binding.derived_session_credentials().map_err(|_| {
        IdentityAuthorityError::AuthenticatorOrigin(
            "direct-bearer credential authority reconciliation",
        )
    })?;
    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(&mut tx, provider, issuer, subject).await?;
    assert_current_direct_bearer_origin_tx(&mut tx, &generation).await?;
    let identity_authority_digest = assert_federated_authority_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        asserted_roles,
        credential_authority.as_ref(),
    )
    .await?;
    let authority = crate::human_authority::resolve_assignment_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        &crate::human_authority::HumanAuthorityAssertion::role_assertion(asserted_roles),
    )
    .await?;
    let principal_binding = authority.principal_binding;
    let identity_last_asserted_at = Utc::now();
    let authority_context =
        crate::human_authority::InteractiveHumanAuthorityContext::from_effective(
            principal_binding,
            provider,
            issuer,
            subject,
            &authority,
        );
    tx.commit().await?;
    Ok(AdmittedFederatedBearer {
        session: ryuki_engine::auth::AuthSession {
            display_user_id: principal_binding.principal_id.to_string(),
            principal_id: Some(principal_binding.principal_id),
            display_name: identity.display_name().to_string(),
            roles: authority.roles,
            token_valid: true,
            actor_class,
            provider_mode: provider.to_string(),
            site_scope: authority.site_scope,
            environment_scope: authority.environment_scope,
        },
        authority: authority_context,
        authenticator_origin,
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

    if state == AuthorityLifecycleState::Active {
        crate::session_credentials::identity_authority_digest(
            provider, issuer, subject, roles, session,
        )?;
    }

    let mut tx = pool.begin().await?;
    crate::human_authority::prepare_writer_tx(&mut tx, provider, issuer, subject).await?;
    if provider.starts_with("provider:") {
        set_test_current_bearer_origin_contract_tx(&mut tx, provider).await?;
    }
    let outcome = match state {
        AuthorityLifecycleState::Active => {
            // Activation never manufactures a new link and can never revive a
            // tombstoned key. A governed assignment/initial verification must
            // already have established the exact active binding.
            let binding = crate::principal_registry::resolve_active_binding_tx(
                &mut tx, provider, issuer, subject,
            )
            .await?;
            AuthorityLifecycleOutcome {
                applied: false,
                authority_epoch: binding.principal_lifecycle_version,
                state,
            }
        }
        AuthorityLifecycleState::Revoked => {
            let applied = crate::principal_registry::tombstone_key_tx(
                &mut tx,
                provider,
                issuer,
                subject,
                "provider-lifecycle",
                "provider-lifecycle",
            )
            .await?;
            let key_version = sqlx::query_scalar::<_, i64>(
                "SELECT key_version FROM principal_keys \
                 WHERE provider_id = $1 AND issuer = $2 AND subject = $3",
            )
            .bind(provider)
            .bind(issuer)
            .bind(subject)
            .fetch_one(&mut *tx)
            .await?;
            AuthorityLifecycleOutcome {
                applied,
                authority_epoch: key_version,
                state,
            }
        }
    };

    tx.commit().await?;
    if outcome.applied {
        crate::session_lookup_admission::clear_positive_global();
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn identity_key_accepts_legacy_evidence_and_canonical_scoped_provider_ids() {
        for provider in [
            LOCAL_PROVIDER,
            "LOCAL",
            "local-extra",
            "oidc",
            "entra-id",
            "provider:oidc",
            "provider:entra-id",
            "provider:a.b_c-d",
            "provider:0id",
        ] {
            assert!(
                validate_identity_key(provider, "https://issuer.example", "subject").is_ok(),
                "{provider} should be a valid identity provider"
            );
        }

        let maximum_provider = format!("provider:a{}", "b".repeat(126));
        assert!(
            validate_identity_key(&maximum_provider, "https://issuer.example", "subject").is_ok()
        );
    }

    #[test]
    fn identity_key_rejects_noncanonical_provider_namespaces_and_shapes() {
        for provider in [
            "",
            "Provider:oidc",
            "deployment:oidc",
            "provider:",
            "provider:a",
            "provider:ab",
            "provider:-oidc",
            "provider:OIDC",
            "provider:oidc tenant",
            "provider:oidc/tenant",
            "provider::oidc",
            "provider:oidc:",
        ] {
            assert!(
                matches!(
                    validate_identity_key(provider, "https://issuer.example", "subject"),
                    Err(IdentityAuthorityError::InvalidInput("provider"))
                ),
                "{provider:?} should be rejected"
            );
        }

        let oversized_provider = format!("provider:a{}", "b".repeat(127));
        assert!(matches!(
            validate_identity_key(&oversized_provider, "https://issuer.example", "subject"),
            Err(IdentityAuthorityError::InvalidInput("provider"))
        ));
    }

    fn session_config() -> SessionConfig {
        SessionConfig {
            credential_hmac_key: "placeholder-session-authority-key".repeat(2),
            cookie_max_age_secs: 3_600,
            federated_authority_max_staleness_secs: 60,
            ..Default::default()
        }
    }

    fn test_direct_bearer_config() -> RyukiConfig {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            session: session_config(),
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = format!("tenant-{}", Uuid::new_v4().simple());
        config.entra_client_id = format!("client-{}", Uuid::new_v4().simple());
        config.entra_redirect_uri.clear();
        config
    }

    fn test_direct_bearer_runtime_for_config(
        config: &RyukiConfig,
    ) -> (
        Arc<crate::authenticator_runtime::VerifiedEntraAuthenticatorRuntimeBinding>,
        Arc<crate::entra_auth::EntraTokenValidator>,
    ) {
        let cookie_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(config, false)
                .expect("test config must construct cookie runtime");
        let authority = crate::security_contracts::ResolvedEntraAuthenticatorAuthority::fixture(
            config, 60, 3_600, false,
        );
        let runtime = crate::authenticator_runtime::ApiAuthenticatorRuntime::from_admitted_config(
            config,
            cookie_runtime,
            Some(authority),
            false,
        )
        .expect("test config must construct exact Entra runtime");
        (
            runtime
                .verified_entra_runtime_binding()
                .expect("Entra runtime must retain exact R"),
            runtime
                .entra_bearer_validator()
                .expect("Entra runtime must retain exact bearer validator"),
        )
    }

    fn test_direct_bearer_runtime() -> (
        Arc<crate::authenticator_runtime::VerifiedEntraAuthenticatorRuntimeBinding>,
        Arc<crate::entra_auth::EntraTokenValidator>,
    ) {
        test_direct_bearer_runtime_for_config(&test_direct_bearer_config())
    }

    #[test]
    fn direct_bearer_identity_rejects_equal_looking_substituted_runtime() {
        let config = test_direct_bearer_config();
        let (runtime, validator) = test_direct_bearer_runtime_for_config(&config);
        let (substituted_runtime, _) = test_direct_bearer_runtime_for_config(&config);
        let roles = vec!["Auditor".to_string()];
        let identity = crate::entra_auth::VerifiedEntraBearerIdentity::fixture(
            validator,
            &Uuid::new_v4().hyphenated().to_string(),
            "Direct Entra User",
            &roles,
            ryuki_engine::auth::ActorClass::VerifiedHuman,
        );

        let origin = runtime
            .verify_direct_bearer_identity(&identity)
            .expect("identity from exact retained validator must be admitted");
        assert!(origin.provider_id().starts_with("provider:"));
        assert_eq!(origin.path_kind(), DIRECT_BEARER_AUTHENTICATOR_PATH_KIND);
        assert!(origin.retains_entra_runtime_binding(&runtime));
        assert!(
            substituted_runtime
                .verify_direct_bearer_identity(&identity)
                .is_err(),
            "an equal-looking runtime with a different validator Arc must be rejected"
        );
    }

    fn test_browser_origin() -> Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>
    {
        crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(&format!(
            "o{}",
            Uuid::new_v4().simple()
        ))
    }

    fn matching_generation_row(
        origin: &Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
    ) -> AuthenticatorAuthorityGenerationRow {
        let generation = VerifiedAuthenticatorAuthorityGeneration::from_browser_origin(origin)
            .expect("test origin must carry one valid canonical generation");
        let projection = generation.projection;
        AuthenticatorAuthorityGenerationRow {
            authenticator_origin_binding_digest: generation.origin_binding_digest.to_vec(),
            deployment_id: projection.deployment_id.clone(),
            trust_domain_id: projection.trust_domain_id.clone(),
            tenant_id: projection.tenant_id.clone(),
            provider_id: projection.provider_id.clone(),
            provider_configuration_version: generation.provider_configuration_version,
            provider_configuration_payload_digest: generation
                .provider_configuration_payload_digest
                .to_vec(),
            provider_lifecycle_record_version: generation.provider_lifecycle_record_version,
            provider_lifecycle_state: "active".to_string(),
            binding_document_id: projection.binding_document_reference.document_id.clone(),
            binding_document_version: generation.binding_document_version,
            binding_document_digest: generation.binding_document_digest.to_vec(),
            binding_document_locator: projection
                .binding_document_reference
                .artifact_locator
                .clone(),
            provider_policy_binding_digest: generation.provider_policy_binding_digest.to_vec(),
            runtime_binding_digest: generation.runtime_binding_digest.to_vec(),
            path_id: projection.path_id.clone(),
            path_version: generation.path_version,
            path_kind: generation.path_kind.to_string(),
        }
    }

    #[test]
    fn origin_registration_sql_round_trips_every_authoritative_preimage_field() {
        for field in [
            "authenticator_origin_binding_digest",
            "deployment_id",
            "trust_domain_id",
            "tenant_id",
            "provider_id",
            "provider_configuration_version",
            "provider_configuration_payload_digest",
            "provider_lifecycle_record_version",
            "provider_lifecycle_state",
            "binding_document_id",
            "binding_document_version",
            "binding_document_digest",
            "binding_document_locator",
            "provider_policy_binding_digest",
            "runtime_binding_digest",
            "path_id",
            "path_version",
            "path_kind",
        ] {
            assert!(AUTHENTICATOR_AUTHORITY_GENERATION_INSERT_SQL.contains(field));
            assert!(AUTHENTICATOR_AUTHORITY_GENERATION_SELECT_SQL.contains(field));
        }
        assert!(AUTHENTICATOR_AUTHORITY_GENERATION_INSERT_SQL.contains("ON CONFLICT DO NOTHING"));
        assert!(!AUTHENTICATOR_AUTHORITY_GENERATION_INSERT_SQL.contains("recorded_at"));
        assert!(!AUTHENTICATOR_AUTHORITY_GENERATION_SELECT_SQL.contains("recorded_at"));
    }

    #[test]
    fn exact_origin_readback_rejects_wrong_and_equal_shape_substitutes() {
        let expected_origin = test_browser_origin();
        let expected =
            VerifiedAuthenticatorAuthorityGeneration::from_browser_origin(&expected_origin)
                .expect("expected origin");
        let exact_row = matching_generation_row(&expected_origin);
        assert!(expected.matches_row(&exact_row));

        let wrong_origin = test_browser_origin();
        let wrong_row = matching_generation_row(&wrong_origin);
        assert!(!expected.matches_row(&wrong_row));

        let mut equal_shape_row = exact_row;
        equal_shape_row.runtime_binding_digest[0] ^= 1;
        assert_eq!(equal_shape_row.runtime_binding_digest.len(), 32);
        assert!(!expected.matches_row(&equal_shape_row));
    }

    #[test]
    fn federated_insert_uses_only_the_canonical_origin_provider_and_digest() {
        let origin = test_browser_origin();
        assert!(origin.provider_id().starts_with("provider:"));
        assert!(
            validate_identity_key(origin.provider_id(), "https://issuer.example", "subject")
                .is_ok()
        );
        assert!(FEDERATED_SESSION_INSERT_SQL.contains("session_bearer_verifier_v3"));
        assert!(FEDERATED_SESSION_INSERT_SQL.contains("authenticator_origin_binding_digest"));
        assert!(FEDERATED_SESSION_INSERT_SQL.contains("$18"));
        assert!(!FEDERATED_SESSION_INSERT_SQL.contains("'oidc'"));
        assert!(!FEDERATED_SESSION_INSERT_SQL.contains("'entra-id'"));
    }

    #[test]
    fn local_session_insert_leaves_authenticator_origin_null_by_schema_default() {
        assert!(LOCAL_SESSION_INSERT_SQL.contains("session_bearer_verifier_v3"));
        assert!(!LOCAL_SESSION_INSERT_SQL.contains("authenticator_origin_binding_digest"));
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

    #[tokio::test]
    async fn session_creation_rejects_a_lifetime_outside_the_retained_authority() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture:fixture@127.0.0.1/fixture")
            .expect("lazy test pool URL must parse");
        let local = local_config("lifetime-fixture:placeholder-pass-1:Auditor");
        let user = local.users.users().first().expect("local fixture user");
        let session = session_config();

        let result = create_local_session(
            &pool,
            user,
            Uuid::new_v4(),
            &[0_u8; crate::session_credentials::SESSION_VERIFIER_LEN],
            session.cookie_max_age_secs + 1,
            &session,
        )
        .await;

        assert!(matches!(
            result,
            Err(IdentityAuthorityError::InvalidInput(
                "session maximum age differs from retained credential authority"
            ))
        ));
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

    #[test]
    fn principal_registry_migration_is_an_opaque_exact_binding_cutover() {
        let migration = include_str!("../../../migrations/199_principal_registry.sql");
        assert!(migration.contains("DROP COLUMN user_id"));
        assert!(migration.contains("DROP COLUMN identity_subject"));
        assert!(migration.contains("principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid()"));
        assert!(migration.contains("principal_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid()"));
        assert!(migration.contains("principal_link_id UUID PRIMARY KEY DEFAULT gen_random_uuid()"));
        assert!(migration.contains("UNIQUE (provider_id, issuer, subject)"));
        assert!(migration.contains("ADD COLUMN principal_id UUID NOT NULL"));
        assert!(migration.contains("ADD COLUMN principal_key_version BIGINT NOT NULL"));
        assert!(migration.contains("authority_digest BYTEA NOT NULL"));
        assert!(migration.contains("CREATE TABLE principal_key_versions"));
        assert!(migration.contains("sessions_principal_fk"));
        assert!(migration.contains("sessions_exact_key_version_fk"));
        assert!(migration.contains("sessions_exact_link_fk"));
        assert!(migration.contains("principal_registry_provider_lock_key"));
        assert!(migration.contains("principal_registry_writer_contract_is_held"));
        assert!(migration.contains("new principal link must enter verified pending state"));
        assert!(migration.contains("principal key transition is terminal or not exactly versioned"));
        assert!(migration.contains("DELETE FROM public.sessions\n        WHERE principal_id"));
        assert!(!migration.contains("md5("));
        assert!(!migration.contains("uuid_generate_v5"));
    }

    #[test]
    fn authenticator_origin_migration_fences_old_session_writers_and_local_origins() {
        let migration =
            include_str!("../../../migrations/201_authenticator_runtime_provenance.sql");
        assert!(migration.contains("RENAME COLUMN bearer_verifier TO session_bearer_verifier_v3"));
        assert!(migration.contains("CREATE TABLE authenticator_authority_generations"));
        assert!(migration.contains("RENAME COLUMN authority_digest TO authority_digest_v3"));
        assert!(migration.contains("CREATE TABLE authenticator_authority_current_paths"));
        assert!(migration.contains("PRIMARY KEY (provider_id, path_kind)"));
        assert!(migration.contains("authenticator_authority_current_paths_current_origin_fk"));
        assert!(migration.contains("authenticator_authority_current_paths_epoch_origin_fk"));
        assert!(migration.contains("path_status IN ('active', 'disabled')"));
        assert!(migration.contains("authenticator_authority_current_provider_coherence"));
        assert!(migration.contains("authenticator_authority_current_paths_no_removal"));
        assert!(migration.contains("CREATE TABLE authenticator_authority_runtime_mode"));
        assert!(migration.contains("INSERT INTO authenticator_authority_runtime_mode"));
        assert!(migration.contains("VALUES (TRUE, 'enabled', 1)"));
        assert!(migration
            .contains("authenticator runtime-mode singleton may not be deleted or truncated"));
        assert!(migration.contains("reconcile_authenticator_authority_current_paths_v3"));
        assert!(migration
            .contains("CREATE FUNCTION disable_all_authenticator_authority_current_paths_v3()"));
        assert!(migration.contains("ryuki-authenticator-authority-global-transition-v3"));
        assert!(migration.contains("ryuki.authenticator_current_path_disable_contract"));
        assert!(migration.contains("ryuki.authenticator_runtime_mode_disable_contract"));
        assert_eq!(migration.matches("active_contract := COALESCE(").count(), 2);
        assert_eq!(
            migration.matches("disable_contract := COALESCE(").count(),
            2
        );
        assert!(migration
            .contains("exactly one authenticator current-path writer contract is required"));
        assert!(migration
            .contains("exactly one authenticator runtime-mode writer contract is required"));
        assert!(migration.contains(
            "authenticator disablement may only clear current authority at the retained epoch"
        ));
        assert!(migration.contains(
            "GRANT SELECT ON TABLE public.authenticator_authority_runtime_mode TO ryuki_app_runtime"
        ));
        assert!(migration.contains(
            "GRANT EXECUTE ON FUNCTION public.disable_all_authenticator_authority_current_paths_v3() TO ryuki_app_runtime"
        ));
        assert!(migration.contains("ryuki.principal_bearer_origin_binding_digest_v3"));
        assert!(migration.contains("oidc_login_states_v3_current_origin_guard"));
        assert!(migration.contains("UNIQUE NULLS NOT DISTINCT"));
        assert!(migration.contains("path_kind IN ('bearer', 'browser-derived-session')"));
        assert!(migration.contains("exact_provider_id = 'local'"));
        assert!(migration.contains("local session must not claim a federated authenticator origin"));
        assert!(migration.contains(
            "federated session requires a canonical provider and exact authenticator origin"
        ));
        assert!(migration.contains("sessions_authenticator_origin_guard"));
        assert!(migration.contains("current_path.path_status = 'active'"));
        assert!(migration.contains("FOR SHARE OF current_path"));
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

    #[tokio::test]
    async fn exact_origin_reconciliation_reads_back_the_same_sealed_generation() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let origin = test_browser_origin();
        let bearer_digest = reconcile_test_authenticator_runtime(pool, &origin)
            .await
            .expect("publish exact paired test authenticator generations");
        let row = sqlx::query_as::<_, AuthenticatorAuthorityGenerationRow>(
            AUTHENTICATOR_AUTHORITY_GENERATION_SELECT_SQL,
        )
        .bind(origin.origin_binding_digest_bytes().as_slice())
        .fetch_one(pool)
        .await
        .expect("read back registered browser authenticator generation");
        let expected = VerifiedAuthenticatorAuthorityGeneration::from_browser_origin(&origin)
            .expect("test origin remains sealed");
        assert!(expected.matches_row(&row));

        let current_rows = sqlx::query_as::<_, AuthenticatorAuthorityCurrentPathRow>(
            "SELECT path_kind, path_status, current_origin_binding_digest, \
                    provider_epoch_origin_binding_digest, provider_epoch_path_kind \
             FROM authenticator_authority_current_paths \
             WHERE provider_id = $1 \
             ORDER BY path_kind",
        )
        .bind(origin.provider_id())
        .fetch_all(pool)
        .await
        .expect("read back paired current paths");
        assert_eq!(current_rows.len(), 2);
        assert!(current_rows.iter().any(|current| {
            current_path_row_matches(
                current,
                DIRECT_BEARER_AUTHENTICATOR_PATH_KIND,
                AUTHENTICATOR_PATH_STATUS_ACTIVE,
                Some(&bearer_digest),
                &bearer_digest,
            )
        }));
        assert!(current_rows.iter().any(|current| {
            current_path_row_matches(
                current,
                BROWSER_DERIVED_AUTHENTICATOR_PATH_KIND,
                AUTHENTICATOR_PATH_STATUS_ACTIVE,
                Some(origin.origin_binding_digest_bytes()),
                &bearer_digest,
            )
        }));
    }

    #[tokio::test]
    async fn request_time_session_mint_cannot_register_or_advance_an_origin() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let origin = test_browser_origin();
        let session = session_config();
        let credential = crate::session_credentials::issue_session_credential(&session)
            .expect("test session credential");
        let result = create_federated_session(
            pool,
            &origin,
            "https://identity.example.test/unpublished",
            &format!("subject-{}", Uuid::new_v4()),
            "Unpublished origin",
            None,
            &["Auditor".to_string()],
            Uuid::new_v4(),
            credential.verifier(),
            session.cookie_max_age_secs,
            &session,
        )
        .await;
        assert!(matches!(
            result,
            Err(IdentityAuthorityError::AssertionRejected)
        ));

        let generation_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM authenticator_authority_generations \
                 WHERE authenticator_origin_binding_digest = $1 \
             )",
        )
        .bind(origin.origin_binding_digest_bytes().as_slice())
        .fetch_one(pool)
        .await
        .expect("check append-only generation absence");
        let pointer_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authenticator_authority_current_paths \
             WHERE provider_id = $1",
        )
        .bind(origin.provider_id())
        .fetch_one(pool)
        .await
        .expect("check current-path absence");
        assert!(!generation_exists);
        assert_eq!(pointer_count, 0);
    }

    #[tokio::test]
    async fn authenticator_epoch_transition_rejects_substitution_rollback_and_disabled_resurrection(
    ) {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let origin = test_browser_origin();
        let v1_runtime = reconcile_test_authenticator_runtime(pool, &origin)
            .await
            .expect("publish initial active browser epoch");

        assert!(matches!(
            reconcile_test_authenticator_epoch(pool, &origin, 1, true, "equal-r-substitution")
                .await,
            Err(IdentityAuthorityError::Database(_))
        ));

        let disabled_v2 =
            reconcile_test_authenticator_epoch(pool, &origin, 2, false, "disabled-v2")
                .await
                .expect("higher provider configuration may reset subordinate versions");
        assert_ne!(disabled_v2.bearer_origin_binding_digest, v1_runtime);
        assert_eq!(disabled_v2.browser_origin_binding_digest, None);

        assert!(matches!(
            reconcile_test_authenticator_runtime(pool, &origin).await,
            Err(IdentityAuthorityError::Database(_))
        ));

        let active_v3 = reconcile_test_authenticator_epoch(pool, &origin, 3, true, "active-v3")
            .await
            .expect("a newer provider configuration may deliberately re-enable browser SSO");
        assert!(active_v3.browser_origin_binding_digest.is_some());
        assert_ne!(
            active_v3.bearer_origin_binding_digest,
            disabled_v2.bearer_origin_binding_digest
        );
    }

    async fn session_is_current(pool: &PgPool, session_record_id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
               SELECT 1 FROM sessions s \
               JOIN principal_keys k \
                 ON k.principal_key_id = s.principal_key_id \
                AND k.key_version = s.principal_key_version \
               JOIN principal_links l \
                 ON l.principal_link_id = s.principal_link_id \
                AND l.link_version = s.principal_link_version \
                AND l.principal_key_id = s.principal_key_id \
                AND l.principal_id = s.principal_id \
               JOIN principals p \
                 ON p.principal_id = s.principal_id \
                AND p.lifecycle_version = s.principal_lifecycle_version \
                AND p.authority_version = s.principal_authority_version \
              WHERE s.session_record_id = $1 \
                AND k.key_state = 'active' \
                AND l.link_state = 'active' \
                AND p.lifecycle_state = 'active' \
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

    async fn principal_authority_version(
        pool: &PgPool,
        provider: &str,
        issuer: &str,
        subject: &str,
    ) -> i64 {
        sqlx::query_scalar(
            "SELECT p.authority_version FROM principals p \
             JOIN principal_links l ON l.principal_id = p.principal_id \
             JOIN principal_keys k ON k.principal_key_id = l.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(subject)
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
            "DELETE FROM sessions s USING principal_keys k \
             WHERE k.principal_key_id = s.principal_key_id \
               AND k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(provider)
        .bind(issuer)
        .bind(subject)
        .execute(pool)
        .await
        .unwrap();
        // Registry keys and links are durable security evidence. Tests retire
        // only ephemeral sessions and always use a fresh provider tuple.
    }

    async fn persist_test_assignment(
        pool: &PgPool,
        provider: &str,
        issuer: &str,
        subject: &str,
        spec: crate::human_authority::HumanAuthorityAssignmentSpec,
        credential_authority_digest: Option<&[u8; 32]>,
    ) -> Result<bool, IdentityAuthorityError> {
        let mut tx = pool.begin().await?;
        if provider.starts_with("provider:") {
            crate::human_authority::prepare_writer_tx(&mut tx, provider, issuer, subject).await?;
            set_test_current_bearer_origin_contract_tx(&mut tx, provider).await?;
        }
        let changed = crate::human_authority::reconcile_assignment_tx(
            &mut tx,
            provider,
            issuer,
            subject,
            spec,
            credential_authority_digest,
        )
        .await?;
        tx.commit().await?;
        if changed {
            crate::session_lookup_admission::clear_positive_global();
        }
        Ok(changed)
    }

    async fn provision_global_assignment(
        pool: &PgPool,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) {
        let digest = crate::session_credentials::identity_authority_digest(
            provider,
            issuer,
            subject,
            roles,
            &session_config(),
        )
        .unwrap();
        persist_test_assignment(
            pool,
            provider,
            issuer,
            subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::test_global(roles),
            Some(&digest),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn concurrent_same_key_callbacks_share_one_opaque_binding() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let authenticator_origin = test_browser_origin();
        reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id().to_string();
        let issuer = format!("urn:ryuki:test:principal-race:{}", Uuid::new_v4());
        let subject = format!("same-key-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let mut callbacks = Vec::new();
        for index in 0..2 {
            let pool = pool.clone();
            let session = session.clone();
            let issuer = issuer.clone();
            let subject = subject.clone();
            let roles = roles.clone();
            let barrier = barrier.clone();
            let authenticator_origin = Arc::clone(&authenticator_origin);
            let provider = provider.clone();
            callbacks.push(tokio::spawn(async move {
                let credential =
                    crate::session_credentials::issue_session_credential(&session).unwrap();
                barrier.wait().await;
                provision_global_assignment(&pool, &provider, &issuer, &subject, &roles).await;
                create_federated_session(
                    &pool,
                    &authenticator_origin,
                    &issuer,
                    &subject,
                    &format!("Concurrent callback {index}"),
                    None,
                    &roles,
                    Uuid::new_v4(),
                    credential.verifier(),
                    3600,
                    &session,
                )
                .await
            }));
        }
        barrier.wait().await;
        for callback in callbacks {
            callback.await.unwrap().unwrap();
        }

        let counts = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64)>(
            "SELECT COUNT(DISTINCT k.principal_key_id), \
                    COUNT(DISTINCT l.principal_link_id), \
                    COUNT(DISTINCT l.principal_id), COUNT(DISTINCT s.session_record_id), \
                    MAX(k.key_version), MAX(l.link_version), \
                    MAX(p.lifecycle_version), MAX(p.authority_version) \
             FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             JOIN principals p ON p.principal_id = l.principal_id \
             LEFT JOIN sessions s ON s.principal_key_id = k.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(&provider)
        .bind(&issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(counts, (1, 1, 1, 2, 1, 2, 1, 3));
        cleanup_identity(pool, &provider, &issuer, &subject).await;
    }

    #[tokio::test]
    async fn credential_authority_change_rotates_key_without_relinking() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let original_session_config = session_config();
        let mut rotated_session_config = original_session_config.clone();
        rotated_session_config.credential_hmac_key =
            "rotated-placeholder-session-authority-key".repeat(2);
        let authenticator_origin = test_browser_origin();
        reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id();
        let issuer = format!("urn:ryuki:test:key-rotation:{}", Uuid::new_v4());
        let subject = format!("rotated-key-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, &issuer, &subject, &roles).await;

        let first_session_id = Uuid::new_v4();
        let first_credential =
            crate::session_credentials::issue_session_credential(&original_session_config).unwrap();
        create_federated_session(
            pool,
            &authenticator_origin,
            &issuer,
            &subject,
            "Credential Rotation",
            None,
            &roles,
            first_session_id,
            first_credential.verifier(),
            3600,
            &original_session_config,
        )
        .await
        .unwrap();
        let before = sqlx::query_as::<_, (Uuid, i64, Uuid, Uuid)>(
            "SELECT k.principal_key_id, k.key_version, l.principal_link_id, l.principal_id \
             FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(provider)
        .bind(&issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();

        let second_session_id = Uuid::new_v4();
        let second_credential =
            crate::session_credentials::issue_session_credential(&rotated_session_config).unwrap();
        create_federated_session(
            pool,
            &authenticator_origin,
            &issuer,
            &subject,
            "Credential Rotation",
            None,
            &roles,
            second_session_id,
            second_credential.verifier(),
            3600,
            &rotated_session_config,
        )
        .await
        .unwrap();
        let after = sqlx::query_as::<_, (Uuid, i64, String, Uuid, i64, String, Uuid)>(
            "SELECT k.principal_key_id, k.key_version, k.key_state, \
                    l.principal_link_id, l.link_version, l.link_state, l.principal_id \
             FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(provider)
        .bind(&issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1 + 1);
        assert_eq!(after.2, "active");
        assert_eq!(after.3, before.2);
        assert_eq!(after.4, 2);
        assert_eq!(after.5, "active");
        assert_eq!(after.6, before.3);
        let recorded_generations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM principal_key_versions WHERE principal_key_id = $1",
        )
        .bind(after.0)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(recorded_generations, 2);
        assert!(!session_row_exists(pool, first_session_id).await);
        assert!(session_is_current(pool, second_session_id).await);
        let persisted_origin: Vec<u8> = sqlx::query_scalar(
            "SELECT authenticator_origin_binding_digest FROM sessions \
             WHERE session_record_id = $1",
        )
        .bind(second_session_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(digest_matches(
            &persisted_origin,
            authenticator_origin.origin_binding_digest_bytes()
        ));
        cleanup_identity(pool, provider, &issuer, &subject).await;
    }

    #[tokio::test]
    async fn identical_subjects_across_provider_or_issuer_get_distinct_principals() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4();
        let subject = format!("shared-subject-{suffix}");
        let issuer_a = format!("urn:ryuki:test:issuer-a:{suffix}");
        let issuer_b = format!("urn:ryuki:test:issuer-b:{suffix}");
        let roles = vec!["Auditor".to_string()];
        for (provider, issuer) in [
            ("oidc", issuer_a.as_str()),
            ("oidc", issuer_b.as_str()),
            ("entra-id", issuer_a.as_str()),
        ] {
            provision_global_assignment(pool, provider, issuer, &subject, &roles).await;
        }

        let principal_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT l.principal_id FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             WHERE k.subject = $1 AND ( \
               (k.provider_id = 'oidc' AND k.issuer = $2) OR \
               (k.provider_id = 'oidc' AND k.issuer = $3) OR \
               (k.provider_id = 'entra-id' AND k.issuer = $2) \
             ) ORDER BY k.provider_id, k.issuer",
        )
        .bind(&subject)
        .bind(&issuer_a)
        .bind(&issuer_b)
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(principal_ids.len(), 3);
        assert_eq!(
            principal_ids
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn lifecycle_revoke_tombstones_the_binding_and_never_relinks_it() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let provider = "passkey";
        let issuer = format!("urn:ryuki:test:tombstone:{}", Uuid::new_v4());
        let subject = format!("tombstoned-subject-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, &issuer, &subject, &roles).await;
        let original_principal: Uuid = sqlx::query_scalar(
            "SELECT l.principal_id FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(provider)
        .bind(&issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();

        let revoked = apply_lifecycle_event(
            pool,
            provider,
            &issuer,
            &subject,
            AuthorityLifecycleState::Revoked,
            &[],
            1,
            &session,
        )
        .await
        .unwrap();
        assert!(revoked.applied);
        let digest = crate::session_credentials::identity_authority_digest(
            provider, &issuer, &subject, &roles, &session,
        )
        .unwrap();
        assert!(matches!(
            crate::human_authority::persist_governed_assignment_with_digest(
                pool,
                provider,
                &issuer,
                &subject,
                crate::human_authority::HumanAuthorityAssignmentSpec::test_global(&roles),
                &digest,
            )
            .await,
            Err(
                crate::human_authority::HumanAuthorityError::PrincipalRegistry(
                    crate::principal_registry::PrincipalRegistryError::NotActive
                )
            )
        ));
        let mut rejected_assertion_tx = pool.begin().await.unwrap();
        let rejected_assertion = assert_federated_authority_tx(
            &mut rejected_assertion_tx,
            provider,
            &issuer,
            &subject,
            &roles,
            &session,
        )
        .await;
        rejected_assertion_tx.rollback().await.unwrap();
        assert!(matches!(
            rejected_assertion,
            Err(IdentityAuthorityError::PrincipalRegistry(
                crate::principal_registry::PrincipalRegistryError::NotActive
            ))
        ));
        let state = sqlx::query_as::<_, (i64, i64, String, String, Uuid)>(
            "SELECT COUNT(*) OVER (), k.key_version, k.key_state, l.link_state, l.principal_id \
             FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(provider)
        .bind(&issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(state.0, 1);
        assert_eq!(state.1, 2);
        assert_eq!(state.2, "tombstoned");
        assert_eq!(state.3, "tombstoned");
        assert_eq!(state.4, original_principal);
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
        let row = sqlx::query_as::<_, (Uuid, i64, i64, Uuid, i64, Uuid, i64)>(
            "SELECT principal_id, principal_lifecycle_version, principal_authority_version, \
                    principal_key_id, principal_key_version, principal_link_id, \
                    principal_link_version \
             FROM sessions WHERE session_bearer_verifier_v3 = $1",
        )
        .bind(credential.verifier().as_slice())
        .fetch_one(pool)
        .await
        .unwrap();
        let exact_cache_binding = crate::session_lookup_admission::SessionAuthorityCacheBinding {
            principal_id: ryuki_core::PrincipalId::from_uuid(row.0).unwrap(),
            principal_lifecycle_version: row.1,
            principal_authority_version: row.2,
            principal_key_id: row.3,
            principal_key_version: row.4,
            principal_link_id: row.5,
            principal_link_version: row.6,
        };
        valid_admission.record_hit(
            *credential.verifier(),
            std::time::Duration::from_secs(3600),
            exact_cache_binding,
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
                principal_authority_version: exact_cache_binding.principal_authority_version + 1,
                ..exact_cache_binding
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
        let local_origin: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT authenticator_origin_binding_digest FROM sessions \
             WHERE session_record_id = $1",
        )
        .bind(session_record_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(local_origin.is_none());

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

        let version_before_scope_change =
            principal_authority_version(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
        let narrowed = scoped_local_config(
            &format!("{username}:placeholder-pass-1:PlatformAdmin|Auditor"),
            "SITE-B",
            "prod",
        );
        reconcile_local_authorities(pool, &narrowed, &session)
            .await
            .unwrap();
        let version_after_scope_change =
            principal_authority_version(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
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
        let (runtime_binding, validator) = test_direct_bearer_runtime();
        reconcile_current_authenticator_runtime(pool, &runtime_binding)
            .await
            .expect("publish current direct-bearer runtime");
        let direct_origin = runtime_binding
            .direct_bearer_origin()
            .expect("test runtime must seal one direct-bearer origin");
        let provider = direct_origin.provider_id().to_string();
        let subject = Uuid::new_v4().hyphenated().to_string();
        let asserted = vec!["PlatformAdmin".to_string(), "Auditor".to_string()];
        let verified_identity = crate::entra_auth::VerifiedEntraBearerIdentity::fixture(
            Arc::clone(&validator),
            &subject,
            "Direct Entra User",
            &asserted,
            ryuki_engine::auth::ActorClass::VerifiedHuman,
        );
        let issuer = verified_identity.issuer().to_string();
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
        let initial_assignment_digest = crate::session_credentials::identity_authority_digest(
            &provider,
            &issuer,
            &subject,
            &["Auditor".to_string()],
            &session_config(),
        )
        .expect("test assignment digest");
        persist_test_assignment(
            pool,
            &provider,
            &issuer,
            &subject,
            assignment,
            Some(&initial_assignment_digest),
        )
        .await
        .unwrap();
        for actor_class in [
            ryuki_engine::auth::ActorClass::Workload,
            ryuki_engine::auth::ActorClass::Unknown,
        ] {
            let non_human_identity = crate::entra_auth::VerifiedEntraBearerIdentity::fixture(
                Arc::clone(&validator),
                &subject,
                "Non-human bearer",
                &asserted,
                actor_class,
            );
            assert!(matches!(
                admit_federated_bearer(pool, &runtime_binding, &non_human_identity).await,
                Err(IdentityAuthorityError::AssertionRejected)
            ));
        }
        let admitted = admit_federated_bearer(pool, &runtime_binding, &verified_identity)
            .await
            .unwrap();
        assert_eq!(admitted.session.roles, ["Auditor"]);
        assert_eq!(admitted.session.site_scope, ["SITE-A"]);
        assert_eq!(admitted.session.environment_scope, ["prod"]);
        assert_eq!(admitted.session.provider_mode, provider);
        assert_eq!(admitted.authority.provider, provider);
        assert_eq!(admitted.authenticator_origin.provider_id(), provider);
        let persisted_provider: String = sqlx::query_scalar(
            "SELECT provider_id FROM principal_keys WHERE issuer = $1 AND subject = $2",
        )
        .bind(&issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(persisted_provider, provider);

        let unknown_subject = Uuid::new_v4().hyphenated().to_string();
        let unknown_identity = crate::entra_auth::VerifiedEntraBearerIdentity::fixture(
            Arc::clone(&validator),
            &unknown_subject,
            "Unknown Entra User",
            &asserted,
            ryuki_engine::auth::ActorClass::VerifiedHuman,
        );
        assert!(matches!(
            admit_federated_bearer(pool, &runtime_binding, &unknown_identity).await,
            Err(IdentityAuthorityError::PrincipalRegistry(
                crate::principal_registry::PrincipalRegistryError::NotActive
            ))
        ));

        persist_test_assignment(
            pool,
            &provider,
            &issuer,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "governed",
                "direct-bearer-test",
            ),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            admit_federated_bearer(pool, &runtime_binding, &verified_identity).await,
            Err(IdentityAuthorityError::PrincipalRegistry(
                crate::principal_registry::PrincipalRegistryError::NotActive
            ))
        ));
        cleanup_identity(pool, &provider, &issuer, &subject).await;
        cleanup_identity(pool, &provider, &issuer, &unknown_subject).await;
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
        let original_assignment_version =
            principal_authority_version(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
        assert_eq!(
            carrier_results(&resolution_config, old_credential.bearer()).await,
            [true, true, true]
        );

        reconcile_local_authorities(pool, &changed, &session)
            .await
            .unwrap();
        let changed_assignment_version =
            principal_authority_version(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
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
    async fn local_tombstone_rollback_and_exact_origin_reconciliation_are_fail_closed() {
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

        reconcile_local_authorities(pool, &LocalAuthConfig::default(), &session)
            .await
            .unwrap();
        assert!(!session_row_exists(pool, local_session).await);

        assert!(matches!(
            reconcile_local_authorities(pool, &local, &session).await,
            Err(IdentityAuthorityError::HumanAuthority(
                crate::human_authority::HumanAuthorityError::PrincipalRegistry(
                    crate::principal_registry::PrincipalRegistryError::NotActive
                )
            ))
        ));
        assert!(
            !session_row_exists(pool, local_session).await,
            "a tombstoned local authority must not resurrect its old session"
        );

        let authenticator_origin = test_browser_origin();
        let initial_reconciliation =
            reconcile_test_authenticator_runtime(pool, &authenticator_origin)
                .await
                .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id();
        let issuer = "https://identity.example.test/provider-admission";
        let subject = format!("admission-subject-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &roles).await;
        let oidc_session = Uuid::new_v4();
        let oidc_credential =
            crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            &authenticator_origin,
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
        let reconciliation = reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("equal-epoch reconciliation is exactly idempotent");
        assert_eq!(reconciliation, initial_reconciliation);
        assert!(session_row_exists(pool, oidc_session).await);

        cleanup_identity(pool, LOCAL_PROVIDER, LOCAL_ISSUER, &username).await;
        cleanup_identity(pool, provider, issuer, &subject).await;
    }

    #[tokio::test]
    #[ignore = "pre-199 watermark feed semantics were replaced by terminal registry tombstones"]
    async fn federated_lifecycle_events_reject_stale_roles_revocation_and_rollback() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let authenticator_origin = test_browser_origin();
        reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id();
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
            &authenticator_origin,
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
            &authenticator_origin,
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
            &authenticator_origin,
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
            &authenticator_origin,
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
            &authenticator_origin,
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
            &authenticator_origin,
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
        let authenticator_origin = test_browser_origin();
        reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id().to_string();
        let issuer = "urn:ryuki:test:concurrent-revoke";
        let subject = format!("race-subject-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, &provider, issuer, &subject, &roles).await;

        let initial = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            &authenticator_origin,
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
        crate::human_authority::prepare_writer_tx(&mut revoke_tx, &provider, issuer, &subject)
            .await
            .unwrap();
        set_test_current_bearer_origin_contract_tx(&mut revoke_tx, &provider)
            .await
            .unwrap();
        crate::human_authority::reconcile_assignment_tx(
            &mut revoke_tx,
            &provider,
            issuer,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "governed",
                "two-connection-test",
            ),
            None,
        )
        .await
        .unwrap();

        let mint_pool = pool.clone();
        let mint_session = session.clone();
        let mint_subject = subject.clone();
        let mint_roles = roles.clone();
        let mint_origin = Arc::clone(&authenticator_origin);
        let mut mint = tokio::spawn(async move {
            let credential =
                crate::session_credentials::issue_session_credential(&mint_session).unwrap();
            create_federated_session(
                &mint_pool,
                &mint_origin,
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
            Err(IdentityAuthorityError::PrincipalRegistry(
                crate::principal_registry::PrincipalRegistryError::NotActive
            ))
        ));
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions s \
             JOIN principal_keys k ON k.principal_key_id = s.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(&provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0, "revoke must win without rolling back");
        cleanup_identity(pool, &provider, issuer, &subject).await;
    }

    #[tokio::test]
    async fn assignment_revoke_and_lifecycle_revoke_serialize_without_deadlock() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let authenticator_origin = test_browser_origin();
        reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id().to_string();
        let issuer = "urn:ryuki:test:lifecycle-assignment-order";
        let subject = format!("lifecycle-order-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, &provider, issuer, &subject, &roles).await;
        let credential = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            &authenticator_origin,
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
        crate::human_authority::prepare_writer_tx(&mut assignment_tx, &provider, issuer, &subject)
            .await
            .unwrap();
        set_test_current_bearer_origin_contract_tx(&mut assignment_tx, &provider)
            .await
            .unwrap();
        crate::human_authority::reconcile_assignment_tx(
            &mut assignment_tx,
            &provider,
            issuer,
            &subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::revoked(
                "governed",
                "deadlock-regression",
            ),
            None,
        )
        .await
        .unwrap();

        let lifecycle_pool = pool.clone();
        let lifecycle_provider = provider.clone();
        let lifecycle_subject = subject.clone();
        let lifecycle_session = session.clone();
        let mut lifecycle = tokio::spawn(async move {
            apply_lifecycle_event(
                &lifecycle_pool,
                &lifecycle_provider,
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
        assert!(!outcome.applied);
        assert_eq!(outcome.state, AuthorityLifecycleState::Revoked);
        let states: (String, String) = sqlx::query_as(
            "SELECT k.key_state, l.link_state \
             FROM principal_keys k \
             JOIN principal_links l ON l.principal_key_id = k.principal_key_id \
             WHERE k.provider_id = $1 AND k.issuer = $2 AND k.subject = $3",
        )
        .bind(&provider)
        .bind(issuer)
        .bind(&subject)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(states, ("revoked".to_string(), "revoked".to_string()));
        cleanup_identity(pool, &provider, issuer, &subject).await;
    }

    #[tokio::test]
    #[ignore = "pre-199 direct-writer fixture references frozen legacy evidence tables"]
    async fn direct_writer_cannot_preseed_future_or_revoked_identity_epoch() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let session = session_config();
        let authenticator_origin = test_browser_origin();
        reconcile_test_authenticator_runtime(pool, &authenticator_origin)
            .await
            .expect("publish current authenticator fixture");
        let provider = authenticator_origin.provider_id();
        let issuer = "urn:ryuki:test:passkey";
        let subject = format!("future-epoch-{}", Uuid::new_v4());
        let roles = vec!["Auditor".to_string()];
        provision_global_assignment(pool, provider, issuer, &subject, &roles).await;
        let credential = crate::session_credentials::issue_session_credential(&session).unwrap();
        create_federated_session(
            pool,
            &authenticator_origin,
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
             (session_record_id, session_bearer_verifier_v3, user_id, display_name, roles, provider, \
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
             (session_record_id, session_bearer_verifier_v3, user_id, display_name, roles, provider, \
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
             (session_record_id, session_bearer_verifier_v3, user_id, display_name, roles, provider, \
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
