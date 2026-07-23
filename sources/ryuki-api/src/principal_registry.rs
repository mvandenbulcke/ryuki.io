//! Opaque, provider-qualified principal registry bindings.
//!
//! External identity attributes are lookup material only. A verified
//! `(provider, issuer, subject)` tuple is bound to random internal UUIDs while
//! holding the same tuple advisory lock used by identity and human authority.
//! Email, display name, and bare subject values never participate in internal
//! identifier selection.

use ryuki_core::PrincipalId;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const WRITER_CONTRACT_VERSION: &str = "1";

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrincipalRegistryError {
    #[error("principal registry database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("principal registry binding is not active")]
    NotActive,
    #[error("principal registry contains an invalid opaque identifier or version")]
    InvalidStoredBinding,
}

/// Exact registry generations admitted for one credential or session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrincipalBinding {
    pub principal_id: PrincipalId,
    pub principal_lifecycle_version: i64,
    pub principal_authority_version: i64,
    pub principal_key_id: Uuid,
    pub principal_key_version: i64,
    pub principal_link_id: Uuid,
    pub principal_link_version: i64,
}

/// Canonical human authority stored with a newly allocated principal. Values
/// are validated and normalized by `human_authority` before they cross this
/// boundary.
pub(crate) struct InitialHumanAuthority<'a> {
    pub authority_digest: &'a [u8; 32],
    pub roles: &'a [String],
    pub site_mode: &'static str,
    pub site_scope: &'a [String],
    pub environment_mode: &'static str,
    pub environment_scope: &'a [String],
    pub created_by: &'a str,
}

#[derive(sqlx::FromRow)]
struct PrincipalKeyRow {
    principal_key_id: Uuid,
    key_version: i64,
    key_state: String,
    authority_digest: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct LinkedPrincipalRow {
    principal_id: Uuid,
    lifecycle_version: i64,
    authority_version: i64,
    lifecycle_state: String,
    principal_link_id: Uuid,
    link_version: i64,
    link_state: String,
}

fn active_binding(
    key: PrincipalKeyRow,
    linked: LinkedPrincipalRow,
) -> Result<PrincipalBinding, PrincipalRegistryError> {
    if key.key_state != "active"
        || linked.link_state != "active"
        || linked.lifecycle_state != "active"
        || key.authority_digest.len() != 32
        || key.key_version <= 0
        || linked.link_version <= 0
        || linked.lifecycle_version <= 0
        || linked.authority_version <= 0
    {
        return Err(PrincipalRegistryError::NotActive);
    }
    Ok(PrincipalBinding {
        principal_id: PrincipalId::from_uuid(linked.principal_id)
            .map_err(|_| PrincipalRegistryError::InvalidStoredBinding)?,
        principal_lifecycle_version: linked.lifecycle_version,
        principal_authority_version: linked.authority_version,
        principal_key_id: key.principal_key_id,
        principal_key_version: key.key_version,
        principal_link_id: linked.principal_link_id,
        principal_link_version: linked.link_version,
    })
}

/// Establishes the migration-199 writer contract. The provider sentinel must
/// precede the exact identity-key lock so provider removal cannot race a new
/// key, and every principal-registry writer shares that ordering.
pub(crate) async fn prepare_writer_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), PrincipalRegistryError> {
    sqlx::query("SELECT set_config('ryuki.principal_registry_writer_contract', $1, TRUE)")
        .bind(WRITER_CONTRACT_VERSION)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock( \
             principal_registry_provider_lock_key($1) \
         )",
    )
    .bind(provider)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock( \
             human_authority_lock_key($1, $2, $3) \
         )",
    )
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Holds both registry namespaces in shared mode for an exact binding read.
/// Provider/key tombstoning takes the exclusive counterparts and therefore
/// cannot commit between revalidation and the consuming read transaction.
pub(crate) async fn prepare_reader_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), PrincipalRegistryError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock_shared( \
             principal_registry_provider_lock_key($1) \
         )",
    )
    .bind(provider)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock_shared( \
             human_authority_lock_key($1, $2, $3) \
         )",
    )
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn locked_key(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<Option<PrincipalKeyRow>, PrincipalRegistryError> {
    Ok(sqlx::query_as::<_, PrincipalKeyRow>(
        "SELECT principal_key_id, key_version, key_state, \
                authority_digest_v3 AS authority_digest \
         FROM principal_keys \
         WHERE provider_id = $1 AND issuer = $2 AND subject = $3 \
         FOR SHARE",
    )
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut **tx)
    .await?)
}

async fn locked_linked_principal(
    tx: &mut Transaction<'_, Postgres>,
    principal_key_id: Uuid,
) -> Result<Option<LinkedPrincipalRow>, PrincipalRegistryError> {
    Ok(sqlx::query_as::<_, LinkedPrincipalRow>(
        "SELECT p.principal_id, p.lifecycle_version, p.authority_version, \
                p.lifecycle_state, l.principal_link_id, l.link_version, l.link_state \
         FROM principal_links l \
         JOIN principals p ON p.principal_id = l.principal_id \
         WHERE l.principal_key_id = $1 \
           AND l.link_state IN ('active', 'pending') \
         ORDER BY l.link_version DESC \
         LIMIT 1 \
         FOR SHARE OF l, p",
    )
    .bind(principal_key_id)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Resolves an already established binding and rejects every non-active
/// principal, key, or link generation.
pub(crate) async fn resolve_active_binding_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<PrincipalBinding, PrincipalRegistryError> {
    let key = locked_key(tx, provider, issuer, subject)
        .await?
        .ok_or(PrincipalRegistryError::NotActive)?;
    let linked = locked_linked_principal(tx, key.principal_key_id)
        .await?
        .ok_or(PrincipalRegistryError::NotActive)?;
    active_binding(key, linked)
}

/// Resolves or creates exactly one random opaque binding for a verified
/// provider-qualified key. This establishes the writer contract itself; the
/// exact-key advisory lock makes concurrent callbacks converge on the row
/// selected here.
pub(crate) async fn resolve_or_create_active_binding_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    authority: &InitialHumanAuthority<'_>,
) -> Result<(PrincipalBinding, bool), PrincipalRegistryError> {
    prepare_writer_tx(tx, provider, issuer, subject).await?;
    if let Some(key) = locked_key(tx, provider, issuer, subject).await? {
        let linked = locked_linked_principal(tx, key.principal_key_id)
            .await?
            .ok_or(PrincipalRegistryError::NotActive)?;
        return Ok((active_binding(key, linked)?, false));
    }

    let (principal_uuid, lifecycle_version, initial_authority_version) =
        sqlx::query_as::<_, (Uuid, i64, i64)>(
            "INSERT INTO principals \
         (lifecycle_state, principal_kind, role_allowlist, site_authority_mode, site_scope, \
          environment_authority_mode, environment_scope, created_by) \
         VALUES ('active', 'human', $1, $2, $3, $4, $5, $6) \
         RETURNING principal_id, lifecycle_version, authority_version",
        )
        .bind(authority.roles)
        .bind(authority.site_mode)
        .bind(authority.site_scope)
        .bind(authority.environment_mode)
        .bind(authority.environment_scope)
        .bind(authority.created_by)
        .fetch_one(&mut **tx)
        .await?;
    if lifecycle_version != 1 || initial_authority_version != 1 {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    let principal_id = PrincipalId::from_uuid(principal_uuid)
        .map_err(|_| PrincipalRegistryError::InvalidStoredBinding)?;
    let (principal_key_id, key_version) = sqlx::query_as::<_, (Uuid, i64)>(
        "INSERT INTO principal_keys \
         (provider_id, issuer, subject, key_state, authority_digest_v3, \
          transition_reason, transitioned_by) \
         VALUES ($1, $2, $3, 'active', $4, 'initial-provider-qualified-binding', $5) \
         RETURNING principal_key_id, key_version",
    )
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .bind(authority.authority_digest.as_slice())
    .bind(authority.created_by)
    .fetch_one(&mut **tx)
    .await?;
    if principal_key_id.is_nil() || key_version != 1 {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    let (principal_link_id, pending_link_version) = sqlx::query_as::<_, (Uuid, i64)>(
        "INSERT INTO principal_links \
         (principal_key_id, principal_id, link_state, \
          transition_kind, transition_reason, transitioned_by) \
         VALUES ($1, $2, 'pending', 'initial-verification', \
                 'initial-provider-qualified-binding', $3) \
         RETURNING principal_link_id, link_version",
    )
    .bind(principal_key_id)
    .bind(principal_id.into_uuid())
    .bind(authority.created_by)
    .fetch_one(&mut **tx)
    .await?;
    if principal_link_id.is_nil() || pending_link_version != 1 {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    let active_link_version = sqlx::query_scalar::<_, i64>(
        "UPDATE principal_links SET \
           link_version = link_version + 1, link_state = 'active', \
           transition_kind = 'initial-verification', \
           transition_reason = 'initial-provider-qualified-binding', transitioned_by = $2 \
         WHERE principal_link_id = $1 AND link_state = 'pending' \
         RETURNING link_version",
    )
    .bind(principal_link_id)
    .bind(authority.created_by)
    .fetch_one(&mut **tx)
    .await?;
    if active_link_version != 2 {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    let key = locked_key(tx, provider, issuer, subject)
        .await?
        .ok_or(PrincipalRegistryError::InvalidStoredBinding)?;
    let linked = locked_linked_principal(tx, key.principal_key_id)
        .await?
        .ok_or(PrincipalRegistryError::InvalidStoredBinding)?;
    Ok((active_binding(key, linked)?, true))
}

/// Permanently tombstones an exact provider key. An unseen revoked key is
/// first allocated as an unlinked active row and immediately tombstoned in the
/// same transaction, preserving a non-reusable provider-qualified tombstone
/// without inventing or linking a principal.
pub(crate) async fn tombstone_key_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    reason: &str,
    transitioned_by: &str,
) -> Result<bool, PrincipalRegistryError> {
    prepare_writer_tx(tx, provider, issuer, subject).await?;
    let key = match locked_key(tx, provider, issuer, subject).await? {
        Some(key) if key.key_state == "tombstoned" => return Ok(false),
        Some(key) => key,
        None => {
            let unasserted_digest: [u8; 32] = rand::random();
            let (principal_key_id, key_version) = sqlx::query_as::<_, (Uuid, i64)>(
                "INSERT INTO principal_keys \
                 (provider_id, issuer, subject, key_state, authority_digest_v3, \
                  transition_reason, transitioned_by) \
                 VALUES ($1, $2, $3, 'active', $4, $5, $6) \
                 RETURNING principal_key_id, key_version",
            )
            .bind(provider)
            .bind(issuer)
            .bind(subject)
            .bind(unasserted_digest.as_slice())
            .bind(reason)
            .bind(transitioned_by)
            .fetch_one(&mut **tx)
            .await?;
            PrincipalKeyRow {
                principal_key_id,
                key_version,
                key_state: "active".to_string(),
                authority_digest: unasserted_digest.to_vec(),
            }
        }
    };
    if key.key_state != "active" || key.key_version <= 0 {
        return Err(PrincipalRegistryError::NotActive);
    }
    let next_version = key
        .key_version
        .checked_add(1)
        .ok_or(PrincipalRegistryError::InvalidStoredBinding)?;
    let updated = sqlx::query(
        "UPDATE principal_keys SET \
           key_version = $2, key_state = 'tombstoned', \
           transition_reason = $3, transitioned_by = $4 \
         WHERE principal_key_id = $1 AND key_version = $5 AND key_state = 'active'",
    )
    .bind(key.principal_key_id)
    .bind(next_version)
    .bind(reason)
    .bind(transitioned_by)
    .bind(key.key_version)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    Ok(true)
}

/// Rotates the exact key generation when credential/configuration authority
/// changes. This is non-terminal: the provider key and active link remain the
/// same opaque identities, while migration-199 invalidates credentials bound
/// to the previous key version and records immutable generation evidence.
pub(crate) async fn reconcile_authority_digest_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    authority_digest: &[u8; 32],
    transitioned_by: &str,
) -> Result<bool, PrincipalRegistryError> {
    prepare_writer_tx(tx, provider, issuer, subject).await?;
    let key = locked_key(tx, provider, issuer, subject)
        .await?
        .ok_or(PrincipalRegistryError::NotActive)?;
    if key.key_state != "active" || key.key_version <= 0 {
        return Err(PrincipalRegistryError::NotActive);
    }
    if key.authority_digest.len() != 32 {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    if key.authority_digest.as_slice() == authority_digest {
        return Ok(false);
    }
    let next_version = key
        .key_version
        .checked_add(1)
        .ok_or(PrincipalRegistryError::InvalidStoredBinding)?;
    let rotated = sqlx::query_scalar::<_, i64>(
        "UPDATE principal_keys SET \
           key_version = $2, authority_digest_v3 = $3, \
           transition_reason = 'credential-authority-change', transitioned_by = $4 \
         WHERE principal_key_id = $1 AND key_version = $5 AND key_state = 'active' \
         RETURNING key_version",
    )
    .bind(key.principal_key_id)
    .bind(next_version)
    .bind(authority_digest.as_slice())
    .bind(transitioned_by)
    .bind(key.key_version)
    .fetch_optional(&mut **tx)
    .await?;
    if rotated != Some(next_version) {
        return Err(PrincipalRegistryError::InvalidStoredBinding);
    }
    Ok(true)
}
