//! Provider-neutral interactive-human authorization assignments.
//!
//! Authentication carriers prove identity and may assert an upper bound on
//! roles/scopes. They never grant Ryuki authority directly. Every verified
//! local, OIDC, Entra, brokered SAML/LDAP, or passkey principal is intersected
//! with the current durable assignment keyed by `(provider, issuer, subject)`.

#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Transaction};

use ryuki_core::config::{LocalAuthConfig, LocalAuthorityMode};
use ryuki_engine::auth::ALL_APP_ROLES;

const MAX_AUTHORITY_VALUES: usize = 64;
const MAX_AUTHORITY_VALUE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HumanAuthorityMode {
    Unknown,
    Global,
    Scoped,
    Revoked,
}

impl HumanAuthorityMode {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Global => "global",
            Self::Scoped => "scoped",
            Self::Revoked => "revoked",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, HumanAuthorityError> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "global" => Ok(Self::Global),
            "scoped" => Ok(Self::Scoped),
            "revoked" => Ok(Self::Revoked),
            _ => Err(HumanAuthorityError::InvalidAssignment("authority mode")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HumanAssignmentStatus {
    Unknown,
    Active,
    Revoked,
}

impl HumanAssignmentStatus {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, HumanAuthorityError> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(HumanAuthorityError::InvalidAssignment("assignment status")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HumanAuthorityError {
    #[error("human authority database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("principal registry binding was rejected")]
    PrincipalRegistry(#[from] crate::principal_registry::PrincipalRegistryError),
    #[error("human authority assignment is missing, unknown, or revoked")]
    NotActive,
    #[error("human authority assertion has no permitted role or scope intersection")]
    EmptyIntersection,
    #[error("human authority assignment is invalid: {0}")]
    InvalidAssignment(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HumanAuthorityAssertion {
    pub roles: Vec<String>,
    pub site_mode: HumanAuthorityMode,
    pub site_scope: Vec<String>,
    pub environment_mode: HumanAuthorityMode,
    pub environment_scope: Vec<String>,
}

impl HumanAuthorityAssertion {
    /// A carrier with verified roles but no narrower provider scope claim.
    /// Global here is an explicit *ceiling* and never an authority grant: the
    /// durable assignment is still mandatory and may narrow either axis.
    pub(crate) fn role_assertion(roles: &[String]) -> Self {
        Self {
            roles: roles.to_vec(),
            site_mode: HumanAuthorityMode::Global,
            site_scope: Vec::new(),
            environment_mode: HumanAuthorityMode::Global,
            environment_scope: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveHumanAuthority {
    pub principal_binding: crate::principal_registry::PrincipalBinding,
    pub roles: Vec<String>,
    pub site_mode: HumanAuthorityMode,
    pub site_scope: Vec<String>,
    pub environment_mode: HumanAuthorityMode,
    pub environment_scope: Vec<String>,
}

/// Exact, non-serialized authority that admitted one interactive request.
/// Handlers use this only for derived-credential provenance; owner metadata
/// can never substitute for this stable identity tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InteractiveHumanAuthorityContext {
    pub principal_binding: crate::principal_registry::PrincipalBinding,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub identity_epoch: i64,
    pub assignment_version: i64,
    pub roles: Vec<String>,
    pub site_mode: HumanAuthorityMode,
    pub site_scope: Vec<String>,
    pub environment_mode: HumanAuthorityMode,
    pub environment_scope: Vec<String>,
}

impl InteractiveHumanAuthorityContext {
    pub(crate) fn from_effective(
        principal_binding: crate::principal_registry::PrincipalBinding,
        provider: &str,
        issuer: &str,
        subject: &str,
        authority: &EffectiveHumanAuthority,
    ) -> Self {
        Self {
            principal_binding,
            provider: provider.to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            identity_epoch: principal_binding.principal_lifecycle_version,
            assignment_version: principal_binding.principal_authority_version,
            roles: authority.roles.clone(),
            site_mode: authority.site_mode,
            site_scope: authority.site_scope.clone(),
            environment_mode: authority.environment_mode,
            environment_scope: authority.environment_scope.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HumanAuthorityAssignmentSpec {
    pub status: HumanAssignmentStatus,
    pub role_allowlist: Vec<String>,
    pub site_mode: HumanAuthorityMode,
    pub site_scope: Vec<String>,
    pub environment_mode: HumanAuthorityMode,
    pub environment_scope: Vec<String>,
    pub source_kind: &'static str,
    pub updated_by: String,
}

impl HumanAuthorityAssignmentSpec {
    #[cfg(test)]
    pub(crate) fn test_global(roles: &[String]) -> Self {
        Self {
            status: HumanAssignmentStatus::Active,
            role_allowlist: roles.to_vec(),
            site_mode: HumanAuthorityMode::Global,
            site_scope: Vec::new(),
            environment_mode: HumanAuthorityMode::Global,
            environment_scope: Vec::new(),
            source_kind: "governed",
            updated_by: "test-suite".to_string(),
        }
    }

    pub(crate) fn local(
        config: &LocalAuthConfig,
        roles: &[String],
    ) -> Result<Self, HumanAuthorityError> {
        let authority = config
            .human_authority()
            .map_err(HumanAuthorityError::InvalidAssignment)?;
        Ok(Self {
            status: HumanAssignmentStatus::Active,
            role_allowlist: roles.to_vec(),
            site_mode: local_mode(authority.site_mode),
            site_scope: authority.site_scope,
            environment_mode: local_mode(authority.environment_mode),
            environment_scope: authority.environment_scope,
            source_kind: "local-config",
            updated_by: "local-config".to_string(),
        })
    }

    pub(crate) fn revoked(source_kind: &'static str, updated_by: impl Into<String>) -> Self {
        Self {
            status: HumanAssignmentStatus::Revoked,
            role_allowlist: Vec::new(),
            site_mode: HumanAuthorityMode::Revoked,
            site_scope: Vec::new(),
            environment_mode: HumanAuthorityMode::Revoked,
            environment_scope: Vec::new(),
            source_kind,
            updated_by: updated_by.into(),
        }
    }
}

fn local_mode(mode: LocalAuthorityMode) -> HumanAuthorityMode {
    match mode {
        LocalAuthorityMode::Unknown => HumanAuthorityMode::Unknown,
        LocalAuthorityMode::Global => HumanAuthorityMode::Global,
        LocalAuthorityMode::Scoped => HumanAuthorityMode::Scoped,
    }
}

fn canonical_values(
    values: &[String],
    label: &'static str,
) -> Result<Vec<String>, HumanAuthorityError> {
    if values.len() > MAX_AUTHORITY_VALUES {
        return Err(HumanAuthorityError::InvalidAssignment(label));
    }
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_AUTHORITY_VALUE_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
            })
        {
            return Err(HumanAuthorityError::InvalidAssignment(label));
        }
        canonical.push(value.to_string());
    }
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

fn canonical_roles(values: &[String]) -> Result<Vec<String>, HumanAuthorityError> {
    let roles = canonical_values(values, "roles")?;
    if roles
        .iter()
        .any(|role| !ALL_APP_ROLES.contains(&role.as_str()))
    {
        return Err(HumanAuthorityError::InvalidAssignment("roles"));
    }
    Ok(roles)
}

fn canonical_asserted_roles(values: &[String]) -> Result<Vec<String>, HumanAuthorityError> {
    let mut roles = canonical_values(values, "asserted roles")?;
    roles.retain(|role| ALL_APP_ROLES.contains(&role.as_str()));
    Ok(roles)
}

fn validate_axis(
    mode: HumanAuthorityMode,
    values: &[String],
) -> Result<Vec<String>, HumanAuthorityError> {
    let values = canonical_values(values, "scope")?;
    match mode {
        HumanAuthorityMode::Global if values.is_empty() => Ok(values),
        HumanAuthorityMode::Scoped if !values.is_empty() => Ok(values),
        HumanAuthorityMode::Unknown | HumanAuthorityMode::Revoked => {
            Err(HumanAuthorityError::NotActive)
        }
        HumanAuthorityMode::Global | HumanAuthorityMode::Scoped => {
            Err(HumanAuthorityError::InvalidAssignment("scope shape"))
        }
    }
}

fn intersect_axis(
    asserted_mode: HumanAuthorityMode,
    asserted: &[String],
    assigned_mode: HumanAuthorityMode,
    assigned: &[String],
) -> Result<(HumanAuthorityMode, Vec<String>), HumanAuthorityError> {
    let asserted = validate_axis(asserted_mode, asserted)?;
    let assigned = validate_axis(assigned_mode, assigned)?;
    match (asserted_mode, assigned_mode) {
        (HumanAuthorityMode::Global, HumanAuthorityMode::Global) => {
            Ok((HumanAuthorityMode::Global, Vec::new()))
        }
        (HumanAuthorityMode::Global, HumanAuthorityMode::Scoped) => {
            Ok((HumanAuthorityMode::Scoped, assigned))
        }
        (HumanAuthorityMode::Scoped, HumanAuthorityMode::Global) => {
            Ok((HumanAuthorityMode::Scoped, asserted))
        }
        (HumanAuthorityMode::Scoped, HumanAuthorityMode::Scoped) => {
            let intersection: Vec<String> = asserted
                .into_iter()
                .filter(|value| assigned.binary_search(value).is_ok())
                .collect();
            if intersection.is_empty() {
                Err(HumanAuthorityError::EmptyIntersection)
            } else {
                Ok((HumanAuthorityMode::Scoped, intersection))
            }
        }
        _ => Err(HumanAuthorityError::NotActive),
    }
}

/// Acquires the migration-199 provider sentinel and exact identity-key writer
/// order before any principal, key, link, session, or derived-token mutation.
pub(crate) async fn prepare_writer_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), HumanAuthorityError> {
    crate::principal_registry::prepare_writer_tx(tx, provider, issuer, subject).await?;
    Ok(())
}

/// Shared form used by derived-token resolution. Concurrent reads for the same
/// issuer remain possible, while every semantic identity/assignment writer
/// takes the exclusive form and therefore cannot overlap admission.
pub(crate) async fn prepare_reader_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), HumanAuthorityError> {
    crate::principal_registry::prepare_reader_tx(tx, provider, issuer, subject).await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct AssignmentRow {
    assignment_version: i64,
    assignment_status: String,
    role_allowlist: Vec<String>,
    site_authority_mode: String,
    site_scope: Vec<String>,
    environment_authority_mode: String,
    environment_scope: Vec<String>,
}

fn effective_from_row(
    principal_binding: crate::principal_registry::PrincipalBinding,
    row: AssignmentRow,
    assertion: &HumanAuthorityAssertion,
) -> Result<EffectiveHumanAuthority, HumanAuthorityError> {
    if row.assignment_version <= 0
        || HumanAssignmentStatus::parse(&row.assignment_status)? != HumanAssignmentStatus::Active
    {
        return Err(HumanAuthorityError::NotActive);
    }
    let assigned_roles = canonical_roles(&row.role_allowlist)?;
    // Unknown provider role/group names contribute no authority. They are
    // ignored before intersecting with the server-owned application catalog.
    let asserted_roles = canonical_asserted_roles(&assertion.roles)?;
    let roles: Vec<String> = asserted_roles
        .into_iter()
        .filter(|role| assigned_roles.binary_search(role).is_ok())
        .collect();
    if roles.is_empty() {
        return Err(HumanAuthorityError::EmptyIntersection);
    }
    let (site_mode, site_scope) = intersect_axis(
        assertion.site_mode,
        &assertion.site_scope,
        HumanAuthorityMode::parse(&row.site_authority_mode)?,
        &row.site_scope,
    )?;
    let (environment_mode, environment_scope) = intersect_axis(
        assertion.environment_mode,
        &assertion.environment_scope,
        HumanAuthorityMode::parse(&row.environment_authority_mode)?,
        &row.environment_scope,
    )?;
    Ok(EffectiveHumanAuthority {
        principal_binding,
        roles,
        site_mode,
        site_scope,
        environment_mode,
        environment_scope,
    })
}

pub(crate) async fn resolve_assignment_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    assertion: &HumanAuthorityAssertion,
) -> Result<EffectiveHumanAuthority, HumanAuthorityError> {
    let principal_binding =
        crate::principal_registry::resolve_active_binding_tx(tx, provider, issuer, subject).await?;
    let row = sqlx::query_as::<_, AssignmentRow>(
        "SELECT authority_version AS assignment_version, \
                CASE WHEN lifecycle_state = 'active' THEN 'active' ELSE 'revoked' END \
                    AS assignment_status, role_allowlist, \
                site_authority_mode, site_scope, environment_authority_mode, \
                environment_scope \
         FROM principals \
         WHERE principal_id = $1 AND lifecycle_version = $2 AND authority_version = $3 \
         FOR SHARE",
    )
    .bind(principal_binding.principal_id.into_uuid())
    .bind(principal_binding.principal_lifecycle_version)
    .bind(principal_binding.principal_authority_version)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(HumanAuthorityError::NotActive)?;
    effective_from_row(principal_binding, row, assertion)
}

fn normalize_spec(
    mut spec: HumanAuthorityAssignmentSpec,
) -> Result<HumanAuthorityAssignmentSpec, HumanAuthorityError> {
    if spec.updated_by.trim().is_empty() || spec.updated_by.len() > 512 {
        return Err(HumanAuthorityError::InvalidAssignment("updated_by"));
    }
    spec.role_allowlist = canonical_roles(&spec.role_allowlist)?;
    match spec.status {
        HumanAssignmentStatus::Active => {
            if spec.role_allowlist.is_empty() {
                return Err(HumanAuthorityError::InvalidAssignment("roles"));
            }
            spec.site_scope = validate_axis(spec.site_mode, &spec.site_scope)?;
            spec.environment_scope = validate_axis(spec.environment_mode, &spec.environment_scope)?;
        }
        HumanAssignmentStatus::Unknown => {
            if !spec.role_allowlist.is_empty()
                || spec.site_mode != HumanAuthorityMode::Unknown
                || spec.environment_mode != HumanAuthorityMode::Unknown
                || !spec.site_scope.is_empty()
                || !spec.environment_scope.is_empty()
            {
                return Err(HumanAuthorityError::InvalidAssignment("unknown shape"));
            }
        }
        HumanAssignmentStatus::Revoked => {
            if !spec.role_allowlist.is_empty()
                || spec.site_mode != HumanAuthorityMode::Revoked
                || spec.environment_mode != HumanAuthorityMode::Revoked
                || !spec.site_scope.is_empty()
                || !spec.environment_scope.is_empty()
            {
                return Err(HumanAuthorityError::InvalidAssignment("revoked shape"));
            }
        }
    }
    Ok(spec)
}

/// Reconciles one provider-qualified assignment into the opaque principal.
/// Authority changes advance the principal generation; revocation tombstones
/// the verified key/link instead of manufacturing a replacement principal.
pub(crate) async fn reconcile_assignment_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    issuer: &str,
    subject: &str,
    spec: HumanAuthorityAssignmentSpec,
    credential_authority_digest: Option<&[u8; 32]>,
) -> Result<bool, HumanAuthorityError> {
    prepare_writer_tx(tx, provider, issuer, subject).await?;
    let spec = normalize_spec(spec)?;
    if spec.status != HumanAssignmentStatus::Active {
        return crate::principal_registry::tombstone_key_tx(
            tx,
            provider,
            issuer,
            subject,
            spec.source_kind,
            &spec.updated_by,
        )
        .await
        .map_err(Into::into);
    }
    let credential_authority_digest = credential_authority_digest.ok_or(
        HumanAuthorityError::InvalidAssignment("credential authority digest"),
    )?;

    let authority = crate::principal_registry::InitialHumanAuthority {
        authority_digest: credential_authority_digest,
        roles: &spec.role_allowlist,
        site_mode: spec.site_mode.as_db(),
        site_scope: &spec.site_scope,
        environment_mode: spec.environment_mode.as_db(),
        environment_scope: &spec.environment_scope,
        created_by: &spec.updated_by,
    };
    let (binding, created) = crate::principal_registry::resolve_or_create_active_binding_tx(
        tx, provider, issuer, subject, &authority,
    )
    .await?;
    if created {
        return Ok(true);
    }
    let credential_changed = crate::principal_registry::reconcile_authority_digest_tx(
        tx,
        provider,
        issuer,
        subject,
        credential_authority_digest,
        &spec.updated_by,
    )
    .await?;

    let current = sqlx::query_as::<_, AssignmentRow>(
        "SELECT authority_version AS assignment_version, \
                CASE WHEN lifecycle_state = 'active' THEN 'active' ELSE 'revoked' END \
                    AS assignment_status, role_allowlist, \
                site_authority_mode, site_scope, environment_authority_mode, \
                environment_scope \
         FROM principals \
         WHERE principal_id = $1 \
         FOR UPDATE",
    )
    .bind(binding.principal_id.into_uuid())
    .fetch_one(&mut **tx)
    .await?;
    let unchanged = current.assignment_status == HumanAssignmentStatus::Active.as_db()
        && current.role_allowlist == spec.role_allowlist
        && current.site_authority_mode == spec.site_mode.as_db()
        && current.site_scope == spec.site_scope
        && current.environment_authority_mode == spec.environment_mode.as_db()
        && current.environment_scope == spec.environment_scope;
    if unchanged {
        return Ok(credential_changed);
    }

    sqlx::query(
        "UPDATE principals SET \
           lifecycle_version = CASE WHEN lifecycle_state = 'active' \
               THEN lifecycle_version ELSE lifecycle_version + 1 END, \
           authority_version = authority_version + 1, lifecycle_state = 'active', \
           role_allowlist = $2, site_authority_mode = $3, site_scope = $4, \
           environment_authority_mode = $5, environment_scope = $6, \
           tombstoned_at = NULL, updated_at = statement_timestamp() \
         WHERE principal_id = $1",
    )
    .bind(binding.principal_id.into_uuid())
    .bind(&spec.role_allowlist)
    .bind(spec.site_mode.as_db())
    .bind(&spec.site_scope)
    .bind(spec.environment_mode.as_db())
    .bind(&spec.environment_scope)
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

/// Provider-neutral seam for a governed assignment source. It is intentionally
/// repository-only until an authenticated administrative control plane is
/// supplied; provider claims/groups remain external trusted input and must be
/// read back before calling this boundary.
#[allow(dead_code)]
#[cfg(test)]
pub(crate) async fn persist_governed_assignment_with_digest(
    pool: &PgPool,
    provider: &str,
    issuer: &str,
    subject: &str,
    spec: HumanAuthorityAssignmentSpec,
    credential_authority_digest: &[u8; 32],
) -> Result<bool, HumanAuthorityError> {
    let mut tx = pool.begin().await?;
    let changed = reconcile_assignment_tx(
        &mut tx,
        provider,
        issuer,
        subject,
        spec,
        Some(credential_authority_digest),
    )
    .await?;
    tx.commit().await?;
    if changed {
        crate::session_lookup_admission::clear_positive_global();
    }
    Ok(changed)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) async fn persist_governed_assignment(
    pool: &PgPool,
    provider: &str,
    issuer: &str,
    subject: &str,
    spec: HumanAuthorityAssignmentSpec,
) -> Result<bool, HumanAuthorityError> {
    // Tests that only provision platform authority do not possess a verified
    // credential assertion yet. Allocate an opaque placeholder generation;
    // the first real callback rotates it to the keyed credential digest before
    // any session can be minted.
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    let mut authority_digest = [0_u8; 32];
    authority_digest[..16].copy_from_slice(first.as_bytes());
    authority_digest[16..].copy_from_slice(second.as_bytes());
    persist_governed_assignment_with_digest(
        pool,
        provider,
        issuer,
        subject,
        spec,
        &authority_digest,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> crate::principal_registry::PrincipalBinding {
        crate::principal_registry::PrincipalBinding {
            principal_id: "018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0"
                .parse()
                .expect("canonical principal id"),
            principal_lifecycle_version: 3,
            principal_authority_version: 7,
            principal_key_id: uuid::Uuid::from_u128(1),
            principal_key_version: 2,
            principal_link_id: uuid::Uuid::from_u128(2),
            principal_link_version: 4,
        }
    }

    fn row(
        roles: &[&str],
        site_mode: &str,
        sites: &[&str],
        environment_mode: &str,
        environments: &[&str],
    ) -> AssignmentRow {
        AssignmentRow {
            assignment_version: 7,
            assignment_status: "active".into(),
            role_allowlist: roles.iter().map(|value| (*value).into()).collect(),
            site_authority_mode: site_mode.into(),
            site_scope: sites.iter().map(|value| (*value).into()).collect(),
            environment_authority_mode: environment_mode.into(),
            environment_scope: environments.iter().map(|value| (*value).into()).collect(),
        }
    }

    #[test]
    fn role_and_cross_axis_scope_intersections_only_narrow() {
        let assertion = HumanAuthorityAssertion {
            roles: vec!["PlatformAdmin".into(), "Auditor".into()],
            site_mode: HumanAuthorityMode::Scoped,
            site_scope: vec!["SITE-A".into(), "SITE-B".into()],
            environment_mode: HumanAuthorityMode::Scoped,
            environment_scope: vec!["prod".into(), "stage".into()],
        };
        let effective = effective_from_row(
            binding(),
            row(
                &["Auditor", "Requester"],
                "scoped",
                &["SITE-B", "SITE-C"],
                "scoped",
                &["prod"],
            ),
            &assertion,
        )
        .unwrap();
        assert_eq!(effective.roles, ["Auditor"]);
        assert_eq!(effective.site_scope, ["SITE-B"]);
        assert_eq!(effective.environment_scope, ["prod"]);
    }

    #[test]
    fn explicit_global_is_preserved_but_empty_scoped_is_rejected() {
        let assertion = HumanAuthorityAssertion::role_assertion(&["Auditor".into()]);
        let effective = effective_from_row(
            binding(),
            row(&["Auditor"], "global", &[], "global", &[]),
            &assertion,
        )
        .unwrap();
        assert_eq!(effective.site_mode, HumanAuthorityMode::Global);
        assert!(effective.site_scope.is_empty());

        let error = effective_from_row(
            binding(),
            row(&["Auditor"], "scoped", &[], "global", &[]),
            &assertion,
        )
        .unwrap_err();
        assert!(matches!(error, HumanAuthorityError::InvalidAssignment(_)));
    }

    #[test]
    fn unknown_and_revoked_assignments_fail_closed() {
        let assertion = HumanAuthorityAssertion::role_assertion(&["Auditor".into()]);
        for status in ["unknown", "revoked"] {
            let mut assignment = row(&["Auditor"], "global", &[], "global", &[]);
            assignment.assignment_status = status.into();
            assert!(matches!(
                effective_from_row(binding(), assignment, &assertion),
                Err(HumanAuthorityError::NotActive)
            ));
        }
    }
}
