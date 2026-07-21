//! Permit-bearing repository for one canonical request instance.
//!
//! The public handler never receives a raw request-row loader. This adapter
//! revalidates exact credential authority, resolves the minimal authorization
//! projection, reserves the audit obligation, and mints an opaque permit while
//! retaining the same SQL transaction (or local-store lock). The full request
//! and its child plan are loaded only after the permit is rechecked against the
//! current projection.

use chrono::{Duration, Utc};
use ryuki_engine::auth::AuthSession;
use ryuki_engine::authorization::{
    Action, AuthorizationError, AuthorizationKernel, AuthorizationPermit, BindingDigest,
    BindingVersion, DecisionStatus, RequestReadResourceEvidence, ResolvedResource,
    ResourceLifecycle, ResourceSensitivity, TransactionContext, VerifiedPrincipal,
};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit::{self, AuditRecord, LocalAuditReservation};
use crate::contracts::{
    lock_local_request_for_typed_read, DbRequestRow, LocalRequestReadBinding,
    LocalRequestReadLease, REQUEST_COLUMNS,
};
use crate::database::get_db;
use crate::request_authority::{
    RequestAuthorityError, RequestReadAuthority, RevalidatedRequestReadAuthority,
};

const REQUEST_READ_PERMIT_SECONDS: i64 = 60;
const AUDIT_RESERVATION_VERSION: u64 = 1;

pub(crate) use currentness::Permit as CurrentRequestReadPermit;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestReadError {
    #[error("request not found")]
    NotFound,
    #[error("request-read principal is not entitled")]
    Forbidden,
    #[error("request-read credential is stale")]
    CredentialStale,
    #[error("request-read authority is unavailable")]
    AuthorityUnavailable,
    #[error("request authorization binding became stale")]
    Stale,
    #[error("request-read authorization failed")]
    Authorization(#[from] AuthorizationError),
    #[error("request-read database operation failed")]
    Database(#[from] sqlx::Error),
}

impl From<RequestAuthorityError> for RequestReadError {
    fn from(error: RequestAuthorityError) -> Self {
        match error {
            RequestAuthorityError::StaleCredential => Self::CredentialStale,
            RequestAuthorityError::InvalidBinding(_)
            | RequestAuthorityError::ApiTokenNotAdmitted => Self::AuthorityUnavailable,
            RequestAuthorityError::Database(error) => Self::Database(error),
            RequestAuthorityError::Authorization(error) => Self::Authorization(error),
        }
    }
}

pub(crate) enum RequestReadRecord {
    Database {
        row: DbRequestRow,
        steps: Vec<crate::repos::job_steps::JobStepRow>,
    },
    Local(ryuki_engine::models::Request),
}

#[derive(Clone)]
struct RequestReadBoundary {
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbRequestReadBindingRow {
    id: Uuid,
    resource_version: i64,
    status: String,
    stage: String,
    site: String,
    environment: String,
    requester: Option<String>,
    created_by: Option<String>,
}

enum RequestReadUnitOfWork {
    Database {
        transaction: Transaction<'static, Postgres>,
        request_id: Uuid,
    },
    Local {
        lease: LocalRequestReadLease,
        audit_reservation: LocalAuditReservation,
    },
}

/// Non-cloneable authorization grant retaining the exact unit of work that
/// produced its principal, resource, obligation receipt, and permit.
pub(crate) struct RequestReadGrant {
    kernel: AuthorizationKernel,
    boundary: RequestReadBoundary,
    principal: VerifiedPrincipal,
    transaction_context: TransactionContext,
    permit: AuthorizationPermit,
    unit_of_work: RequestReadUnitOfWork,
}

pub(crate) async fn authorize_read(
    session: &AuthSession,
    authority: &RequestReadAuthority,
    request_id: &str,
) -> Result<RequestReadGrant, RequestReadError> {
    match get_db() {
        Some(pool) => authorize_database_read(pool, session, authority, request_id).await,
        None => authorize_local_read(session, authority, request_id).await,
    }
}

async fn authorize_database_read(
    pool: &'static sqlx::PgPool,
    session: &AuthSession,
    authority: &RequestReadAuthority,
    request_id: &str,
) -> Result<RequestReadGrant, RequestReadError> {
    let request_id = Uuid::parse_str(request_id).map_err(|_| RequestReadError::NotFound)?;
    let mut transaction = pool.begin().await?;
    let revalidated = authority
        .prepare_request_row_lookup_tx(&mut transaction, Utc::now())
        .await?;
    revalidated.ensure_audit_session(session)?;
    let kernel = AuthorizationKernel::request_read_slice(revalidated.kernel_evidence())?;
    let boundary = boundary_from(&revalidated);
    let row = load_binding_row(&mut transaction, request_id)
        .await?
        .ok_or(RequestReadError::NotFound)?;
    let plan_state_digest =
        crate::repos::job_steps::load_plan_state_digest(&mut transaction, request_id).await?;
    let principal_expires_at = Utc::now() + Duration::seconds(REQUEST_READ_PERMIT_SECONDS);
    let principal_evidence = revalidated.principal_evidence(principal_expires_at)?;
    let permit_expires_at = principal_evidence.expires_at;
    let principal = kernel.bind_request_read_principal(principal_evidence)?;
    let resource = bind_database_resource(&kernel, &boundary, &row, plan_state_digest)?;
    let decision = kernel.decide(&principal, Action::RequestRead, &resource);
    if decision.status() == DecisionStatus::Deny {
        return Err(if decision.conceals_resource_existence() {
            RequestReadError::NotFound
        } else {
            RequestReadError::Forbidden
        });
    }

    let transaction_context = kernel.begin_transaction_context(permit_expires_at)?;
    let request_id_text = request_id.to_string();
    let audit_reservation = audit::record_audit_tx(
        &mut transaction,
        session,
        &AuditRecord {
            action: Action::RequestRead.as_str(),
            request_id: Some(&request_id_text),
            from_status: Some(&row.status),
            to_status: &row.status,
            from_stage: Some(&row.stage),
            to_stage: &row.stage,
            detail: json!({"authorization_boundary": "typed-request-read-v1"}),
            outcome: "success",
        },
    )
    .await?;
    let receipt = kernel.issue_audit_obligation_receipt(
        &decision,
        audit_reservation,
        BindingVersion::new(AUDIT_RESERVATION_VERSION)?,
        permit_expires_at,
    )?;
    let satisfied = kernel.satisfy_obligations(&decision, &[receipt])?;
    let permit = kernel.authorize_instance(satisfied, &transaction_context)?;

    Ok(RequestReadGrant {
        kernel,
        boundary,
        principal,
        transaction_context,
        permit,
        unit_of_work: RequestReadUnitOfWork::Database {
            transaction,
            request_id,
        },
    })
}

async fn authorize_local_read(
    session: &AuthSession,
    authority: &RequestReadAuthority,
    request_id: &str,
) -> Result<RequestReadGrant, RequestReadError> {
    let revalidated = authority.prepare_local_request_lookup(Utc::now())?;
    revalidated.ensure_audit_session(session)?;
    let kernel = AuthorizationKernel::request_read_slice(revalidated.kernel_evidence())?;
    let boundary = boundary_from(&revalidated);
    let lease = lock_local_request_for_typed_read(request_id)
        .await
        .ok_or(RequestReadError::NotFound)?;
    let row = lease.binding().ok_or(RequestReadError::NotFound)?;
    let principal_expires_at = Utc::now() + Duration::seconds(REQUEST_READ_PERMIT_SECONDS);
    let principal_evidence = revalidated.principal_evidence(principal_expires_at)?;
    let permit_expires_at = principal_evidence.expires_at;
    let principal = kernel.bind_request_read_principal(principal_evidence)?;
    let resource = bind_local_resource(&kernel, &boundary, &row)?;
    let decision = kernel.decide(&principal, Action::RequestRead, &resource);
    if decision.status() == DecisionStatus::Deny {
        return Err(if decision.conceals_resource_existence() {
            RequestReadError::NotFound
        } else {
            RequestReadError::Forbidden
        });
    }

    let transaction_context = kernel.begin_transaction_context(permit_expires_at)?;
    let status = row.status.as_str();
    let audit_reservation = audit::reserve_audit_local(
        session,
        &AuditRecord {
            action: Action::RequestRead.as_str(),
            request_id: Some(&row.id),
            from_status: Some(status),
            to_status: status,
            from_stage: None,
            to_stage: "read",
            detail: json!({"authorization_boundary": "typed-request-read-v1"}),
            outcome: "success",
        },
    )
    .await;
    let receipt = kernel.issue_audit_obligation_receipt(
        &decision,
        audit_reservation.evidence().clone(),
        BindingVersion::new(AUDIT_RESERVATION_VERSION)?,
        permit_expires_at,
    )?;
    let satisfied = kernel.satisfy_obligations(&decision, &[receipt])?;
    let permit = kernel.authorize_instance(satisfied, &transaction_context)?;

    Ok(RequestReadGrant {
        kernel,
        boundary,
        principal,
        transaction_context,
        permit,
        unit_of_work: RequestReadUnitOfWork::Local {
            lease,
            audit_reservation,
        },
    })
}

pub(crate) async fn read(grant: RequestReadGrant) -> Result<RequestReadRecord, RequestReadError> {
    let RequestReadGrant {
        kernel,
        boundary,
        principal,
        transaction_context,
        permit,
        unit_of_work,
    } = grant;

    match unit_of_work {
        RequestReadUnitOfWork::Database {
            mut transaction,
            request_id,
        } => {
            // The grant already carries a sealed permit. Load the exact values
            // that would be returned, keep child rows opaque, and compare that
            // immutable snapshot to the permit before releasing either sink.
            // Optimistic MVCC binding avoids deadlocks with orchestration's
            // plan-first writers while detecting every changed tuple.
            let row: DbRequestRow = sqlx::query_as(&format!(
                "SELECT {REQUEST_COLUMNS} FROM requests WHERE id = $1"
            ))
            .bind(request_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(RequestReadError::Stale)?;
            let current = binding_from_database_row(&row);
            let locked_plan =
                crate::repos::job_steps::load_plan_for_permit_read(&mut transaction, request_id)
                    .await?;
            let current_resource =
                bind_database_resource(&kernel, &boundary, &current, locked_plan.state_digest())?;
            let current_permit = currentness::verify(
                &kernel,
                &permit,
                &principal,
                &current_resource,
                &transaction_context,
            )?;

            let steps = locked_plan.into_rows(&current_permit);
            transaction.commit().await?;
            Ok(RequestReadRecord::Database { row, steps })
        }
        RequestReadUnitOfWork::Local {
            lease,
            audit_reservation,
        } => {
            let binding = lease.binding().ok_or(RequestReadError::Stale)?;
            let current_resource = bind_local_resource(&kernel, &boundary, &binding)?;
            let current_permit = currentness::verify(
                &kernel,
                &permit,
                &principal,
                &current_resource,
                &transaction_context,
            )?;
            let request = lease
                .authorized_request(&current_permit)
                .ok_or(RequestReadError::Stale)?
                .clone();
            audit_reservation.commit();
            Ok(RequestReadRecord::Local(request))
        }
    }
}

async fn load_binding_row(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Option<DbRequestReadBindingRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, resource_version, status, stage, site, environment, requester, created_by \
         FROM requests WHERE id = $1",
    )
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await
}

fn binding_from_database_row(row: &DbRequestRow) -> DbRequestReadBindingRow {
    DbRequestReadBindingRow {
        id: row.id,
        resource_version: row.resource_version,
        status: row.status.clone(),
        stage: row.stage.clone(),
        site: row.site.clone(),
        environment: row.environment.clone(),
        requester: row.requester.clone(),
        created_by: row.created_by.clone(),
    }
}

fn boundary_from(authority: &RevalidatedRequestReadAuthority<'_>) -> RequestReadBoundary {
    RequestReadBoundary {
        deployment_id: authority.deployment_id().to_string(),
        trust_domain_id: authority.trust_domain_id().to_string(),
        tenant_id: authority.tenant_id().map(str::to_string),
    }
}

fn bind_database_resource(
    kernel: &AuthorizationKernel,
    boundary: &RequestReadBoundary,
    row: &DbRequestReadBindingRow,
    state_digest: BindingDigest,
) -> Result<ResolvedResource, RequestReadError> {
    let owner = authoritative_owner(row.requester.as_deref(), row.created_by.as_deref())?;
    bind_resource(
        kernel,
        boundary,
        row.id.to_string(),
        row.resource_version,
        &row.site,
        &row.environment,
        owner,
        state_digest,
        database_lifecycle(&row.status),
    )
}

fn bind_local_resource(
    kernel: &AuthorizationKernel,
    boundary: &RequestReadBoundary,
    row: &LocalRequestReadBinding,
) -> Result<ResolvedResource, RequestReadError> {
    let owner = authoritative_owner(Some(&row.requester), Some(&row.owner))?;
    bind_resource(
        kernel,
        boundary,
        row.id.clone(),
        row.resource_version,
        &row.site,
        &row.environment,
        owner,
        crate::repos::job_steps::empty_plan_state_digest(),
        local_lifecycle(&row.status),
    )
}

#[allow(clippy::too_many_arguments)]
fn bind_resource(
    kernel: &AuthorizationKernel,
    boundary: &RequestReadBoundary,
    request_id: String,
    resource_version: i64,
    site: &str,
    environment: &str,
    owner: String,
    state_digest: BindingDigest,
    lifecycle_state: ResourceLifecycle,
) -> Result<ResolvedResource, RequestReadError> {
    let resource_version = u64::try_from(resource_version)
        .ok()
        .and_then(|value| BindingVersion::new(value).ok())
        .ok_or(RequestReadError::Authorization(
            AuthorizationError::InvalidBinding("request resource version"),
        ))?;
    Ok(
        kernel.bind_request_read_resource(RequestReadResourceEvidence {
            canonical_id: format!("request:{request_id}"),
            deployment_id: boundary.deployment_id.clone(),
            trust_domain_id: boundary.trust_domain_id.clone(),
            tenant_id: boundary.tenant_id.clone(),
            site_id: site.to_string(),
            environment_id: environment.to_string(),
            owner_principal_id: owner,
            resource_version,
            state_digest,
            // The registry fixes the request resource kind at confidential. A row
            // field cannot lower the registered sensitivity.
            sensitivity: ResourceSensitivity::Confidential,
            lifecycle_state,
        })?,
    )
}

fn authoritative_owner(
    preferred: Option<&str>,
    legacy_fallback: Option<&str>,
) -> Result<String, RequestReadError> {
    preferred
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            legacy_fallback
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_string)
        .ok_or(RequestReadError::NotFound)
}

fn database_lifecycle(status: &str) -> ResourceLifecycle {
    match status {
        "completed" | "retired" | "failed" | "rejected" | "cancelled" => {
            ResourceLifecycle::Terminal
        }
        "draft" | "intake" | "validated" | "planned" | "approved" | "locked" | "executing"
        | "executed" | "verifying" | "verified" | "protecting" | "operational" => {
            ResourceLifecycle::Active
        }
        _ => ResourceLifecycle::Unknown,
    }
}

fn local_lifecycle(status: &ryuki_engine::models::RequestStatus) -> ResourceLifecycle {
    use ryuki_engine::models::RequestStatus;
    match status {
        RequestStatus::Completed
        | RequestStatus::Retired
        | RequestStatus::Failed
        | RequestStatus::Rejected
        | RequestStatus::Cancelled => ResourceLifecycle::Terminal,
        RequestStatus::Draft
        | RequestStatus::Intake
        | RequestStatus::Validated
        | RequestStatus::Planned
        | RequestStatus::Approved
        | RequestStatus::Locked
        | RequestStatus::Executing
        | RequestStatus::Verifying
        | RequestStatus::Protecting
        | RequestStatus::Operational => ResourceLifecycle::Active,
    }
}

mod currentness {
    use super::*;

    /// Capability proving that the exact principal/resource pair still matches
    /// the sealed request-read permit in its retained unit of work. The private
    /// field is owned by this submodule, so pre-policy repository code cannot
    /// manufacture the capability used by the local full-record sink.
    pub(crate) struct Permit(());

    pub(super) fn verify(
        kernel: &AuthorizationKernel,
        permit: &AuthorizationPermit,
        principal: &VerifiedPrincipal,
        resource: &ResolvedResource,
        transaction: &TransactionContext,
    ) -> Result<Permit, RequestReadError> {
        kernel
            .ensure_instance_current_for(
                permit,
                Action::RequestRead,
                principal,
                resource,
                transaction,
            )
            .map(|()| Permit(()))
            .map_err(|error| match error {
                AuthorizationError::Expired | AuthorizationError::StaleBinding => {
                    RequestReadError::Stale
                }
                other => RequestReadError::Authorization(other),
            })
    }
}
