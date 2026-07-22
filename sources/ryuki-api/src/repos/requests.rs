//! Permit-bearing repository for one canonical request instance.
//!
//! The public handler never receives a raw request-row loader. This adapter
//! revalidates exact credential authority, resolves the minimal authorization
//! projection, reserves the audit obligation, and mints an opaque permit while
//! retaining the same SQL transaction (or local-store lock). The full request
//! and its child plan are loaded only after the permit is rechecked against the
//! current projection.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use ryuki_core::PrincipalId;
use ryuki_engine::auth::AuthSession;
use ryuki_engine::authorization::{
    Action, AuthorizationError, AuthorizationKernel, AuthorizationPermit, BindingDigest,
    BindingVersion, CanonicalOwnerScope, DecisionStatus, ExplicitScope, QueryPermit,
    RequestReadResourceEvidence, RequestedQuery, ResolvedResource, ResourceLifecycle,
    ResourceSensitivity, SnapshotContext, TransactionContext, VerifiedPrincipal,
};
use serde_json::json;
use sqlx::{Acquire, FromRow, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::audit::{self, AuditRecord, LocalAuditReservation};
use crate::contracts::{
    lock_local_request_for_typed_read, lock_local_requests_for_typed_list, DbRequestRow,
    LocalRequestListLease, LocalRequestListRow, LocalRequestReadBinding, LocalRequestReadLease,
    REQUEST_COLUMNS,
};
use crate::database::get_db;
use crate::request_authority::{
    RequestAuthorityError, RequestReadAuthority, RevalidatedRequestReadAuthority,
};

const REQUEST_READ_PERMIT_SECONDS: i64 = 60;
const AUDIT_RESERVATION_VERSION: u64 = 1;
const REQUEST_LIST_PAGE_STATEMENT_TIMEOUT: &str = "500ms";
const REQUEST_LIST_COUNT_STATEMENT_TIMEOUT: &str = "250ms";
const REQUEST_LIST_COLUMNS: &str =
    "id, request_type, status, stage, site, environment, name, created_at";
pub(crate) const MAX_AUTHORIZED_REQUEST_COUNT: i64 = 10_001;

pub(crate) use currentness::Permit as CurrentRequestReadPermit;
pub(crate) use list_currentness::Permit as CurrentRequestListPermit;

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
    #[error("invalid request-list query: {0}")]
    InvalidQuery(&'static str),
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
        row: Box<DbRequestRow>,
        steps: Vec<crate::repos::job_steps::JobStepRow>,
    },
    Local(Box<ryuki_engine::models::Request>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestListSort {
    CreatedAt,
    UpdatedAt,
    Name,
    Status,
    Site,
    RequestType,
}

impl RequestListSort {
    fn parse(value: &str) -> Result<Self, RequestReadError> {
        match value {
            "created_at" => Ok(Self::CreatedAt),
            "updated_at" => Ok(Self::UpdatedAt),
            "name" => Ok(Self::Name),
            "status" => Ok(Self::Status),
            "site" => Ok(Self::Site),
            "request_type" => Ok(Self::RequestType),
            _ => Err(RequestReadError::InvalidQuery("unsupported sort")),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::Status => "status",
            Self::Site => "site",
            Self::RequestType => "request_type",
        }
    }

    const fn sql_column(self) -> &'static str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestListDirection {
    Asc,
    Desc,
}

impl RequestListDirection {
    fn parse(value: &str) -> Result<Self, RequestReadError> {
        match value {
            "ASC" => Ok(Self::Asc),
            "DESC" => Ok(Self::Desc),
            _ => Err(RequestReadError::InvalidQuery("unsupported sort direction")),
        }
    }

    pub(crate) const fn as_sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestListCursor {
    pub(crate) created_at: chrono::DateTime<Utc>,
    pub(crate) id: String,
}

#[derive(Debug)]
pub(crate) struct RequestListRequest {
    filters: BTreeMap<String, String>,
    limit: u32,
    offset: u64,
}

#[allow(clippy::too_many_arguments)]
impl RequestListRequest {
    pub(crate) fn new(
        status: Option<String>,
        site: Option<String>,
        environment: Option<String>,
        request_type: Option<String>,
        created_by: Option<String>,
        q: Option<String>,
        sort: RequestListSort,
        direction: RequestListDirection,
        include_total: bool,
        cursor: Option<RequestListCursor>,
        limit: usize,
        offset: usize,
    ) -> Result<Self, RequestReadError> {
        let limit = u32::try_from(limit)
            .map_err(|_| RequestReadError::InvalidQuery("request-list limit is too large"))?;
        let offset = u64::try_from(offset)
            .map_err(|_| RequestReadError::InvalidQuery("request-list offset is too large"))?;
        if limit > 100 || offset > 10_000 {
            return Err(RequestReadError::InvalidQuery(
                "request-list paging exceeds its supported bound",
            ));
        }
        if cursor.is_some() && (sort != RequestListSort::CreatedAt || offset != 0) {
            return Err(RequestReadError::InvalidQuery(
                "request-list cursor is incompatible with sort or offset",
            ));
        }
        let mut filters = BTreeMap::from([
            ("sort".to_string(), sort.as_str().to_string()),
            ("direction".to_string(), direction.as_sql().to_string()),
            ("include_total".to_string(), include_total.to_string()),
        ]);
        for (key, value) in [
            ("status", status),
            ("site_id", site),
            ("environment_id", environment),
            ("request_type", request_type),
            ("created_by_principal_id", created_by),
            ("q", q),
        ] {
            if let Some(value) = value {
                filters.insert(key.to_string(), value);
            }
        }
        if let Some(cursor) = cursor {
            filters.insert("cursor_created_at".into(), cursor.created_at.to_rfc3339());
            filters.insert("cursor_id".into(), cursor.id.to_string());
        }
        // Construct now so malformed caller criteria fail before any authority
        // revalidation, audit reservation, or database work begins.
        RequestedQuery::new(filters.clone(), limit, offset).map_err(|error| match error {
            AuthorizationError::InvalidQuery => {
                RequestReadError::InvalidQuery("request-list query contains an invalid criterion")
            }
            other => RequestReadError::Authorization(other),
        })?;
        Ok(Self {
            filters,
            limit,
            offset,
        })
    }

    fn into_requested_query(self) -> Result<RequestedQuery, AuthorizationError> {
        RequestedQuery::new(self.filters, self.limit, self.offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestListItem {
    pub(crate) request_id: String,
    pub(crate) request_type: String,
    pub(crate) status: String,
    pub(crate) name: String,
    pub(crate) site: String,
    pub(crate) environment: String,
    pub(crate) stage: String,
    pub(crate) created_at: chrono::DateTime<Utc>,
}

pub(crate) struct RequestListPage {
    pub(crate) items: Vec<RequestListItem>,
    pub(crate) total: Option<i64>,
    pub(crate) total_unavailable: bool,
    pub(crate) has_more: bool,
}

/// Least-privilege database projection for the collection endpoint. The list
/// repository never hydrates request payload, justification, lifecycle plan,
/// evidence, approval, or ownership metadata into application memory.
#[derive(sqlx::FromRow)]
struct DbRequestListRow {
    id: Uuid,
    request_type: String,
    status: String,
    stage: String,
    site: String,
    environment: String,
    name: String,
    created_at: chrono::DateTime<Utc>,
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
    principal_binding_state: String,
    owner_principal_id: Option<Uuid>,
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

enum RequestListUnitOfWork {
    Database(Transaction<'static, Postgres>),
    Local {
        lease: LocalRequestListLease,
        audit_reservation: LocalAuditReservation,
    },
}

/// Non-cloneable query grant retaining the exact snapshot that produced its
/// principal, collection resource, audit receipt, and sealed predicate.
pub(crate) struct RequestListGrant {
    kernel: AuthorizationKernel,
    principal: VerifiedPrincipal,
    resource: ResolvedResource,
    snapshot: SnapshotContext,
    permit: QueryPermit,
    unit_of_work: RequestListUnitOfWork,
}

pub(crate) async fn authorize_list(
    session: &AuthSession,
    authority: &RequestReadAuthority,
    request: RequestListRequest,
) -> Result<RequestListGrant, RequestReadError> {
    let requested = request.into_requested_query()?;
    match get_db() {
        Some(pool) => authorize_database_list(pool, session, authority, requested).await,
        None => authorize_local_list(session, authority, requested).await,
    }
}

async fn authorize_database_list(
    pool: &'static sqlx::PgPool,
    session: &AuthSession,
    authority: &RequestReadAuthority,
    requested: RequestedQuery,
) -> Result<RequestListGrant, RequestReadError> {
    let mut transaction = pool.begin().await?;
    // Authority locks, audit reservation, page, and optional count all share a
    // single stable snapshot. This must be the first statement in the unit of
    // work so PostgreSQL cannot establish a weaker snapshot first.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let revalidated = authority
        .prepare_request_row_lookup_tx(&mut transaction, Utc::now())
        .await?;
    let audit_session = revalidated.audit_session(session)?;
    let kernel = AuthorizationKernel::request_read_slice(revalidated.kernel_evidence())?;
    let principal_expires_at = Utc::now() + Duration::seconds(REQUEST_READ_PERMIT_SECONDS);
    let principal_evidence = revalidated.principal_evidence(principal_expires_at)?;
    let permit_expires_at = principal_evidence.expires_at;
    let principal = kernel.bind_request_read_principal(principal_evidence)?;
    let resource = kernel.bind_request_list_resource()?;
    let decision = kernel.decide(&principal, Action::RequestList, &resource);
    if decision.status() == DecisionStatus::Deny {
        return Err(RequestReadError::Forbidden);
    }
    let snapshot = kernel.begin_query_snapshot(&resource, permit_expires_at)?;
    let audit_reservation = audit::record_audit_tx(
        &mut transaction,
        &audit_session,
        &AuditRecord {
            action: Action::RequestList.as_str(),
            request_id: None,
            from_status: None,
            to_status: "listed",
            from_stage: None,
            to_stage: "read",
            detail: json!({"authorization_boundary": "typed-request-list-v1"}),
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
    let permit = kernel.authorize_query(satisfied, requested, &snapshot)?;

    Ok(RequestListGrant {
        kernel,
        principal,
        resource,
        snapshot,
        permit,
        unit_of_work: RequestListUnitOfWork::Database(transaction),
    })
}

async fn authorize_local_list(
    session: &AuthSession,
    authority: &RequestReadAuthority,
    requested: RequestedQuery,
) -> Result<RequestListGrant, RequestReadError> {
    let revalidated = authority.prepare_local_request_lookup(Utc::now())?;
    let audit_session = revalidated.audit_session(session)?;
    let kernel = AuthorizationKernel::request_read_slice(revalidated.kernel_evidence())?;
    let principal_expires_at = Utc::now() + Duration::seconds(REQUEST_READ_PERMIT_SECONDS);
    let principal_evidence = revalidated.principal_evidence(principal_expires_at)?;
    let permit_expires_at = principal_evidence.expires_at;
    let principal = kernel.bind_request_read_principal(principal_evidence)?;
    let resource = kernel.bind_request_list_resource()?;
    let decision = kernel.decide(&principal, Action::RequestList, &resource);
    if decision.status() == DecisionStatus::Deny {
        return Err(RequestReadError::Forbidden);
    }
    let snapshot = kernel.begin_query_snapshot(&resource, permit_expires_at)?;
    let lease = lock_local_requests_for_typed_list().await;
    let audit_reservation = audit::reserve_audit_local(
        &audit_session,
        &AuditRecord {
            action: Action::RequestList.as_str(),
            request_id: None,
            from_status: None,
            to_status: "listed",
            from_stage: None,
            to_stage: "read",
            detail: json!({"authorization_boundary": "typed-request-list-v1"}),
            outcome: "success",
        },
    )
    .await?;
    let receipt = kernel.issue_audit_obligation_receipt(
        &decision,
        audit_reservation.evidence().clone(),
        BindingVersion::new(AUDIT_RESERVATION_VERSION)?,
        permit_expires_at,
    )?;
    let satisfied = kernel.satisfy_obligations(&decision, &[receipt])?;
    let permit = kernel.authorize_query(satisfied, requested, &snapshot)?;

    Ok(RequestListGrant {
        kernel,
        principal,
        resource,
        snapshot,
        permit,
        unit_of_work: RequestListUnitOfWork::Local {
            lease,
            audit_reservation,
        },
    })
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
    let audit_session = revalidated.audit_session(session)?;
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
        &audit_session,
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
    let audit_session = revalidated.audit_session(session)?;
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
        &audit_session,
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
    .await?;
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
            let snapshot = sqlx::query(&format!(
                "SELECT {REQUEST_COLUMNS}, principal_binding_state, owner_principal_id \
                 FROM requests WHERE id = $1"
            ))
            .bind(request_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(RequestReadError::Stale)?;
            let row = DbRequestRow::from_row(&snapshot)?;
            let current = DbRequestReadBindingRow::from_row(&snapshot)?;
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
            Ok(RequestReadRecord::Database {
                row: Box::new(row),
                steps,
            })
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
            Ok(RequestReadRecord::Local(Box::new(request)))
        }
    }
}

#[derive(Clone)]
struct AuthorizedRequestListQuery {
    site_scope: ExplicitScope,
    environment_scope: ExplicitScope,
    owner_scope: CanonicalOwnerScope,
    status: Option<String>,
    site: Option<String>,
    environment: Option<String>,
    request_type: Option<String>,
    created_by: Option<String>,
    q: Option<String>,
    sort: RequestListSort,
    direction: RequestListDirection,
    include_total: bool,
    cursor: Option<RequestListCursor>,
    limit: usize,
    offset: usize,
}

fn authorized_list_query(
    permit: &QueryPermit,
) -> Result<AuthorizedRequestListQuery, RequestReadError> {
    if permit.action() != Action::RequestList {
        return Err(RequestReadError::Authorization(
            AuthorizationError::UnexpectedAction,
        ));
    }
    let filters = permit.filters();
    let optional = |key: &str| filters.get(key).cloned();
    let sort = RequestListSort::parse(filters.get("sort").ok_or(
        RequestReadError::InvalidQuery("request-list sort is missing"),
    )?)?;
    let direction = RequestListDirection::parse(filters.get("direction").ok_or(
        RequestReadError::InvalidQuery("request-list direction is missing"),
    )?)?;
    let include_total = match filters.get("include_total").map(String::as_str) {
        Some("true") => true,
        Some("false") => false,
        _ => {
            return Err(RequestReadError::InvalidQuery(
                "request-list total mode is invalid",
            ));
        }
    };
    let cursor = match (filters.get("cursor_created_at"), filters.get("cursor_id")) {
        (None, None) => None,
        (Some(created_at), Some(id)) => Some(RequestListCursor {
            created_at: chrono::DateTime::parse_from_rfc3339(created_at)
                .map_err(|_| RequestReadError::InvalidQuery("request-list cursor time is invalid"))?
                .with_timezone(&Utc),
            id: id.clone(),
        }),
        _ => {
            return Err(RequestReadError::InvalidQuery(
                "request-list cursor is incomplete",
            ));
        }
    };
    let limit = usize::try_from(permit.limit())
        .map_err(|_| RequestReadError::InvalidQuery("request-list limit is invalid"))?;
    let offset = usize::try_from(permit.offset())
        .map_err(|_| RequestReadError::InvalidQuery("request-list offset is invalid"))?;
    if limit > 100
        || offset > 10_000
        || cursor.is_some() && (sort != RequestListSort::CreatedAt || offset != 0)
        || matches!(
            permit.scope().owner_scope(),
            CanonicalOwnerScope::NotApplicable
        )
    {
        return Err(RequestReadError::InvalidQuery(
            "request-list permit exceeds the repository ceiling",
        ));
    }
    Ok(AuthorizedRequestListQuery {
        site_scope: permit.scope().site_scope().clone(),
        environment_scope: permit.scope().environment_scope().clone(),
        owner_scope: permit.scope().owner_scope().clone(),
        status: optional("status"),
        site: optional("site_id"),
        environment: optional("environment_id"),
        request_type: optional("request_type"),
        created_by: optional("created_by_principal_id"),
        q: optional("q"),
        sort,
        direction,
        include_total,
        cursor,
        limit,
        offset,
    })
}

pub(crate) async fn list(grant: RequestListGrant) -> Result<RequestListPage, RequestReadError> {
    let RequestListGrant {
        kernel,
        principal,
        resource,
        snapshot,
        permit,
        unit_of_work,
    } = grant;
    let query = authorized_list_query(&permit)?;

    match unit_of_work {
        RequestListUnitOfWork::Database(mut transaction) => {
            let mut page_builder = request_list_builder(&query, true)?;
            page_builder
                .push(" ORDER BY ")
                .push(query.sort.sql_column())
                .push(" ")
                .push(query.direction.as_sql())
                .push(", id ")
                .push(query.direction.as_sql())
                .push(" LIMIT ")
                .push_bind(i64::try_from(query.limit.saturating_add(1)).unwrap_or(i64::MAX));
            if query.cursor.is_none() {
                page_builder
                    .push(" OFFSET ")
                    .push_bind(i64::try_from(query.offset).unwrap_or(i64::MAX));
            }
            let mut rows = fetch_database_request_page(&mut transaction, page_builder).await?;
            let has_more = rows.len() > query.limit;
            if has_more {
                rows.truncate(query.limit);
            }

            let (total, total_unavailable) = if query.include_total {
                count_database_requests(&mut transaction, &query).await?
            } else {
                (None, false)
            };
            list_currentness::verify(&kernel, &permit, &principal, &resource, &snapshot)?;
            let items = rows.into_iter().map(database_list_item).collect();
            transaction.commit().await?;
            Ok(RequestListPage {
                items,
                total,
                total_unavailable,
                has_more,
            })
        }
        RequestListUnitOfWork::Local {
            lease,
            audit_reservation,
        } => {
            let current =
                list_currentness::verify(&kernel, &permit, &principal, &resource, &snapshot)?;
            let page = list_local_requests(&lease.authorized_rows(&current), &query)?;
            audit_reservation.commit();
            Ok(page)
        }
    }
}

fn request_list_builder(
    query: &AuthorizedRequestListQuery,
    include_cursor: bool,
) -> Result<QueryBuilder<'static, Postgres>, RequestReadError> {
    let mut builder =
        QueryBuilder::<Postgres>::new(format!("SELECT {REQUEST_LIST_COLUMNS} FROM requests"));
    push_request_list_predicates(&mut builder, query, include_cursor)?;
    Ok(builder)
}

async fn fetch_database_request_page(
    transaction: &mut Transaction<'static, Postgres>,
    mut builder: QueryBuilder<'static, Postgres>,
) -> Result<Vec<DbRequestListRow>, RequestReadError> {
    // Scope the attacker-influenced substring scan to a rollback-only
    // savepoint. Rolling the savepoint back after a successful SELECT discards
    // SET LOCAL as well, so the outer audit/currentness/commit work never
    // inherits the page-query timeout.
    let mut page_tx = transaction.begin().await?;
    if let Err(error) = sqlx::query("SELECT set_config('statement_timeout', $1, TRUE)")
        .bind(REQUEST_LIST_PAGE_STATEMENT_TIMEOUT)
        .execute(&mut *page_tx)
        .await
    {
        page_tx.rollback().await.ok();
        return Err(RequestReadError::Database(error));
    }
    match builder
        .build_query_as::<DbRequestListRow>()
        .fetch_all(&mut *page_tx)
        .await
    {
        Ok(rows) => {
            page_tx.rollback().await?;
            Ok(rows)
        }
        Err(error) => {
            page_tx.rollback().await.ok();
            if statement_timed_out(&error) {
                tracing::warn!(
                    timeout = REQUEST_LIST_PAGE_STATEMENT_TIMEOUT,
                    "authorized request-list page exceeded its statement budget"
                );
            }
            Err(RequestReadError::Database(error))
        }
    }
}

fn push_predicate_prefix(builder: &mut QueryBuilder<'static, Postgres>, first: &mut bool) {
    if *first {
        builder.push(" WHERE ");
        *first = false;
    } else {
        builder.push(" AND ");
    }
}

fn push_request_list_predicates(
    builder: &mut QueryBuilder<'static, Postgres>,
    query: &AuthorizedRequestListQuery,
    include_cursor: bool,
) -> Result<(), RequestReadError> {
    let mut first = true;
    push_predicate_prefix(builder, &mut first);
    builder.push("principal_binding_state = 'exact-v1'");
    match &query.owner_scope {
        CanonicalOwnerScope::Principal(principal_id) => {
            push_predicate_prefix(builder, &mut first);
            builder
                .push("owner_principal_id = ")
                .push_bind(principal_id.into_uuid());
        }
        CanonicalOwnerScope::Any => {}
        CanonicalOwnerScope::NotApplicable => {
            return Err(RequestReadError::InvalidQuery(
                "request-list owner scope is absent",
            ));
        }
    }
    if let Some(values) = query.site_scope.values() {
        push_predicate_prefix(builder, &mut first);
        builder
            .push("site = ANY(")
            .push_bind(values.iter().cloned().collect::<Vec<_>>())
            .push(")");
    }
    if let Some(values) = query.environment_scope.values() {
        push_predicate_prefix(builder, &mut first);
        builder
            .push("environment = ANY(")
            .push_bind(values.iter().cloned().collect::<Vec<_>>())
            .push(")");
    }
    for (column, value) in [
        ("status", &query.status),
        ("site", &query.site),
        ("environment", &query.environment),
        ("request_type", &query.request_type),
        ("created_by_principal_id::text", &query.created_by),
    ] {
        if let Some(value) = value {
            push_predicate_prefix(builder, &mut first);
            builder.push(column).push(" = ").push_bind(value.clone());
        }
    }
    if let Some(value) = &query.q {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        push_predicate_prefix(builder, &mut first);
        builder
            .push("name ILIKE '%' || ")
            .push_bind(escaped)
            .push(" || '%' ESCAPE '\\'");
    }
    if include_cursor {
        if let Some(cursor) = &query.cursor {
            push_predicate_prefix(builder, &mut first);
            let operator = match query.direction {
                RequestListDirection::Asc => ">",
                RequestListDirection::Desc => "<",
            };
            let cursor_id = Uuid::parse_str(&cursor.id)
                .map_err(|_| RequestReadError::InvalidQuery("request-list cursor id is invalid"))?;
            builder
                .push("(created_at, id) ")
                .push(operator)
                .push(" (")
                .push_bind(cursor.created_at)
                .push(", ")
                .push_bind(cursor_id)
                .push(")");
        }
    }
    Ok(())
}

async fn count_database_requests(
    transaction: &mut Transaction<'static, Postgres>,
    query: &AuthorizedRequestListQuery,
) -> Result<(Option<i64>, bool), RequestReadError> {
    let mut builder = request_count_builder(query)?;
    let mut count_tx = transaction.begin().await?;
    if let Err(error) = sqlx::query("SELECT set_config('statement_timeout', $1, TRUE)")
        .bind(REQUEST_LIST_COUNT_STATEMENT_TIMEOUT)
        .execute(&mut *count_tx)
        .await
    {
        count_tx.rollback().await.ok();
        return Err(RequestReadError::Database(error));
    }
    match builder
        .build_query_scalar::<i64>()
        .fetch_one(&mut *count_tx)
        .await
    {
        Ok(total) => {
            // A released savepoint would preserve SET LOCAL in the outer
            // transaction. Roll back this read-only savepoint so the 250ms
            // count budget cannot leak into currentness/audit commit work.
            count_tx.rollback().await?;
            Ok((Some(total), false))
        }
        Err(error) if statement_timed_out(&error) => {
            count_tx.rollback().await.ok();
            tracing::warn!(
                timeout = REQUEST_LIST_COUNT_STATEMENT_TIMEOUT,
                "optional authorized request-list total exceeded its statement budget"
            );
            Ok((None, true))
        }
        Err(error) => {
            count_tx.rollback().await.ok();
            Err(RequestReadError::Database(error))
        }
    }
}

fn request_count_builder(
    query: &AuthorizedRequestListQuery,
) -> Result<QueryBuilder<'static, Postgres>, RequestReadError> {
    let mut builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM (SELECT 1 FROM requests");
    push_request_list_predicates(&mut builder, query, false)?;
    builder
        .push(" LIMIT ")
        .push_bind(MAX_AUTHORIZED_REQUEST_COUNT)
        .push(") AS bounded_requests");
    Ok(builder)
}

fn statement_timed_out(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "57014")
}

fn database_list_item(row: DbRequestListRow) -> RequestListItem {
    RequestListItem {
        request_id: row.id.to_string(),
        request_type: row.request_type,
        status: row.status,
        name: row.name,
        site: row.site,
        environment: row.environment,
        stage: row.stage,
        created_at: row.created_at,
    }
}

fn list_local_requests(
    requests: &[LocalRequestListRow],
    query: &AuthorizedRequestListQuery,
) -> Result<RequestListPage, RequestReadError> {
    let q = query.q.as_deref().map(str::to_lowercase);
    let mut eligible = requests
        .iter()
        .filter(|request| {
            let owner = authoritative_local_owner(&request.owner).ok();
            let owner_visible = match (&query.owner_scope, owner) {
                (CanonicalOwnerScope::Any, Some(_)) => true,
                (CanonicalOwnerScope::Principal(expected), Some(actual)) => expected == &actual,
                _ => false,
            };
            owner_visible
                && query.site_scope.permits(Some(&request.site))
                && query.environment_scope.permits(Some(&request.environment))
                && query
                    .status
                    .as_deref()
                    .is_none_or(|value| request.status == value)
                && query
                    .site
                    .as_deref()
                    .is_none_or(|value| request.site == value)
                && query
                    .environment
                    .as_deref()
                    .is_none_or(|value| request.environment == value)
                && query
                    .request_type
                    .as_deref()
                    .is_none_or(|value| request.request_type == value)
                && query
                    .created_by
                    .as_deref()
                    .is_none_or(|value| request.created_by == value)
                && q.as_deref()
                    .is_none_or(|value| request.name.to_lowercase().contains(value))
        })
        .collect::<Vec<_>>();
    let total = i64::try_from(eligible.len()).unwrap_or(i64::MAX);
    eligible.sort_by(|left, right| compare_local_requests(left, right, query.sort));
    if query.direction == RequestListDirection::Desc {
        eligible.reverse();
    }
    if let Some(cursor) = &query.cursor {
        eligible.retain(|request| local_request_is_after_cursor(request, cursor, query.direction));
    }
    let start = query.offset.min(eligible.len());
    let probe_end = start
        .saturating_add(query.limit.saturating_add(1))
        .min(eligible.len());
    let mut page = eligible[start..probe_end].to_vec();
    let has_more = page.len() > query.limit;
    if has_more {
        page.truncate(query.limit);
    }
    let items = page
        .into_iter()
        .map(local_list_item)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RequestListPage {
        items,
        total: query.include_total.then_some(total),
        total_unavailable: false,
        has_more,
    })
}

fn compare_local_requests(
    left: &LocalRequestListRow,
    right: &LocalRequestListRow,
    sort: RequestListSort,
) -> Ordering {
    let primary = match sort {
        RequestListSort::CreatedAt => compare_rfc3339(&left.created_at, &right.created_at),
        RequestListSort::UpdatedAt => compare_rfc3339(&left.updated_at, &right.updated_at),
        RequestListSort::Name => left.name.cmp(&right.name),
        RequestListSort::Status => left.status.cmp(&right.status),
        RequestListSort::Site => left.site.cmp(&right.site),
        RequestListSort::RequestType => left.request_type.cmp(&right.request_type),
    };
    primary.then_with(|| left.id.cmp(&right.id))
}

fn compare_rfc3339(left: &str, right: &str) -> Ordering {
    match (
        chrono::DateTime::parse_from_rfc3339(left),
        chrono::DateTime::parse_from_rfc3339(right),
    ) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn local_request_is_after_cursor(
    request: &LocalRequestListRow,
    cursor: &RequestListCursor,
    direction: RequestListDirection,
) -> bool {
    let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(&request.created_at) else {
        return false;
    };
    let order = created_at
        .with_timezone(&Utc)
        .cmp(&cursor.created_at)
        .then_with(|| request.id.cmp(&cursor.id));
    match direction {
        RequestListDirection::Asc => order == Ordering::Greater,
        RequestListDirection::Desc => order == Ordering::Less,
    }
}

fn local_list_item(request: &LocalRequestListRow) -> Result<RequestListItem, RequestReadError> {
    let created_at = chrono::DateTime::parse_from_rfc3339(&request.created_at)
        .map_err(|_| RequestReadError::Stale)?
        .with_timezone(&Utc);
    Ok(RequestListItem {
        request_id: request.id.clone(),
        request_type: request.request_type.clone(),
        status: request.status.clone(),
        name: request.name.clone(),
        site: request.site.clone(),
        environment: request.environment.clone(),
        stage: request.stage.clone(),
        created_at,
    })
}

async fn load_binding_row(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Option<DbRequestReadBindingRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, resource_version, status, stage, site, environment, \
                principal_binding_state, owner_principal_id \
         FROM requests WHERE id = $1",
    )
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await
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
    // `request.read` follows the current opaque owner, not the maker/requester.
    // Creation initializes those identities together. Any future ownership
    // transfer must be a governed transition that advances resource_version;
    // this reader must never recover authority from either legacy label or the
    // immutable requester when the exact owner binding is absent.
    let owner = authoritative_database_owner(&row.principal_binding_state, row.owner_principal_id)?;
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
    let owner = authoritative_local_owner(&row.owner)?;
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
    owner: PrincipalId,
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

fn authoritative_database_owner(
    binding_state: &str,
    owner_principal_id: Option<Uuid>,
) -> Result<PrincipalId, RequestReadError> {
    if binding_state != "exact-v1" {
        return Err(RequestReadError::NotFound);
    }
    owner_principal_id
        .and_then(|value| PrincipalId::from_uuid(value).ok())
        .ok_or(RequestReadError::NotFound)
}

fn authoritative_local_owner(owner_principal_id: &str) -> Result<PrincipalId, RequestReadError> {
    owner_principal_id
        .parse::<PrincipalId>()
        .map_err(|_| RequestReadError::NotFound)
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

mod list_currentness {
    use super::*;

    /// Capability proving that the exact collection authority and sealed query
    /// plan are current in the retained SQL/local snapshot.
    pub(crate) struct Permit(());

    pub(super) fn verify(
        kernel: &AuthorizationKernel,
        permit: &QueryPermit,
        principal: &VerifiedPrincipal,
        resource: &ResolvedResource,
        snapshot: &SnapshotContext,
    ) -> Result<Permit, RequestReadError> {
        kernel
            .ensure_query_current_for(permit, Action::RequestList, principal, resource, snapshot)
            .map(|()| Permit(()))
            .map_err(|error| match error {
                AuthorizationError::Expired | AuthorizationError::StaleBinding => {
                    RequestReadError::Stale
                }
                other => RequestReadError::Authorization(other),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0";
    const REQUESTER: &str = "018f3f54-8f5e-7bb7-9f06-1f3cc6f819d1";

    #[test]
    fn quarantined_database_rows_never_recover_legacy_owner_text() {
        let owner = Uuid::parse_str(OWNER).expect("test owner UUID");

        assert!(matches!(
            authoritative_database_owner("legacy-quarantined", Some(owner)),
            Err(RequestReadError::NotFound)
        ));
        assert!(matches!(
            authoritative_database_owner("exact-v1", None),
            Err(RequestReadError::NotFound)
        ));
    }

    #[test]
    fn exact_database_owner_is_a_non_nil_internal_uuid() {
        let owner = Uuid::parse_str(OWNER).expect("test owner UUID");

        assert_eq!(
            authoritative_database_owner("exact-v1", Some(owner))
                .expect("exact owner")
                .to_string(),
            OWNER
        );
        assert!(matches!(
            authoritative_database_owner("exact-v1", Some(Uuid::nil())),
            Err(RequestReadError::NotFound)
        ));
    }

    #[test]
    fn local_rows_require_canonical_uuid_owners() {
        assert_eq!(
            authoritative_local_owner(OWNER)
                .expect("canonical local owner")
                .to_string(),
            OWNER
        );
        for legacy in [
            "shared-subject",
            "user@example.test",
            "018F3F54-8F5E-7BB7-9F06-1F3CC6F819D0",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(matches!(
                authoritative_local_owner(legacy),
                Err(RequestReadError::NotFound)
            ));
        }
    }

    fn local_query(owner_scope: CanonicalOwnerScope) -> AuthorizedRequestListQuery {
        AuthorizedRequestListQuery {
            site_scope: ExplicitScope::global(),
            environment_scope: ExplicitScope::global(),
            owner_scope,
            status: None,
            site: None,
            environment: None,
            request_type: None,
            created_by: None,
            q: None,
            sort: RequestListSort::CreatedAt,
            direction: RequestListDirection::Desc,
            include_total: true,
            cursor: None,
            limit: 50,
            offset: 0,
        }
    }

    fn local_list_row(request: &ryuki_engine::models::Request) -> LocalRequestListRow {
        LocalRequestListRow {
            id: request.id.clone(),
            request_type: request.request_type.to_string(),
            status: request.status.as_str().to_string(),
            name: request.requester.clone(),
            site: request.site.clone(),
            environment: request.environment.clone(),
            stage: "intake".into(),
            created_at: request.created_at.clone(),
            updated_at: request.updated_at.clone(),
            created_by: request.requester.clone(),
            owner: request.owner.clone(),
        }
    }

    #[test]
    fn request_list_rejects_malformed_filters_as_client_queries() {
        let error = RequestListRequest::new(
            None,
            None,
            None,
            None,
            None,
            Some("x".repeat(4097)),
            RequestListSort::CreatedAt,
            RequestListDirection::Desc,
            false,
            None,
            50,
            0,
        )
        .expect_err("overlong query filter must fail");
        assert!(matches!(error, RequestReadError::InvalidQuery(_)));
    }

    #[test]
    fn database_list_builder_selects_only_summary_fields() {
        let query = local_query(CanonicalOwnerScope::Principal(
            OWNER.parse().expect("owner principal"),
        ));
        let builder = request_list_builder(&query, true).expect("valid list query");
        let sql = builder.sql();
        assert!(sql.starts_with(&format!("SELECT {REQUEST_LIST_COLUMNS} FROM requests")));
        assert!(sql.contains("principal_binding_state = 'exact-v1'"));
        assert!(sql.contains("owner_principal_id ="));
        for forbidden in [
            "justification",
            "payload",
            "stages",
            "approval_route",
            "plan",
            "validation_results",
            "evidence_manifest_id",
        ] {
            assert!(
                !sql.contains(forbidden),
                "list projection must not hydrate {forbidden}: {sql}"
            );
        }
    }

    #[test]
    fn database_count_builder_is_predicate_bound_and_capped() {
        let query = local_query(CanonicalOwnerScope::Principal(
            OWNER.parse().expect("owner principal"),
        ));
        let builder = request_count_builder(&query).expect("valid count query");
        let sql = builder.sql();
        assert!(sql.starts_with("SELECT COUNT(*) FROM (SELECT 1 FROM requests"));
        assert!(sql.contains("principal_binding_state = 'exact-v1'"));
        assert!(sql.contains("owner_principal_id ="));
        assert!(sql.contains(" LIMIT $"));
        assert!(sql.ends_with(") AS bounded_requests"));
        assert_eq!(REQUEST_LIST_PAGE_STATEMENT_TIMEOUT, "500ms");
        assert_eq!(REQUEST_LIST_COUNT_STATEMENT_TIMEOUT, "250ms");
        assert_eq!(MAX_AUTHORIZED_REQUEST_COUNT, 10_001);
    }

    #[test]
    fn local_cursor_uses_the_same_created_at_and_id_tuple_order() {
        let created_at = "2026-07-15T12:00:00Z";
        let row = |id: &str| LocalRequestListRow {
            id: id.into(),
            request_type: "server-deployment".into(),
            status: "draft".into(),
            name: "request".into(),
            site: "DEFRA".into(),
            environment: "production".into(),
            stage: "intake".into(),
            created_at: created_at.into(),
            updated_at: created_at.into(),
            created_by: REQUESTER.into(),
            owner: OWNER.into(),
        };
        let before = row("request-a");
        let after = row("request-c");
        let cursor = RequestListCursor {
            created_at: chrono::DateTime::parse_from_rfc3339(created_at)
                .unwrap()
                .with_timezone(&Utc),
            id: "request-b".into(),
        };

        assert!(local_request_is_after_cursor(
            &after,
            &cursor,
            RequestListDirection::Asc
        ));
        assert!(!local_request_is_after_cursor(
            &before,
            &cursor,
            RequestListDirection::Asc
        ));
        assert!(local_request_is_after_cursor(
            &before,
            &cursor,
            RequestListDirection::Desc
        ));
        assert!(!local_request_is_after_cursor(
            &after,
            &cursor,
            RequestListDirection::Desc
        ));
    }

    #[test]
    fn local_request_list_uses_current_owner_not_immutable_requester() {
        let mut request = ryuki_engine::request_lifecycle::create_request(
            "windows-server-deployment",
            ryuki_engine::models::RequestType::ServerDeployment,
            REQUESTER,
            OWNER,
            "DEFRA",
            "production",
            "standard",
        )
        .expect("valid local request");
        request.id = "request-owner-transfer".into();
        let request = local_list_row(&request);

        let requester_page = list_local_requests(
            std::slice::from_ref(&request),
            &local_query(CanonicalOwnerScope::Principal(
                REQUESTER.parse().expect("requester principal"),
            )),
        )
        .expect("requester query executes");
        assert!(requester_page.items.is_empty());
        assert_eq!(requester_page.total, Some(0));

        let owner_page = list_local_requests(
            std::slice::from_ref(&request),
            &local_query(CanonicalOwnerScope::Principal(
                OWNER.parse().expect("owner principal"),
            )),
        )
        .expect("owner query executes");
        assert_eq!(owner_page.items.len(), 1);
        assert_eq!(owner_page.total, Some(1));
    }

    #[test]
    fn local_request_list_hides_noncanonical_owner_bindings_even_from_read_any() {
        let mut request = ryuki_engine::request_lifecycle::create_request(
            "windows-server-deployment",
            ryuki_engine::models::RequestType::ServerDeployment,
            REQUESTER,
            "legacy-provider-subject",
            "DEFRA",
            "production",
            "standard",
        )
        .expect("valid local request");
        request.id = "request-quarantined-owner".into();
        let request = local_list_row(&request);

        let page = list_local_requests(&[request], &local_query(CanonicalOwnerScope::Any))
            .expect("read-any query executes");
        assert!(page.items.is_empty());
        assert_eq!(page.total, Some(0));
    }
}
