//! Repository functions for `integration_connections` used by the durable
//! scheduler's `connection_health_sweep` (#19).
//!
//! These are executor-generic (work with both `&PgPool` and `&mut *tx`) so the
//! sweep can list, append, and refresh INSIDE its tick transaction — keeping the
//! whole sweep atomic with the schedule's savepoint (a failure rolls back).
//!
//! NEVER touches secret material: `credential_ref` is a vault path / env key
//! names / secret-row FK, and the persisted health-check `message` is the stub's
//! secret-free output (it names the credential SOURCE type, never the ref).

use ryuki_engine::integration_connections::{
    CredentialSource, ExecutionMode, IntegrationConnection,
};

/// SELECT column list for `integration_connections`. Mirrors the handler's
/// `CONN_COLUMNS` in `integration.rs`.
const CONN_COLUMNS: &str =
    "id, vendor_type, name, endpoint_url, site_scope, credential_source, credential_ref, \
     status, readiness, execution_mode, last_test_at, last_test_result, created_by, \
     created_at, updated_at";

/// One `integration_connections` row. Decodes into the engine model.
#[derive(sqlx::FromRow)]
struct IntegrationConnectionRow {
    id: String,
    vendor_type: String,
    name: String,
    endpoint_url: String,
    site_scope: Option<String>,
    credential_source: String,
    credential_ref: String,
    status: String,
    readiness: String,
    execution_mode: String,
    last_test_at: Option<String>,
    last_test_result: Option<String>,
    created_by: String,
    created_at: String,
    updated_at: String,
}

impl IntegrationConnectionRow {
    fn into_model(self) -> IntegrationConnection {
        IntegrationConnection {
            id: self.id,
            vendor_type: self.vendor_type,
            name: self.name,
            endpoint_url: self.endpoint_url,
            site_scope: self.site_scope,
            credential_source: CredentialSource::parse(&self.credential_source)
                .unwrap_or(CredentialSource::EnvVar),
            credential_ref: self.credential_ref,
            status: self.status,
            readiness: self.readiness,
            execution_mode: ExecutionMode::parse(&self.execution_mode)
                .unwrap_or(ExecutionMode::StaticDryRun),
            last_test_at: self.last_test_at,
            last_test_result: self.last_test_result,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// List EVERY integration connection for the platform-wide health sweep
/// (`connection_health_sweep`). There is no `enabled` column on
/// `integration_connections` — the sweep probes every connection. Executor-generic
/// so the scheduler can run it INSIDE its tick transaction (pass `&mut *tx`),
/// keeping the sweep atomic with its savepoint.
pub async fn list_all_connections<'e, E>(
    executor: E,
) -> Result<Vec<IntegrationConnection>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<IntegrationConnectionRow> = sqlx::query_as(&format!(
        "SELECT {CONN_COLUMNS} FROM integration_connections ORDER BY id"
    ))
    .fetch_all(executor)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

/// Append one `connection_health_checks` history row. Mirrors the on-demand
/// probe's INSERT in `integration.rs`. `message` MUST be the stub's secret-free
/// output. Executor-generic so the scheduler can write it on `&mut *tx`.
pub async fn insert_health_check<'e, E>(
    executor: E,
    connection_id: &str,
    endpoint_status: &str,
    credential_status: &str,
    message: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO connection_health_checks \
         (id, connection_id, endpoint_status, credential_status, message) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(connection_id)
    .bind(endpoint_status)
    .bind(credential_status)
    .bind(message)
    .execute(executor)
    .await?;
    Ok(())
}

/// Refresh a connection's `last_test_at` / `last_test_result`. Mirrors the
/// on-demand probe so the integrations list shows the scheduled freshness (the
/// portal table reads those columns). Executor-generic so the scheduler can write
/// it on `&mut *tx`.
pub async fn update_last_test<'e, E>(
    executor: E,
    connection_id: &str,
    tested_at: &str,
    result: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE integration_connections \
         SET last_test_at = $1, last_test_result = $2 WHERE id = $3",
    )
    .bind(tested_at)
    .bind(result)
    .bind(connection_id)
    .execute(executor)
    .await?;
    Ok(())
}
