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

use crate::integration::{
    parse_persisted_credential_binding, parse_persisted_execution_mode,
    PersistedIntegrationConnectionError,
};
use ryuki_engine::integration_connections::IntegrationConnection;
use serde_json::Value;

/// SELECT column list for `integration_connections`. Mirrors the handler's
/// `CONN_COLUMNS` in `integration.rs`.
const CONN_COLUMNS: &str =
    "id, vendor_type, name, endpoint_url, site_scope, credential_source, credential_ref, \
     credential_secret_ref, credential_secret_ref_generation, \
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
    credential_secret_ref: Option<Value>,
    credential_secret_ref_generation: Option<i64>,
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
    fn try_into_model(self) -> Result<IntegrationConnection, PersistedIntegrationConnectionError> {
        let (credential_source, _) = parse_persisted_credential_binding(
            &self.credential_source,
            &self.credential_ref,
            self.credential_secret_ref,
            self.credential_secret_ref_generation,
        )?;
        Ok(IntegrationConnection {
            id: self.id,
            vendor_type: self.vendor_type,
            name: self.name,
            endpoint_url: self.endpoint_url,
            site_scope: self.site_scope,
            credential_source,
            credential_ref: self.credential_ref,
            status: self.status,
            readiness: self.readiness,
            execution_mode: parse_persisted_execution_mode(&self.execution_mode)?,
            last_test_at: self.last_test_at,
            last_test_result: self.last_test_result,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
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

    rows.into_iter()
        .map(IntegrationConnectionRow::try_into_model)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_engine::integration_connections::{CredentialSource, ExecutionMode};

    fn row(credential_source: &str) -> IntegrationConnectionRow {
        IntegrationConnectionRow {
            id: "ic-scheduler-source-test".to_string(),
            vendor_type: "vmware".to_string(),
            name: "Scheduler Source Test".to_string(),
            endpoint_url: "https://vcenter.test.example.com".to_string(),
            site_scope: None,
            credential_source: credential_source.to_string(),
            credential_ref: "fixture-reference".to_string(),
            credential_secret_ref: None,
            credential_secret_ref_generation: None,
            status: "configured".to_string(),
            readiness: "configured".to_string(),
            execution_mode: "static-dry-run".to_string(),
            last_test_at: None,
            last_test_result: None,
            created_by: "test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn scheduler_row_decoder_accepts_explicit_sources_and_rejects_unknown_values() {
        assert_eq!(
            row("vault")
                .try_into_model()
                .expect("explicit Vault source")
                .credential_source,
            CredentialSource::Vault
        );
        assert!(row("").try_into_model().is_err());
        assert!(row("future-provider").try_into_model().is_err());
        assert!(row(" env-var ").try_into_model().is_err());
    }

    #[test]
    fn scheduler_row_decoder_requires_an_explicit_valid_execution_mode() {
        for (raw, expected) in [
            ("static-dry-run", ExecutionMode::StaticDryRun),
            ("live", ExecutionMode::Live),
        ] {
            let mut row = row("vault");
            row.execution_mode = raw.to_string();
            assert_eq!(
                row.try_into_model()
                    .expect("explicit persisted execution mode")
                    .execution_mode,
                expected
            );
        }

        let raw = "future-mode-with-sensitive-marker-DO-NOT-LOG";
        let mut row = row("vault");
        row.execution_mode = raw.to_string();
        let error = row
            .try_into_model()
            .expect_err("unknown persisted execution mode must stop scheduler row decoding");

        assert!(matches!(
            &error,
            PersistedIntegrationConnectionError::ExecutionMode(_)
        ));
        assert_eq!(
            error.to_string(),
            "persisted integration execution mode is invalid"
        );
        assert!(!format!("{error:?}").contains(raw));
        assert!(!format!("{error:?}").contains("DO-NOT-LOG"));
    }
}
