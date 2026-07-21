//! Repository functions for degradation mode site and component status.
//!
//! Reads from `site_status` and `component_status` tables (migration 025).
//! Mutation functions require a caller-owned SQL transaction so both status
//! updates and the audit insert commit atomically.

use ryuki_engine::degradation_mode::{
    AdapterComponentStatus, ComponentStatus, SiteDegradationState, SiteStatus,
};
use sqlx::PgPool;

/// Opaque proof that the caller's current database transaction acquired the
/// exact active, healthy, dependency-up, fresh site execution authority.
///
/// Construction is private to this repository module.  Callers may persist the
/// epoch but cannot fabricate a successful fence from a raw integer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LiveSiteExecutionFence {
    authority_epoch: i64,
}

impl LiveSiteExecutionFence {
    pub(crate) fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
}

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct SiteStatusRow {
    pub site: String,
    pub state: String,
    pub api_status: String,
    pub db_status: String,
    pub degradation_reason: Option<String>,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct ComponentStatusRow {
    pub site: String,
    pub adapter_name: String,
    pub status: String,
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

fn build_site_status(row: SiteStatusRow, components: &[ComponentStatusRow]) -> SiteStatus {
    let site_components: Vec<&ComponentStatusRow> =
        components.iter().filter(|c| c.site == row.site).collect();

    let adapter_status = fold_adapter_status(site_components);

    SiteStatus {
        site: row.site,
        state: SiteDegradationState::from_str(&row.state),
        api_status: ComponentStatus::from_str(&row.api_status),
        db_status: ComponentStatus::from_str(&row.db_status),
        adapter_status,
        degradation_reason: row.degradation_reason,
        last_check: row.last_check.to_rfc3339(),
    }
}

fn fold_adapter_status(components: Vec<&ComponentStatusRow>) -> AdapterComponentStatus {
    let mut result = AdapterComponentStatus::default();
    for c in components {
        let status = ComponentStatus::from_str(&c.status);
        match c.adapter_name.as_str() {
            "vmware" => result.vmware = status,
            "hyperv" => result.hyperv = status,
            "proxmox" => result.proxmox = status,
            "nutanix" => result.nutanix = status,
            "xen" => result.xen = status,
            "kvm" => result.kvm = status,
            "veeam" => result.veeam = status,
            "zabbix" => result.zabbix = status,
            "servicenow" => result.servicenow = status,
            "commvault" => result.commvault = status,
            "rubrik" => result.rubrik = status,
            "cohesity" => result.cohesity = status,
            "netbackup" => result.netbackup = status,
            _ => {}
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Read functions
// ---------------------------------------------------------------------------

pub async fn list_site_statuses(pool: &PgPool) -> Result<Vec<SiteStatus>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let active_site_status_missing: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM site_registry AS registry \
             LEFT JOIN site_status AS status ON status.site = registry.unlocode \
             WHERE registry.active = TRUE AND status.site IS NULL \
         )",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if active_site_status_missing {
        transaction.rollback().await?;
        return Err(sqlx::Error::Protocol(
            "an active site has no canonical degradation status".into(),
        ));
    }

    let site_rows: Vec<SiteStatusRow> = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         ORDER BY site",
    )
    .fetch_all(&mut *transaction)
    .await?;

    if site_rows.is_empty() {
        transaction.rollback().await?;
        return Ok(vec![]);
    }

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         ORDER BY site, adapter_name",
    )
    .fetch_all(&mut *transaction)
    .await?;

    transaction.commit().await?;

    let result = site_rows
        .into_iter()
        .map(|row| build_site_status(row, &component_rows))
        .collect();

    Ok(result)
}

pub async fn get_site_status(pool: &PgPool, site: &str) -> Result<Option<SiteStatus>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let row: Option<SiteStatusRow> = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         WHERE site = $1",
    )
    .bind(site)
    .fetch_optional(&mut *transaction)
    .await?;

    let row = match row {
        None => {
            transaction.rollback().await?;
            return Ok(None);
        }
        Some(r) => r,
    };

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         WHERE site = $1 \
         ORDER BY adapter_name",
    )
    .bind(site)
    .fetch_all(&mut *transaction)
    .await?;

    transaction.commit().await?;

    Ok(Some(build_site_status(row, &component_rows)))
}

/// Acquire the live-mutation site fence on the caller-owned transaction.
///
/// The database function takes a share lock on the site's canonical authority
/// mutex row. Registry and VMware writers serialize through that same row and
/// advance its epoch when authority changes. `None` is deliberately value-free:
/// it covers missing/inactive authority, every state other than exact
/// `healthy/up/up`, an absent or non-up VMware observation, and stale/future
/// observations.
pub(crate) async fn acquire_live_site_execution_fence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    site: &str,
) -> Result<Option<LiveSiteExecutionFence>, sqlx::Error> {
    let authority_epoch: Option<i64> =
        sqlx::query_scalar("SELECT public.ryuki_acquire_live_site_execution_epoch($1)")
            .bind(site)
            .fetch_one(&mut **transaction)
            .await?;

    Ok(authority_epoch.map(|authority_epoch| LiveSiteExecutionFence { authority_epoch }))
}

/// Reacquire and compare a stored live-site authority epoch in the caller's
/// current transaction.  A missing stored binding is never current.
pub(crate) async fn live_site_execution_fence_is_current(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    site: &str,
    expected_authority_epoch: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let Some(expected_authority_epoch) = expected_authority_epoch else {
        return Ok(false);
    };
    let current = acquire_live_site_execution_fence(transaction, site).await?;
    Ok(current
        .as_ref()
        .is_some_and(|fence| fence.authority_epoch() == expected_authority_epoch))
}

// ---------------------------------------------------------------------------
// Mutation functions (caller holds the transaction)
// ---------------------------------------------------------------------------

pub async fn enter(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    site: &str,
    reason: &str,
) -> Result<Option<SiteStatus>, sqlx::Error> {
    // Component writers acquire their component row before the migration-198
    // trigger acquires the site's authority mutex. Lock the complete component
    // set first, in canonical order, so a concurrent refresh can never form a
    // component -> site / site -> component cycle with this bulk transition.
    let _: Vec<i32> = sqlx::query_scalar(
        "SELECT 1 FROM component_status \
         WHERE site = $1 ORDER BY adapter_name FOR UPDATE",
    )
    .bind(site)
    .fetch_all(&mut **transaction)
    .await?;

    sqlx::query(
        "UPDATE component_status \
         SET status = 'degraded', last_check = statement_timestamp() \
         WHERE site = $1",
    )
    .bind(site)
    .execute(&mut **transaction)
    .await?;

    let rows_affected = sqlx::query(
        "UPDATE site_status \
         SET state = 'degraded', \
             api_status = 'degraded', \
             db_status = 'degraded', \
             degradation_reason = $2, \
             last_check = NOW(), \
             updated_at = NOW() \
         WHERE site = $1",
    )
    .bind(site)
    .bind(reason)
    .execute(&mut **transaction)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Ok(None);
    }

    // Re-read the updated row to return the persisted state.
    let row: SiteStatusRow = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         WHERE site = $1",
    )
    .bind(site)
    .fetch_one(&mut **transaction)
    .await?;

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         WHERE site = $1 \
         ORDER BY adapter_name",
    )
    .bind(site)
    .fetch_all(&mut **transaction)
    .await?;

    Ok(Some(build_site_status(row, &component_rows)))
}

pub async fn exit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    site: &str,
) -> Result<Option<SiteStatus>, sqlx::Error> {
    let _: Vec<i32> = sqlx::query_scalar(
        "SELECT 1 FROM component_status \
         WHERE site = $1 ORDER BY adapter_name FOR UPDATE",
    )
    .bind(site)
    .fetch_all(&mut **transaction)
    .await?;

    sqlx::query(
        "UPDATE component_status \
         SET status = 'up', last_check = statement_timestamp() \
         WHERE site = $1",
    )
    .bind(site)
    .execute(&mut **transaction)
    .await?;

    let rows_affected = sqlx::query(
        "UPDATE site_status \
         SET state = 'recovering', \
             api_status = 'up', \
             db_status = 'up', \
             degradation_reason = 'Site marked as recovering, exiting degradation mode', \
             last_check = NOW(), \
             updated_at = NOW() \
         WHERE site = $1",
    )
    .bind(site)
    .execute(&mut **transaction)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Ok(None);
    }

    let row: SiteStatusRow = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         WHERE site = $1",
    )
    .bind(site)
    .fetch_one(&mut **transaction)
    .await?;

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         WHERE site = $1 \
         ORDER BY adapter_name",
    )
    .bind(site)
    .fetch_all(&mut **transaction)
    .await?;

    Ok(Some(build_site_status(row, &component_rows)))
}

#[cfg(test)]
mod live_site_execution_fence_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static SITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    async fn migrated_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()
            .expect("RYUKI_DATABASE_URL is set but the DB connection failed");
        crate::database::run_migrations(pool)
            .await
            .expect("apply embedded migrations");
        Some(pool)
    }

    fn unique_site(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let sequence = SITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        format!("T198-{label}-{nanos}-{sequence}")
    }

    async fn insert_registry_site(pool: &PgPool, site: &str, active: bool) {
        sqlx::query(
            "INSERT INTO site_registry \
                 (unlocode, name, country, country_code, timezone, active, code_system) \
             VALUES ($1, 'Migration 198 fence test', 'Test', 'ZZ', 'UTC', $2, 'custom')",
        )
        .bind(site)
        .bind(active)
        .execute(pool)
        .await
        .expect("insert custom test site");
    }

    async fn insert_site_status(pool: &PgPool, site: &str) {
        sqlx::query(
            "INSERT INTO site_status (site, last_check, updated_at) \
             VALUES ($1, NOW(), NOW())",
        )
        .bind(site)
        .execute(pool)
        .await
        .expect("insert recovering site status authority");
        sqlx::query(
            "UPDATE site_status \
             SET state = 'healthy', api_status = 'up', db_status = 'up', \
                 degradation_reason = NULL, last_check = NOW(), updated_at = NOW() \
             WHERE site = $1",
        )
        .bind(site)
        .execute(pool)
        .await
        .expect("promote site status after a fresh recovery observation");
    }

    async fn insert_vmware_status(pool: &PgPool, site: &str) {
        sqlx::query(
            "INSERT INTO component_status (site, adapter_name, status, last_check) \
             VALUES ($1, 'vmware', 'up', NOW())",
        )
        .bind(site)
        .execute(pool)
        .await
        .expect("insert fresh VMware status");
    }

    async fn provision_safe_site(pool: &PgPool, site: &str) {
        insert_registry_site(pool, site, true).await;
        insert_site_status(pool, site).await;
        insert_vmware_status(pool, site).await;
    }

    async fn set_site_health(
        pool: &PgPool,
        site: &str,
        state: &str,
        api_status: &str,
        db_status: &str,
        observation_age_seconds: i64,
    ) {
        sqlx::query(
            "UPDATE site_status \
             SET state = $2, api_status = $3, db_status = $4, \
                 last_check = NOW() - ($5::BIGINT * INTERVAL '1 second'), \
                 updated_at = NOW() \
             WHERE site = $1",
        )
        .bind(site)
        .bind(state)
        .bind(api_status)
        .bind(db_status)
        .bind(observation_age_seconds)
        .execute(pool)
        .await
        .expect("update site health fixture");
    }

    async fn set_vmware_health(
        pool: &PgPool,
        site: &str,
        status: &str,
        observation_age_seconds: i64,
    ) {
        sqlx::query(
            "UPDATE component_status \
             SET status = $2, \
                 last_check = NOW() - ($3::BIGINT * INTERVAL '1 second') \
             WHERE site = $1 AND adapter_name = 'vmware'",
        )
        .bind(site)
        .bind(status)
        .bind(observation_age_seconds)
        .execute(pool)
        .await
        .expect("update VMware health fixture");
    }

    async fn acquired_epoch(pool: &PgPool, site: &str) -> Option<i64> {
        let mut transaction = pool.begin().await.expect("begin fence transaction");
        let epoch = acquire_live_site_execution_fence(&mut transaction, site)
            .await
            .expect("acquire live-site execution fence")
            .map(|fence| fence.authority_epoch());
        transaction
            .rollback()
            .await
            .expect("release test fence transaction");
        epoch
    }

    async fn epoch_is_current(pool: &PgPool, site: &str, epoch: i64) -> bool {
        let mut transaction = pool.begin().await.expect("begin fence transaction");
        let current = live_site_execution_fence_is_current(&mut transaction, site, Some(epoch))
            .await
            .expect("compare live-site execution fence");
        transaction
            .rollback()
            .await
            .expect("release test fence transaction");
        current
    }

    async fn deactivate_site(pool: &PgPool, site: &str) {
        sqlx::query("UPDATE site_registry SET active = FALSE WHERE unlocode = $1")
            .bind(site)
            .execute(pool)
            .await
            .expect("deactivate custom test site");
    }

    fn assert_check_violation(error: &sqlx::Error) {
        let code = error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .map(|code| code.into_owned());
        assert_eq!(code.as_deref(), Some("23514"));
    }

    #[tokio::test]
    async fn acquisition_requires_exact_fresh_canonical_site_authority() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = migrated_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let safe_site = unique_site("SEMANTICS");
        provision_safe_site(pool, &safe_site).await;
        assert!(acquired_epoch(pool, &safe_site).await.is_some());

        let absent_site = unique_site("ABSENT");
        assert_eq!(acquired_epoch(pool, &absent_site).await, None);

        let missing_status_site = unique_site("NO-STATUS");
        insert_registry_site(pool, &missing_status_site, true).await;
        assert_eq!(acquired_epoch(pool, &missing_status_site).await, None);

        let missing_vmware_site = unique_site("NO-VMWARE");
        insert_registry_site(pool, &missing_vmware_site, true).await;
        insert_site_status(pool, &missing_vmware_site).await;
        assert_eq!(acquired_epoch(pool, &missing_vmware_site).await, None);

        sqlx::query("UPDATE site_registry SET active = FALSE WHERE unlocode = $1")
            .bind(&safe_site)
            .execute(pool)
            .await
            .expect("deactivate site for acquisition check");
        assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        sqlx::query("UPDATE site_registry SET active = TRUE WHERE unlocode = $1")
            .bind(&safe_site)
            .execute(pool)
            .await
            .expect("reactivate site for acquisition checks");

        for state in ["recovering", "degraded", "unreachable"] {
            set_site_health(pool, &safe_site, state, "up", "up", 0).await;
            assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        }
        for api_status in ["degraded", "down"] {
            set_site_health(pool, &safe_site, "healthy", api_status, "up", 0).await;
            assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        }
        for db_status in ["degraded", "down"] {
            set_site_health(pool, &safe_site, "healthy", "up", db_status, 0).await;
            assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        }

        set_site_health(pool, &safe_site, "healthy", "up", "up", 0).await;
        for vmware_status in ["degraded", "down"] {
            set_vmware_health(pool, &safe_site, vmware_status, 0).await;
            assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        }

        set_vmware_health(pool, &safe_site, "up", 300).await;
        assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        set_vmware_health(pool, &safe_site, "up", 290).await;
        assert!(acquired_epoch(pool, &safe_site).await.is_some());
        set_site_health(pool, &safe_site, "healthy", "up", "up", 300).await;
        assert_eq!(acquired_epoch(pool, &safe_site).await, None);
        set_site_health(pool, &safe_site, "healthy", "up", "up", 290).await;
        assert!(acquired_epoch(pool, &safe_site).await.is_some());

        deactivate_site(pool, &safe_site).await;
        deactivate_site(pool, &missing_status_site).await;
        deactivate_site(pool, &missing_vmware_site).await;
    }

    #[tokio::test]
    async fn future_dated_site_and_vmware_observations_are_rejected() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = migrated_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let site = unique_site("FUTURE");
        provision_safe_site(pool, &site).await;

        let site_error = sqlx::query(
            "UPDATE site_status \
             SET last_check = NOW() + INTERVAL '1 hour' \
             WHERE site = $1",
        )
        .bind(&site)
        .execute(pool)
        .await
        .expect_err("future-dated site observation must fail closed");
        assert_check_violation(&site_error);

        let vmware_error = sqlx::query(
            "UPDATE component_status \
             SET last_check = NOW() + INTERVAL '1 hour' \
             WHERE site = $1 AND adapter_name = 'vmware'",
        )
        .bind(&site)
        .execute(pool)
        .await
        .expect_err("future-dated VMware observation must fail closed");
        assert_check_violation(&vmware_error);

        assert!(acquired_epoch(pool, &site).await.is_some());
        deactivate_site(pool, &site).await;
    }

    #[tokio::test]
    async fn aggregate_status_read_rejects_an_active_site_without_authority() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = migrated_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let site = unique_site("MISSING");
        sqlx::query(
            "INSERT INTO site_registry \
                 (unlocode, name, country, country_code, timezone, active) \
             VALUES ($1, 'Missing authority fixture', 'Test', 'TS', 'UTC', TRUE)",
        )
        .bind(&site)
        .execute(pool)
        .await
        .expect("seed active site without a status authority row");

        let error = list_site_statuses(pool)
            .await
            .expect_err("a partial active-site status set must fail closed");
        assert!(error
            .to_string()
            .contains("active site has no canonical degradation status"));

        deactivate_site(pool, &site).await;
    }

    #[tokio::test]
    async fn recovery_observations_advance_epoch_and_invalidate_old_authority() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = migrated_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let site = unique_site("EPOCH");
        provision_safe_site(pool, &site).await;
        let before_stale = acquired_epoch(pool, &site)
            .await
            .expect("fresh healthy site has an epoch");

        set_site_health(pool, &site, "healthy", "up", "up", 600).await;
        assert_eq!(acquired_epoch(pool, &site).await, None);
        set_site_health(pool, &site, "healthy", "up", "up", 0).await;
        let after_fresh = acquired_epoch(pool, &site)
            .await
            .expect("fresh observation restores authority");
        assert!(after_fresh > before_stale);
        assert!(!epoch_is_current(pool, &site, before_stale).await);

        set_vmware_health(pool, &site, "up", 600).await;
        assert_eq!(acquired_epoch(pool, &site).await, None);
        set_vmware_health(pool, &site, "up", 0).await;
        let after_vmware_fresh = acquired_epoch(pool, &site)
            .await
            .expect("fresh VMware observation restores authority");
        assert!(after_vmware_fresh > after_fresh);
        assert!(!epoch_is_current(pool, &site, after_fresh).await);

        set_site_health(pool, &site, "degraded", "degraded", "up", 0).await;
        assert_eq!(acquired_epoch(pool, &site).await, None);
        set_site_health(pool, &site, "healthy", "up", "up", 0).await;
        let after_recovery = acquired_epoch(pool, &site)
            .await
            .expect("unsafe-to-safe transition restores authority");
        assert!(after_recovery > after_vmware_fresh);
        assert!(!epoch_is_current(pool, &site, after_vmware_fresh).await);

        deactivate_site(pool, &site).await;
    }

    #[tokio::test]
    async fn acquisition_waits_for_in_flight_health_transition_and_observes_commit() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = migrated_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let site = unique_site("RACE");
        provision_safe_site(pool, &site).await;
        let mut reader = pool.begin().await.expect("begin reader transaction");
        let reader_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *reader)
            .await
            .expect("read fence connection backend PID");
        let mut writer = pool.begin().await.expect("begin health writer transaction");
        sqlx::query(
            "UPDATE site_status \
             SET state = 'degraded', api_status = 'degraded', last_check = NOW(), \
                 updated_at = NOW() \
             WHERE site = $1",
        )
        .bind(&site)
        .execute(&mut *writer)
        .await
        .expect("stage uncommitted degradation transition");

        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let acquisition_site = site.clone();
        let acquisition = tokio::spawn(async move {
            let _ = started_sender.send(());
            let acquired = acquire_live_site_execution_fence(&mut reader, &acquisition_site).await;
            reader
                .rollback()
                .await
                .expect("release reader fence transaction");
            acquired
        });
        started_receiver
            .await
            .expect("acquisition task started before wait assertion");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let waiting_on_lock: bool = sqlx::query_scalar(
                    "SELECT COALESCE(( \
                         SELECT wait_event_type = 'Lock' \
                         FROM pg_stat_activity \
                         WHERE pid = $1 \
                     ), FALSE)",
                )
                .bind(reader_backend_pid)
                .fetch_one(pool)
                .await
                .expect("inspect fence connection lock wait");
                if waiting_on_lock {
                    break;
                }
                assert!(
                    !acquisition.is_finished(),
                    "fence acquisition completed instead of waiting on the authority row"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fence acquisition enters a PostgreSQL lock wait");
        assert!(
            !acquisition.is_finished(),
            "fence acquisition must remain blocked before the writer commits"
        );

        writer
            .commit()
            .await
            .expect("commit degraded health transition");
        let acquired = tokio::time::timeout(Duration::from_secs(2), acquisition)
            .await
            .expect("fence acquisition resumes after health commit")
            .expect("fence acquisition task joins")
            .expect("fence acquisition query succeeds");
        assert_eq!(acquired, None);

        deactivate_site(pool, &site).await;
    }

    #[tokio::test]
    async fn bulk_degradation_transition_cannot_deadlock_with_component_refresh() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = migrated_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let site = unique_site("ORDER");
        provision_safe_site(pool, &site).await;

        let mut component_writer = pool.begin().await.expect("begin component writer");
        sqlx::query(
            "SELECT 1 FROM component_status \
             WHERE site = $1 AND adapter_name = 'vmware' FOR UPDATE",
        )
        .bind(&site)
        .fetch_one(&mut *component_writer)
        .await
        .expect("hold VMware component row before bulk degradation");

        let transition_pool = pool.clone();
        let transition_site = site.clone();
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let transition = tokio::spawn(async move {
            let mut transaction = transition_pool
                .begin()
                .await
                .expect("begin degradation transition");
            let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await
                .expect("read degradation backend PID");
            let _ = pid_sender.send(backend_pid);
            let status = enter(&mut transaction, &transition_site, "lock-order regression")
                .await
                .expect("bulk degradation transition");
            transaction
                .commit()
                .await
                .expect("commit bulk degradation transition");
            status
        });
        let transition_backend_pid = pid_receiver
            .await
            .expect("degradation transition publishes its backend PID");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let waiting_on_lock: bool = sqlx::query_scalar(
                    "SELECT COALESCE(( \
                         SELECT wait_event_type = 'Lock' \
                         FROM pg_stat_activity WHERE pid = $1 \
                     ), FALSE)",
                )
                .bind(transition_backend_pid)
                .fetch_one(pool)
                .await
                .expect("inspect degradation transition lock wait");
                if waiting_on_lock {
                    break;
                }
                assert!(
                    !transition.is_finished(),
                    "bulk degradation unexpectedly bypassed the held component row"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bulk degradation waits on the component row before the site mutex");

        // This refresh fires the migration-198 component trigger. Because the
        // bulk transition has not yet taken the site mutex, the trigger can
        // acquire it without forming the historical deadlock cycle.
        sqlx::query(
            "UPDATE component_status \
             SET last_check = statement_timestamp() \
             WHERE site = $1 AND adapter_name = 'vmware'",
        )
        .bind(&site)
        .execute(&mut *component_writer)
        .await
        .expect("refresh held component without deadlocking on site authority");
        component_writer
            .commit()
            .await
            .expect("commit component refresh");

        let status = tokio::time::timeout(Duration::from_secs(2), transition)
            .await
            .expect("bulk degradation resumes after component refresh")
            .expect("bulk degradation task joins")
            .expect("site status remains present");
        assert_eq!(status.state, SiteDegradationState::Degraded);

        deactivate_site(pool, &site).await;
    }
}
