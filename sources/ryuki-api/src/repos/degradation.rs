//! Repository functions for degradation mode site and component status.
//!
//! Reads from `site_status` and `component_status` tables (migration 025).
//! Mutation functions take `&mut sqlx::PgConnection` so the caller's
//! transaction wraps both UPDATEs + the audit INSERT atomically.

use ryuki_engine::degradation_mode::{
    AdapterComponentStatus, ComponentStatus, SiteDegradationState, SiteStatus,
};
use sqlx::PgPool;

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
    let site_rows: Vec<SiteStatusRow> = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         ORDER BY site",
    )
    .fetch_all(pool)
    .await?;

    if site_rows.is_empty() {
        return Ok(vec![]);
    }

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         ORDER BY site, adapter_name",
    )
    .fetch_all(pool)
    .await?;

    let result = site_rows
        .into_iter()
        .map(|row| build_site_status(row, &component_rows))
        .collect();

    Ok(result)
}

pub async fn get_site_status(pool: &PgPool, site: &str) -> Result<Option<SiteStatus>, sqlx::Error> {
    let row: Option<SiteStatusRow> = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         WHERE site = $1",
    )
    .bind(site)
    .fetch_optional(pool)
    .await?;

    let row = match row {
        None => return Ok(None),
        Some(r) => r,
    };

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         WHERE site = $1 \
         ORDER BY adapter_name",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;

    Ok(Some(build_site_status(row, &component_rows)))
}

// ---------------------------------------------------------------------------
// Mutation functions (caller holds the transaction)
// ---------------------------------------------------------------------------

pub async fn enter(
    executor: &mut sqlx::PgConnection,
    site: &str,
    reason: &str,
) -> Result<Option<SiteStatus>, sqlx::Error> {
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
    .execute(&mut *executor)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Ok(None);
    }

    sqlx::query(
        "UPDATE component_status \
         SET status = 'degraded' \
         WHERE site = $1",
    )
    .bind(site)
    .execute(&mut *executor)
    .await?;

    // Re-read the updated row to return the persisted state.
    let row: SiteStatusRow = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         WHERE site = $1",
    )
    .bind(site)
    .fetch_one(&mut *executor)
    .await?;

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         WHERE site = $1 \
         ORDER BY adapter_name",
    )
    .bind(site)
    .fetch_all(&mut *executor)
    .await?;

    Ok(Some(build_site_status(row, &component_rows)))
}

pub async fn exit(
    executor: &mut sqlx::PgConnection,
    site: &str,
) -> Result<Option<SiteStatus>, sqlx::Error> {
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
    .execute(&mut *executor)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Ok(None);
    }

    sqlx::query(
        "UPDATE component_status \
         SET status = 'up' \
         WHERE site = $1",
    )
    .bind(site)
    .execute(&mut *executor)
    .await?;

    let row: SiteStatusRow = sqlx::query_as(
        "SELECT site, state, api_status, db_status, degradation_reason, last_check \
         FROM site_status \
         WHERE site = $1",
    )
    .bind(site)
    .fetch_one(&mut *executor)
    .await?;

    let component_rows: Vec<ComponentStatusRow> = sqlx::query_as(
        "SELECT site, adapter_name, status \
         FROM component_status \
         WHERE site = $1 \
         ORDER BY adapter_name",
    )
    .bind(site)
    .fetch_all(&mut *executor)
    .await?;

    Ok(Some(build_site_status(row, &component_rows)))
}
