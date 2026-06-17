//! Repository functions for `datacenter_readiness_checks`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500.
//!
//! # UUID discipline
//! `id` is a UUID primary key. SELECTs cast it to TEXT (`id::text AS id`) so
//! sqlx decodes into `String`.
//!
//! # Timestamps
//! `last_checked TIMESTAMPTZ` is decoded as `DateTime<Utc>` and converted to a
//! stable RFC-3339 string in `into_model`. Casting with `::text` in the query
//! would yield a Postgres-formatted timestamp that is NOT RFC-3339; downstream
//! parsers would break.
//!
//! # Enum discipline
//! `check_type` and `status` are stored as kebab-case strings matching the
//! `#[serde(rename_all = "kebab-case")]` annotations on the engine enums.
//! `into_model` decodes them strictly via `serde_json::from_str`; a corrupt
//! persisted value surfaces as a Decode error (caller → 500), not a silent
//! default.

use chrono::{DateTime, Utc};
use ryuki_engine::datacenter_readiness::{CheckStatus, CheckType, ReadinessCheck};
use sqlx::PgPool;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx decodes into `String`.
/// `last_checked` stays a TIMESTAMPTZ decoded as `DateTime<Utc>` — a `::text`
/// cast yields a non-RFC-3339 string that downstream parsers would reject.
pub const COLUMNS: &str = "id::text AS id, \
     site, \
     check_type, \
     status, \
     last_checked, \
     details";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct DatacenterReadinessRow {
    pub id: String,
    pub site: String,
    pub check_type: String,
    pub status: String,
    pub last_checked: DateTime<Utc>,
    pub details: String,
}

impl DatacenterReadinessRow {
    /// Convert a DB row into the engine model.
    ///
    /// `check_type` and `status` are decoded strictly from their kebab-case
    /// serde names (matching the DB values). A corrupt value → Decode error
    /// (caller → 500) rather than a silent default.
    ///
    /// The model `id` is set from the real UUID string (the DB primary key
    /// cast to text); the synthetic "dc-check-{site}-{type}" id used by the
    /// old in-memory store is NOT reproduced — the UUID is the canonical key.
    ///
    /// `last_checked` is decoded as `DateTime<Utc>` and rendered as RFC-3339
    /// so engine/serialisation consumers see a stable format.
    pub fn into_model(self) -> Result<ReadinessCheck, sqlx::Error> {
        let check_type = decode_check_type(&self.check_type)?;
        let status = decode_status(&self.status)?;

        Ok(ReadinessCheck {
            id: self.id,
            site: self.site,
            check_type,
            status,
            last_checked: self.last_checked.to_rfc3339(),
            details: self.details,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical kebab-case serde variant name for `CheckType` as stored in the DB.
#[allow(dead_code)]
pub fn check_type_str(t: &CheckType) -> &'static str {
    match t {
        CheckType::Power => "power",
        CheckType::Cooling => "cooling",
        CheckType::RackSpace => "rack-space",
        CheckType::Switchport => "switchport",
        CheckType::Firmware => "firmware",
        CheckType::Capacity => "capacity",
    }
}

/// Canonical kebab-case serde variant name for `CheckStatus` as stored in the DB.
#[allow(dead_code)]
pub fn status_str(s: &CheckStatus) -> &'static str {
    match s {
        CheckStatus::Passed => "passed",
        CheckStatus::Failed => "failed",
        CheckStatus::Warning => "warning",
        CheckStatus::NotChecked => "not-checked",
    }
}

/// Decode a `check_type` string from the DB into the engine enum.
/// Uses serde's kebab-case wire names (as stored by `check_type_str`).
/// A corrupt or unknown value → `sqlx::Error::Decode`.
fn decode_check_type(raw: &str) -> Result<CheckType, sqlx::Error> {
    serde_json::from_value(serde_json::Value::String(raw.to_string())).map_err(|e| {
        sqlx::Error::Decode(
            format!("datacenter_readiness_checks.check_type: corrupt persisted value '{raw}': {e}")
                .into(),
        )
    })
}

/// Decode a `status` string from the DB into the engine enum.
/// Uses serde's kebab-case wire names (as stored by `status_str`).
/// A corrupt or unknown value → `sqlx::Error::Decode`.
fn decode_status(raw: &str) -> Result<CheckStatus, sqlx::Error> {
    serde_json::from_value(serde_json::Value::String(raw.to_string())).map_err(|e| {
        sqlx::Error::Decode(
            format!("datacenter_readiness_checks.status: corrupt persisted value '{raw}': {e}")
                .into(),
        )
    })
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Return all readiness checks across all sites, ordered by `site, check_type`
/// for determinism.
pub async fn list_all(pool: &PgPool) -> Result<Vec<ReadinessCheck>, sqlx::Error> {
    let rows: Vec<DatacenterReadinessRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM datacenter_readiness_checks ORDER BY site, check_type"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all readiness checks for a specific site, ordered by `check_type`
/// for determinism.
pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<ReadinessCheck>, sqlx::Error> {
    let rows: Vec<DatacenterReadinessRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM datacenter_readiness_checks WHERE site = $1 ORDER BY check_type"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}
