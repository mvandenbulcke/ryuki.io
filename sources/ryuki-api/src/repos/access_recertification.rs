//! Repository functions for `access_reviews` and `recertification_campaigns`.
//!
//! # UUID discipline
//! `access_reviews.id` is a UUID PK. SELECT casts: `id::text AS id`.
//! On bind: `Uuid::parse_str(id)` — malformed id → `Ok(None)` (caller → 404).
//!
//! # Enum encoding
//! `review_type` and `status` stored as PascalCase variants. Decoded via
//! `serde_json::from_value(Value::String(raw))`. Parse failure → decode error
//! (caller → 500), NOT a default.
//!
//! # JSONB access_details
//! `review_history` JSONB stores a plain string array (migration 070 normalised
//! old `{timestamp,action,reviewer,detail}` objects to their `detail` strings).
//! `into_model` decodes via `serde_json::from_value` into `Vec<String>`.
//! Writes append a single string via `review_history || to_jsonb($::text)`.
//!
//! # Timestamps
//! `last_reviewed` is nullable TIMESTAMPTZ: `None` → `""`, `Some` → to_rfc3339.
//! `next_review_due` is TIMESTAMPTZ → to_rfc3339.
//!
//! # CAS design
//! Mutations use a dual-CAS conditioned on BOTH `status` AND `updated_at`
//! (approve/exempt additionally condition on `next_review_due`).
//! A miss after a successful load returns `Ok(None)` (caller → 409).

use chrono::{DateTime, Utc};
use ryuki_engine::access_recertification::{
    AccessReview, CampaignStatus, RecertificationCampaign, ReviewStatus, ReviewType,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

pub const COLUMNS: &str = "id::text AS id, \
     review_type, \
     target_name, \
     owner, \
     last_reviewed, \
     next_review_due, \
     status, \
     reviewer, \
     site, \
     review_history, \
     updated_at";

pub const CAMPAIGN_COLUMNS: &str = "id, \
     name, \
     start_date, \
     end_date, \
     review_type, \
     reviewer_group, \
     reviews_count, \
     completed_count, \
     status";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct AccessReviewRow {
    pub id: String,
    pub review_type: String,
    pub target_name: String,
    pub owner: String,
    pub last_reviewed: Option<DateTime<Utc>>,
    pub next_review_due: DateTime<Utc>,
    pub status: String,
    pub reviewer: Option<String>,
    pub site: String,
    pub review_history: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

impl AccessReviewRow {
    pub fn into_model(self) -> Result<(AccessReview, DateTime<Utc>), sqlx::Error> {
        let review_type: ReviewType = serde_json::from_value(serde_json::Value::String(
            self.review_type.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "access_reviews.review_type: corrupt value '{}': {e}",
                    self.review_type
                )
                .into(),
            )
        })?;

        let status: ReviewStatus = serde_json::from_value(serde_json::Value::String(
            self.status.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "access_reviews.status: corrupt value '{}': {e}",
                    self.status
                )
                .into(),
            )
        })?;

        let access_details: Vec<String> = serde_json::from_value(self.review_history.clone())
            .map_err(|e| {
                sqlx::Error::Decode(
                    format!("access_reviews.review_history: corrupt JSONB value: {e}").into(),
                )
            })?;

        let last_reviewed = self
            .last_reviewed
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        let model = AccessReview {
            id: self.id,
            review_type,
            target_name: self.target_name,
            owner: self.owner,
            last_reviewed,
            next_review_due: self.next_review_due.to_rfc3339(),
            status,
            reviewer: self.reviewer,
            site: self.site,
            access_details,
        };

        Ok((model, self.updated_at))
    }
}

#[derive(sqlx::FromRow)]
pub struct CampaignRow {
    pub id: String,
    pub name: String,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub review_type: String,
    pub reviewer_group: String,
    pub reviews_count: i32,
    pub completed_count: i32,
    pub status: String,
}

impl CampaignRow {
    pub fn into_model(self) -> Result<RecertificationCampaign, sqlx::Error> {
        let review_type: ReviewType = serde_json::from_value(serde_json::Value::String(
            self.review_type.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "recertification_campaigns.review_type: corrupt value '{}': {e}",
                    self.review_type
                )
                .into(),
            )
        })?;

        let status: CampaignStatus = serde_json::from_value(serde_json::Value::String(
            self.status.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "recertification_campaigns.status: corrupt value '{}': {e}",
                    self.status
                )
                .into(),
            )
        })?;

        Ok(RecertificationCampaign {
            id: self.id,
            name: self.name,
            start_date: self.start_date.to_rfc3339(),
            end_date: self.end_date.to_rfc3339(),
            review_type,
            reviewer_group: self.reviewer_group,
            reviews_count: self.reviews_count as usize,
            completed_count: self.completed_count as usize,
            status,
        })
    }
}

// ─── Review repository functions ──────────────────────────────────────────────

/// List reviews, optionally filtered by site and/or review_type.
pub async fn list(
    pool: &PgPool,
    site: &str,
    review_type: &str,
) -> Result<Vec<AccessReview>, sqlx::Error> {
    let rows: Vec<AccessReviewRow> = match (site.is_empty(), review_type.is_empty()) {
        (true, true) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews ORDER BY site, target_name"
            ))
            .fetch_all(pool)
            .await?
        }
        (false, true) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews WHERE site = $1 ORDER BY target_name"
            ))
            .bind(site)
            .fetch_all(pool)
            .await?
        }
        (true, false) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews WHERE review_type = $1 ORDER BY site, target_name"
            ))
            .bind(review_type)
            .fetch_all(pool)
            .await?
        }
        (false, false) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews WHERE site = $1 AND review_type = $2 ORDER BY target_name"
            ))
            .bind(site)
            .bind(review_type)
            .fetch_all(pool)
            .await?
        }
    };

    rows.into_iter()
        .map(|r| r.into_model().map(|(m, _)| m))
        .collect()
}

/// List reviews (optionally site/type-filtered), bounded to one `LIMIT`/`OFFSET`
/// page (#14). SEPARATE from [`list`] because that feeds `access_review_summary`,
/// which counts EVERY row by status — only the list endpoint pages. The base
/// `ORDER BY ... target_name` is non-unique, so `, id` (the UUID PK) is appended
/// as the tie-breaker to make each page a stable cut.
pub async fn list_reviews_page(
    pool: &PgPool,
    site: &str,
    review_type: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AccessReview>, sqlx::Error> {
    let rows: Vec<AccessReviewRow> = match (site.is_empty(), review_type.is_empty()) {
        (true, true) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews \
                 ORDER BY site, target_name, id LIMIT $1 OFFSET $2"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
        (false, true) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews WHERE site = $1 \
                 ORDER BY target_name, id LIMIT $2 OFFSET $3"
            ))
            .bind(site)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
        (true, false) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews WHERE review_type = $1 \
                 ORDER BY site, target_name, id LIMIT $2 OFFSET $3"
            ))
            .bind(review_type)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
        (false, false) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM access_reviews WHERE site = $1 AND review_type = $2 \
                 ORDER BY target_name, id LIMIT $3 OFFSET $4"
            ))
            .bind(site)
            .bind(review_type)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
    };

    rows.into_iter()
        .map(|r| r.into_model().map(|(m, _)| m))
        .collect()
}

/// Count reviews (optionally site/type-filtered) — the pagination total for
/// [`list_reviews_page`], using the SAME `WHERE` so the count matches the page.
pub async fn count_reviews(
    pool: &PgPool,
    site: &str,
    review_type: &str,
) -> Result<i64, sqlx::Error> {
    let count: i64 = match (site.is_empty(), review_type.is_empty()) {
        (true, true) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM access_reviews")
                .fetch_one(pool)
                .await?
        }
        (false, true) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM access_reviews WHERE site = $1")
                .bind(site)
                .fetch_one(pool)
                .await?
        }
        (true, false) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM access_reviews WHERE review_type = $1")
                .bind(review_type)
                .fetch_one(pool)
                .await?
        }
        (false, false) => {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM access_reviews WHERE site = $1 AND review_type = $2",
            )
            .bind(site)
            .bind(review_type)
            .fetch_one(pool)
            .await?
        }
    };
    Ok(count)
}

/// Get a single review by UUID string id. Malformed id → Ok(None).
pub async fn get(
    pool: &PgPool,
    id: &str,
) -> Result<Option<(AccessReview, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<AccessReviewRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM access_reviews WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// List reviews where next_review_due < NOW() and status != 'Revoked'.
pub async fn list_due(pool: &PgPool) -> Result<Vec<AccessReview>, sqlx::Error> {
    let rows: Vec<AccessReviewRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM access_reviews \
         WHERE next_review_due < NOW() AND status != 'Revoked' \
         ORDER BY next_review_due"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|r| r.into_model().map(|(m, _)| m))
        .collect()
}

/// List reviews expiring within the next `days` days.
pub async fn list_expiring(pool: &PgPool, days: i64) -> Result<Vec<AccessReview>, sqlx::Error> {
    let rows: Vec<AccessReviewRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM access_reviews \
         WHERE next_review_due >= NOW() AND next_review_due <= NOW() + ($1 * INTERVAL '1 day') \
         ORDER BY next_review_due"
    ))
    .bind(days)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|r| r.into_model().map(|(m, _)| m))
        .collect()
}

/// Summary: COUNT per status.
pub async fn summary(pool: &PgPool) -> Result<serde_json::Value, sqlx::Error> {
    let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         COUNT(*) AS total, \
         COUNT(*) FILTER (WHERE status = 'Pending') AS pending, \
         COUNT(*) FILTER (WHERE status = 'InProgress') AS in_progress, \
         COUNT(*) FILTER (WHERE status = 'Approved') AS approved, \
         COUNT(*) FILTER (WHERE status = 'Revoked') AS revoked, \
         COUNT(*) FILTER (WHERE status = 'Exempted') AS exempted \
         FROM access_reviews",
    )
    .fetch_one(pool)
    .await?;

    Ok(serde_json::json!({
        "source": "db",
        "total": row.0,
        "pending": row.1,
        "in_progress": row.2,
        "approved": row.3,
        "revoked": row.4,
        "exempted": row.5
    }))
}

// ─── Mutation functions ───────────────────────────────────────────────────────

/// CAS: status='Pending' → 'InProgress'. Returns Ok(None) → 409 on miss.
pub async fn start(
    pool: &PgPool,
    id: &str,
    reviewer: &str,
    expected_updated_at: DateTime<Utc>,
) -> Result<Option<(AccessReview, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<AccessReviewRow> = sqlx::query_as(&format!(
        "UPDATE access_reviews SET \
         status = 'InProgress', \
         reviewer = $2, \
         updated_at = NOW() \
         WHERE id = $1 AND status = 'Pending' AND updated_at = $3 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(reviewer)
    .bind(expected_updated_at)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Dual-CAS: (status, updated_at, next_review_due) → 'Approved'.
/// Sets last_reviewed=NOW(), next_review_due=NOW()+90days, appends justification.
pub async fn approve(
    pool: &PgPool,
    id: &str,
    reviewer: &str,
    justification: &str,
    expected_status: &str,
    expected_updated_at: DateTime<Utc>,
    expected_next_review_due: DateTime<Utc>,
) -> Result<Option<(AccessReview, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<AccessReviewRow> = sqlx::query_as(&format!(
        "UPDATE access_reviews SET \
         status = 'Approved', \
         reviewer = $2, \
         last_reviewed = NOW(), \
         next_review_due = NOW() + INTERVAL '90 days', \
         review_history = review_history || to_jsonb($3::text), \
         updated_at = NOW() \
         WHERE id = $1 AND status = $4 AND updated_at = $5 AND next_review_due = $6 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(reviewer)
    .bind(justification)
    .bind(expected_status)
    .bind(expected_updated_at)
    .bind(expected_next_review_due)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// CAS: (status, updated_at) → 'Revoked'. Sets last_reviewed=NOW(), appends reason.
pub async fn revoke(
    pool: &PgPool,
    id: &str,
    reviewer: &str,
    reason: &str,
    expected_status: &str,
    expected_updated_at: DateTime<Utc>,
) -> Result<Option<(AccessReview, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<AccessReviewRow> = sqlx::query_as(&format!(
        "UPDATE access_reviews SET \
         status = 'Revoked', \
         reviewer = $2, \
         last_reviewed = NOW(), \
         review_history = review_history || to_jsonb($3::text), \
         updated_at = NOW() \
         WHERE id = $1 AND status = $4 AND updated_at = $5 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(reviewer)
    .bind(reason)
    .bind(expected_status)
    .bind(expected_updated_at)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Dual-CAS: (status, updated_at, next_review_due) → 'Exempted'.
/// Sets last_reviewed=NOW(), next_review_due=$exemption_expiry, appends justification.
#[allow(clippy::too_many_arguments)]
pub async fn exempt(
    pool: &PgPool,
    id: &str,
    reviewer: &str,
    justification: &str,
    exemption_expiry: DateTime<Utc>,
    expected_status: &str,
    expected_updated_at: DateTime<Utc>,
    expected_next_review_due: DateTime<Utc>,
) -> Result<Option<(AccessReview, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<AccessReviewRow> = sqlx::query_as(&format!(
        "UPDATE access_reviews SET \
         status = 'Exempted', \
         reviewer = $2, \
         last_reviewed = NOW(), \
         next_review_due = $3, \
         review_history = review_history || to_jsonb($4::text), \
         updated_at = NOW() \
         WHERE id = $1 AND status = $5 AND updated_at = $6 AND next_review_due = $7 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(reviewer)
    .bind(exemption_expiry)
    .bind(justification)
    .bind(expected_status)
    .bind(expected_updated_at)
    .bind(expected_next_review_due)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

// ─── Campaign repository functions ────────────────────────────────────────────

/// Insert a new campaign. reviews_count and completed_count are computed from
/// the access_reviews table at insert time so they reflect real data.
///
/// The caller owns the transaction: pass `conn = &mut *tx` and commit on success.
/// All three queries (two COUNTs + INSERT) execute on the same connection so they
/// are covered by the same atomic tx; the audit row is written before commit.
pub async fn insert_campaign(
    conn: &mut PgConnection,
    campaign: &RecertificationCampaign,
) -> Result<RecertificationCampaign, sqlx::Error> {
    let start_date: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&campaign.start_date)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let end_date: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&campaign.end_date)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    // Compute counts from the DB at insert time so they reflect real data.
    let review_type_str = campaign.review_type.to_string();
    let (reviews_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM access_reviews WHERE review_type = $1")
            .bind(&review_type_str)
            .fetch_one(&mut *conn)
            .await?;

    let (completed_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM access_reviews \
         WHERE review_type = $1 AND status IN ('Approved','Revoked','Exempted')",
    )
    .bind(&review_type_str)
    .fetch_one(&mut *conn)
    .await?;

    // Checked narrowing to the INT columns — never silently truncate a COUNT.
    let reviews_count =
        i32::try_from(reviews_count).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let completed_count =
        i32::try_from(completed_count).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: CampaignRow = sqlx::query_as(&format!(
        "INSERT INTO recertification_campaigns \
         (id, name, start_date, end_date, review_type, reviewer_group, reviews_count, completed_count, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {CAMPAIGN_COLUMNS}"
    ))
    .bind(&campaign.id)
    .bind(&campaign.name)
    .bind(start_date)
    .bind(end_date)
    .bind(&review_type_str)
    .bind(&campaign.reviewer_group)
    .bind(reviews_count)
    .bind(completed_count)
    .bind(campaign.status.to_string())
    .fetch_one(&mut *conn)
    .await?;

    row.into_model()
}

/// Get a campaign by TEXT id.
pub async fn get_campaign(
    pool: &PgPool,
    id: &str,
) -> Result<Option<RecertificationCampaign>, sqlx::Error> {
    let row: Option<CampaignRow> = sqlx::query_as(&format!(
        "SELECT {CAMPAIGN_COLUMNS} FROM recertification_campaigns WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// List all campaigns.
pub async fn list_campaigns(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<RecertificationCampaign>, sqlx::Error> {
    // `created_at DESC` alone is non-unique → `id` (PK) is the tie-breaker (#14).
    let rows: Vec<CampaignRow> = sqlx::query_as(&format!(
        "SELECT {CAMPAIGN_COLUMNS} FROM recertification_campaigns \
         ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count all recertification campaigns — the pagination total for [`list_campaigns`].
pub async fn count_campaigns(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM recertification_campaigns")
        .fetch_one(pool)
        .await
}

// ─── DB integration tests ────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 access_recertification_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod access_recertification_db_tests {
    use super::*;

    static DB_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    async fn insert_test_review(
        pool: &PgPool,
        id: uuid::Uuid,
        review_type: &str,
        status: &str,
        site: &str,
        next_review_due_offset_days: i64,
    ) {
        let next_due = if next_review_due_offset_days >= 0 {
            format!("NOW() + INTERVAL '{next_review_due_offset_days} days'")
        } else {
            format!("NOW() - INTERVAL '{} days'", -next_review_due_offset_days)
        };
        sqlx::query(&format!(
            "INSERT INTO access_reviews (id, review_type, target_name, owner, next_review_due, status, site, review_history) \
             VALUES ($1, $2, 'test-target', 'test-owner', {next_due}, $3, $4, '[]'::jsonb)"
        ))
        .bind(id)
        .bind(review_type)
        .bind(status)
        .bind(site)
        .execute(pool)
        .await
        .expect("insert_test_review");
    }

    async fn cleanup_review(pool: &PgPool, id: uuid::Uuid) {
        sqlx::query("DELETE FROM access_reviews WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_campaign(pool: &PgPool, id: &str) {
        sqlx::query("DELETE FROM recertification_campaigns WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn list_returns_seeded_rows_with_remapped_types() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Migration 070 remapped Role/Group → ADGroup, FileShare → SharePermission
        // (ServiceAccount unchanged) and the statuses to the engine vocabulary.
        // Decoding alone already proves no old value survived (Role/Current/etc.
        // are not valid engine variants and would fail into_model); also assert the
        // exact remapped type counts from the migration-030 seed.
        let reviews = list(&pool, "", "").await.expect("list");
        assert!(reviews.len() >= 5, "migration 030 seeds 5 reviews");
        use ryuki_engine::access_recertification::ReviewType;
        let count_type = |t: ReviewType| reviews.iter().filter(|r| r.review_type == t).count();
        assert!(
            count_type(ReviewType::ADGroup) >= 2,
            "Role+Group must have remapped to ADGroup"
        );
        assert!(
            count_type(ReviewType::SharePermission) >= 1,
            "FileShare must have remapped to SharePermission"
        );
        assert!(
            count_type(ReviewType::ServiceAccount) >= 2,
            "ServiceAccount rows unchanged"
        );
    }

    /// #14: `list_reviews_page` bounds the page, and the `, id` tie-breaker keeps
    /// pagination deterministic even when `target_name`/`site` TIE (the seeded rows
    /// all share `target_name='test-target'`). Paging `limit=2` across all offsets
    /// must visit each row EXACTLY once — no dup/skip. `count_reviews` mirrors the
    /// site/type `WHERE`. `list` (unbounded) is left intact for access_review_summary.
    #[tokio::test]
    async fn list_reviews_page_paginates_deterministically_on_ties() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Isolated 5-char site so count_reviews counts ONLY our rows; every row
        // shares target_name='test-target', so target_name ties across all 5.
        let site = format!("Z{}", &uuid::Uuid::new_v4().to_string()[..4]);
        let mut ids: Vec<uuid::Uuid> = Vec::new();
        for _ in 0..5 {
            let id = uuid::Uuid::new_v4();
            ids.push(id);
            insert_test_review(&pool, id, "ADGroup", "Pending", &site, 30).await;
        }

        // Independent + fn totals agree; both == 5.
        let raw_total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM access_reviews WHERE site = $1")
                .bind(&site)
                .fetch_one(&pool)
                .await
                .expect("raw count");
        let total = count_reviews(&pool, &site, "")
            .await
            .expect("count_reviews");
        assert_eq!(total, raw_total, "count_reviews matches a raw COUNT(*)");
        assert_eq!(total, 5, "seeded exactly 5 reviews in the isolated site");

        // Page limit=2 across offsets 0,2,4 must TILE the 5 rows exactly (2+2+1) —
        // the tie-breaker guarantee (tied target_name would otherwise dup/skip).
        let mut seen: Vec<String> = Vec::new();
        for off in [0i64, 2, 4] {
            let page = list_reviews_page(&pool, &site, "", 2, off)
                .await
                .expect("list_reviews_page");
            assert!(page.len() <= 2, "LIMIT 2 bounds each page");
            for r in page {
                seen.push(r.id);
            }
        }
        // Exact set equality (NOT dedup-then-count, which would mask an overlap
        // like [A,B],[B,C],[D,E]): the collected page rows must equal the seeded
        // set, so each row is visited exactly once — no duplicate, no skip.
        seen.sort();
        let mut want: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        want.sort();
        assert_eq!(
            seen, want,
            "paged rows equal the seeded set exactly (stable `, id` tie-breaker)"
        );

        // Type branch: matching type == 5, non-matching == 0 (count mirrors WHERE).
        let adg = count_reviews(&pool, &site, "ADGroup")
            .await
            .expect("count ADGroup");
        assert_eq!(adg, 5, "all 5 are ADGroup");
        let svc = count_reviews(&pool, &site, "ServiceAccount")
            .await
            .expect("count ServiceAccount");
        assert_eq!(svc, 0, "none are ServiceAccount");
        let typed_page = list_reviews_page(&pool, &site, "ADGroup", 1000, 0)
            .await
            .expect("typed page");
        assert_eq!(typed_page.len(), 5, "typed page returns all 5 ADGroup rows");

        for id in &ids {
            cleanup_review(&pool, *id).await;
        }
    }

    #[tokio::test]
    async fn get_by_uuid_and_malformed_id() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id = uuid::Uuid::new_v4();
        insert_test_review(&pool, id, "ADGroup", "Pending", "TEST", 30).await;

        let result = get(&pool, &id.to_string()).await.expect("get");
        assert!(result.is_some(), "should find inserted row");

        let malformed = get(&pool, "not-a-uuid").await.expect("get malformed");
        assert!(malformed.is_none(), "malformed uuid → Ok(None)");

        cleanup_review(&pool, id).await;
    }

    #[tokio::test]
    async fn start_cas_success_and_miss() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id = uuid::Uuid::new_v4();
        insert_test_review(&pool, id, "ServiceAccount", "Pending", "TEST", 30).await;

        let (_, updated_at) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row exists");

        // Success
        let result = start(&pool, &id.to_string(), "test.reviewer", updated_at)
            .await
            .expect("start");
        assert!(result.is_some(), "start should succeed");
        let (review, _) = result.unwrap();
        assert_eq!(review.status, ReviewStatus::InProgress);
        assert_eq!(review.reviewer, Some("test.reviewer".into()));

        // Miss: try again with same (now stale) updated_at
        let miss = start(&pool, &id.to_string(), "other.reviewer", updated_at)
            .await
            .expect("start miss");
        assert!(miss.is_none(), "stale updated_at → Ok(None)");

        cleanup_review(&pool, id).await;
    }

    #[tokio::test]
    async fn approve_dual_cas_success_and_stale_next_review_due_miss() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id = uuid::Uuid::new_v4();
        insert_test_review(&pool, id, "ADGroup", "InProgress", "TEST", 30).await;

        let (loaded, updated_at) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");
        let expected_nrd: DateTime<Utc> =
            chrono::DateTime::parse_from_rfc3339(&loaded.next_review_due)
                .unwrap()
                .with_timezone(&Utc);

        // Success
        let result = approve(
            &pool,
            &id.to_string(),
            "approver",
            "access confirmed",
            "InProgress",
            updated_at,
            expected_nrd,
        )
        .await
        .expect("approve");
        assert!(result.is_some(), "approve should succeed");
        let (review, _) = result.unwrap();
        assert_eq!(review.status, ReviewStatus::Approved);
        assert!(!review.access_details.is_empty());

        // Stale next_review_due miss (use an obviously wrong datetime)
        let stale_nrd = chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let (_, new_updated_at) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");
        let miss = approve(
            &pool,
            &id.to_string(),
            "approver2",
            "justification",
            "Approved",
            new_updated_at,
            stale_nrd,
        )
        .await
        .expect("approve miss");
        assert!(miss.is_none(), "stale next_review_due → Ok(None)");

        cleanup_review(&pool, id).await;
    }

    #[tokio::test]
    async fn revoke_sets_status_and_appends_reason() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id = uuid::Uuid::new_v4();
        insert_test_review(&pool, id, "Sudo", "InProgress", "TEST", 30).await;

        let (_, updated_at) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");

        let result = revoke(
            &pool,
            &id.to_string(),
            "revoker",
            "access no longer needed",
            "InProgress",
            updated_at,
        )
        .await
        .expect("revoke");
        assert!(result.is_some());
        let (review, _) = result.unwrap();
        assert_eq!(review.status, ReviewStatus::Revoked);
        assert!(review
            .access_details
            .iter()
            .any(|d| d.contains("access no longer needed")));

        cleanup_review(&pool, id).await;
    }

    #[tokio::test]
    async fn exempt_sets_next_review_due_and_appends_justification() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id = uuid::Uuid::new_v4();
        insert_test_review(&pool, id, "LocalAdmin", "Pending", "TEST", 30).await;

        let (loaded, updated_at) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");
        let expected_nrd: DateTime<Utc> =
            chrono::DateTime::parse_from_rfc3339(&loaded.next_review_due)
                .unwrap()
                .with_timezone(&Utc);

        let expiry = chrono::Utc::now() + chrono::Duration::days(180);

        let result = exempt(
            &pool,
            &id.to_string(),
            "exemption.reviewer",
            "agent migration in progress",
            expiry,
            "Pending",
            updated_at,
            expected_nrd,
        )
        .await
        .expect("exempt");
        assert!(result.is_some());
        let (review, _) = result.unwrap();
        assert_eq!(review.status, ReviewStatus::Exempted);
        // next_review_due should be approximately expiry (within a second).
        let stored_nrd: DateTime<Utc> =
            chrono::DateTime::parse_from_rfc3339(&review.next_review_due)
                .unwrap()
                .with_timezone(&Utc);
        let diff = (stored_nrd - expiry).num_seconds().abs();
        assert!(diff < 2, "next_review_due should match exemption_expiry");
        assert!(review
            .access_details
            .iter()
            .any(|d| d.contains("agent migration")));

        cleanup_review(&pool, id).await;
    }

    #[tokio::test]
    async fn access_details_jsonb_round_trip() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id = uuid::Uuid::new_v4();
        insert_test_review(&pool, id, "ADGroup", "Pending", "TEST", 30).await;

        let (_, updated_at) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");

        // start → appends nothing; approve appends justification
        let _ = start(&pool, &id.to_string(), "rev", updated_at)
            .await
            .expect("start");

        let (after_start, updated_at2) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");
        let nrd: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&after_start.next_review_due)
            .unwrap()
            .with_timezone(&Utc);

        let _ = approve(
            &pool,
            &id.to_string(),
            "rev",
            "round-trip test justification",
            "InProgress",
            updated_at2,
            nrd,
        )
        .await
        .expect("approve");

        let (final_review, _) = get(&pool, &id.to_string())
            .await
            .expect("get")
            .expect("row");
        assert!(
            final_review
                .access_details
                .iter()
                .any(|d| d.contains("round-trip test justification")),
            "justification should be persisted in access_details"
        );

        cleanup_review(&pool, id).await;
    }

    #[tokio::test]
    async fn list_due_and_expiring() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let id_due = uuid::Uuid::new_v4();
        let id_expiring = uuid::Uuid::new_v4();
        insert_test_review(&pool, id_due, "Sudo", "Pending", "TEST", -5).await; // overdue
        insert_test_review(&pool, id_expiring, "Sudo", "Pending", "TEST", 10).await; // expiring within 30 days

        let due = list_due(&pool).await.expect("list_due");
        assert!(
            due.iter().any(|r| r.id == id_due.to_string()),
            "overdue row should appear in list_due"
        );

        let expiring = list_expiring(&pool, 30).await.expect("list_expiring");
        assert!(
            expiring.iter().any(|r| r.id == id_expiring.to_string()),
            "expiring row should appear in list_expiring"
        );

        cleanup_review(&pool, id_due).await;
        cleanup_review(&pool, id_expiring).await;
    }

    #[tokio::test]
    async fn summary_counts() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let result = summary(&pool).await.expect("summary");
        let total = result["total"].as_i64().unwrap();
        let counted = result["pending"].as_i64().unwrap()
            + result["in_progress"].as_i64().unwrap()
            + result["approved"].as_i64().unwrap()
            + result["revoked"].as_i64().unwrap()
            + result["exempted"].as_i64().unwrap();
        assert_eq!(total, counted);
    }

    #[tokio::test]
    async fn campaign_insert_and_list() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_engine::access_recertification::{build_campaign, ReviewType};

        let campaign = build_campaign(
            "Test Campaign",
            ReviewType::ADGroup,
            "test-reviewers",
            30,
            0, // will be overwritten by DB count
            0,
        );
        let campaign_id = campaign.id.clone();

        let mut tx = pool.begin().await.expect("begin tx");
        let inserted = insert_campaign(&mut tx, &campaign)
            .await
            .expect("insert_campaign");
        tx.commit().await.expect("commit tx");
        assert_eq!(inserted.name, "Test Campaign");
        assert_eq!(inserted.status, CampaignStatus::Active);
        // reviews_count computed from DB
        let _ = inserted.reviews_count; // just verify no decode error

        let campaigns = list_campaigns(&pool, 1000, 0)
            .await
            .expect("list_campaigns");
        assert!(campaigns.iter().any(|c| c.id == campaign_id));
        assert_eq!(
            count_campaigns(&pool).await.expect("count_campaigns"),
            campaigns.len() as i64,
            "#14: count_campaigns matches the full unpaged set"
        );

        cleanup_campaign(&pool, &campaign_id).await;
    }
}
