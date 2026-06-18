//! Repository functions for `outage_notices`, `outage_notice_systems`, and
//! `outage_notice_acknowledgments`.
//!
//! # UUID discipline
//! `outage_notices.id` is a UUID PK. SELECT casts: `id::text AS id`.
//! On bind: `Uuid::parse_str(id)` — malformed id → `Ok(None)` (caller → 404).
//!
//! # Enum encoding
//! `status` and `impact_level` stored as PascalCase variants. Decoded via
//! `serde_json::from_value(Value::String(raw))`. Parse failure → decode error
//! (caller → 500), NOT a default.
//!
//! # Timestamps
//! All TIMESTAMPTZ columns decoded as `DateTime<Utc>`, converted to RFC 3339
//! strings in `into_model`. NEVER `::text` on a timestamp column.
//!
//! # Child tables
//! `affected_systems` aggregated via subquery over `outage_notice_systems`.
//! `acknowledgments` queried via a separate SELECT (no aggregation needed for
//! the main notice model — the engine only stores the last `acknowledged_by`).
//! On create, parent + child rows are inserted in a single transaction.
//!
//! # CAS design
//! Lifecycle mutations (send, acknowledge, complete, cancel) use a status-CAS:
//! UPDATE … WHERE id = $1 AND status = $2 RETURNING … — a zero-row result
//! signals a concurrent state change (→ Ok(None), caller → 409).

use chrono::{DateTime, Utc};
use ryuki_engine::outage_comms::{
    ImpactLevel, NoticeAckEvent, NoticeStatus, OutageNotice,
};
use sqlx::PgPool;
use uuid::Uuid;

// ─── DB ↔ enum helpers ────────────────────────────────────────────────────────

/// Decode an `impact_level` string (PascalCase as stored in the DB CHECK constraint)
/// into the engine `ImpactLevel`. The engine enum uses `#[serde(rename_all = "kebab-case")]`
/// so `serde_json::from_value` would expect `"med"`, not `"Med"` — we decode manually.
fn impact_from_db(raw: &str) -> Result<ImpactLevel, sqlx::Error> {
    match raw {
        "None" => Ok(ImpactLevel::None),
        "Low" => Ok(ImpactLevel::Low),
        "Med" => Ok(ImpactLevel::Med),
        "High" => Ok(ImpactLevel::High),
        "Critical" => Ok(ImpactLevel::Critical),
        other => Err(sqlx::Error::Decode(
            format!("outage_notices.impact_level: unknown value '{other}'").into(),
        )),
    }
}

/// Decode a `status` string (PascalCase as stored in the DB CHECK constraint)
/// into the engine `NoticeStatus`. Same kebab-case serde mismatch applies.
fn status_from_db(raw: &str) -> Result<NoticeStatus, sqlx::Error> {
    match raw {
        "Draft" => Ok(NoticeStatus::Draft),
        "Sent" => Ok(NoticeStatus::Sent),
        "Acknowledged" => Ok(NoticeStatus::Acknowledged),
        "Completed" => Ok(NoticeStatus::Completed),
        "Cancelled" => Ok(NoticeStatus::Cancelled),
        other => Err(sqlx::Error::Decode(
            format!("outage_notices.status: unknown value '{other}'").into(),
        )),
    }
}

// ─── Column list ─────────────────────────────────────────────────────────────

/// Main notice columns. id cast to text; timestamps decoded as DateTime<Utc>.
/// affected_systems is aggregated from the child table via a correlated subquery.
pub const COLUMNS: &str = "n.id::text AS id, \
     n.site, \
     n.start_time, \
     n.end_time, \
     n.impact_level, \
     n.message_template, \
     n.status, \
     n.sent_at, \
     n.acknowledged_by, \
     n.created_at, \
     n.updated_at, \
     COALESCE(ARRAY(SELECT s.system_name FROM outage_notice_systems s WHERE s.notice_id = n.id ORDER BY s.system_name), '{}') AS affected_systems";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct OutageNoticeRow {
    pub id: String,
    pub site: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub impact_level: String,
    pub message_template: String,
    pub status: String,
    pub sent_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub affected_systems: Vec<String>,
}

impl OutageNoticeRow {
    pub fn into_model(self) -> Result<OutageNotice, sqlx::Error> {
        let impact_level = impact_from_db(&self.impact_level)?;
        let status = status_from_db(&self.status)?;

        Ok(OutageNotice {
            id: self.id,
            site: self.site,
            affected_systems: self.affected_systems,
            start_time: self.start_time.to_rfc3339(),
            end_time: self.end_time.to_rfc3339(),
            impact_level,
            message_template: self.message_template,
            status,
            sent_at: self.sent_at.map(|dt| dt.to_rfc3339()),
            acknowledged_by: self.acknowledged_by,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
            // Metadata is not persisted in the DB; return empty vec for repo-loaded notices.
            metadata: vec![],
        })
    }
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List all notices, optionally filtered by site.
pub async fn list(pool: &PgPool, site: &str) -> Result<Vec<OutageNotice>, sqlx::Error> {
    let rows: Vec<OutageNoticeRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM outage_notices n ORDER BY n.created_at DESC"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM outage_notices n WHERE n.site = $1 ORDER BY n.created_at DESC"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Get a single notice by UUID string id. Malformed id → Ok(None).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<OutageNotice>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<OutageNoticeRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM outage_notices n WHERE n.id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// List active notices for a site: not Completed/Cancelled, end_time >= NOW().
pub async fn list_active(pool: &PgPool, site: &str) -> Result<Vec<OutageNotice>, sqlx::Error> {
    let rows: Vec<OutageNoticeRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM outage_notices n \
         WHERE n.site = $1 \
           AND n.status NOT IN ('Completed', 'Cancelled') \
           AND n.end_time >= NOW() \
         ORDER BY n.start_time"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List history (Completed or Cancelled) for a site.
pub async fn list_history(pool: &PgPool, site: &str) -> Result<Vec<OutageNotice>, sqlx::Error> {
    let rows: Vec<OutageNoticeRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM outage_notices n \
         WHERE n.site = $1 AND n.status IN ('Completed', 'Cancelled') \
         ORDER BY n.updated_at DESC"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List upcoming notices for a site: not Cancelled/Completed, start_time in [NOW(), NOW()+7d].
pub async fn list_upcoming(pool: &PgPool, site: &str) -> Result<Vec<OutageNotice>, sqlx::Error> {
    let rows: Vec<OutageNoticeRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM outage_notices n \
         WHERE n.site = $1 \
           AND n.status NOT IN ('Cancelled', 'Completed') \
           AND n.start_time >= NOW() \
           AND n.start_time <= NOW() + INTERVAL '7 days' \
         ORDER BY n.start_time"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Insert a new notice + its affected systems in a single transaction.
/// Returns the persisted notice (re-read through the aggregating query).
pub async fn insert(pool: &PgPool, notice: &OutageNotice) -> Result<OutageNotice, sqlx::Error> {
    let id = Uuid::new_v4();

    let start_time: DateTime<Utc> =
        chrono::DateTime::parse_from_rfc3339(&notice.start_time)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let end_time: DateTime<Utc> =
        chrono::DateTime::parse_from_rfc3339(&notice.end_time)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO outage_notices \
         (id, site, start_time, end_time, impact_level, message_template, status, \
          sent_at, acknowledged_by, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NOW(), NOW())",
    )
    .bind(id)
    .bind(&notice.site)
    .bind(start_time)
    .bind(end_time)
    .bind(notice.impact_level.to_string())
    .bind(&notice.message_template)
    .bind(notice.status.to_string())
    .execute(&mut *tx)
    .await?;

    for system in &notice.affected_systems {
        sqlx::query(
            "INSERT INTO outage_notice_systems (notice_id, system_name) VALUES ($1, $2)",
        )
        .bind(id)
        .bind(system)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    get(pool, &id.to_string()).await?.ok_or_else(|| {
        sqlx::Error::Decode("outage_notices: row vanished immediately after insert".into())
    })
}

/// CAS: transition notice to Sent (guard already verified by caller).
/// Returns Ok(None) on status mismatch → caller maps to 409.
pub async fn send(
    pool: &PgPool,
    id: &str,
    expected_status: &str,
) -> Result<Option<OutageNotice>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let affected = sqlx::query(
        "UPDATE outage_notices \
         SET status = 'Sent', sent_at = NOW(), updated_at = NOW() \
         WHERE id = $1 AND status = $2",
    )
    .bind(uid)
    .bind(expected_status)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Ok(None);
    }

    get(pool, id).await
}

/// CAS: transition notice to Acknowledged and record ack in child table.
/// Returns Ok(None) on status mismatch → caller maps to 409.
pub async fn acknowledge(
    pool: &PgPool,
    id: &str,
    user: &str,
    expected_status: &str,
) -> Result<Option<NoticeAckEvent>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let mut tx = pool.begin().await?;

    let affected = sqlx::query(
        "UPDATE outage_notices \
         SET status = 'Acknowledged', acknowledged_by = $2, updated_at = NOW() \
         WHERE id = $1 AND status = $3",
    )
    .bind(uid)
    .bind(user)
    .bind(expected_status)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        tx.rollback().await?;
        return Ok(None);
    }

    let acked_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO outage_notice_acknowledgments (notice_id, acknowledged_by, acknowledged_at) \
         VALUES ($1, $2, NOW()) RETURNING acknowledged_at",
    )
    .bind(uid)
    .bind(user)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(NoticeAckEvent {
        notice_id: id.to_string(),
        user: user.to_string(),
        acknowledged_at: acked_at.to_rfc3339(),
    }))
}

/// CAS: transition notice to Completed.
/// Returns Ok(None) on status mismatch → caller maps to 409.
pub async fn complete(
    pool: &PgPool,
    id: &str,
    expected_status: &str,
) -> Result<Option<OutageNotice>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let affected = sqlx::query(
        "UPDATE outage_notices \
         SET status = 'Completed', updated_at = NOW() \
         WHERE id = $1 AND status = $2",
    )
    .bind(uid)
    .bind(expected_status)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Ok(None);
    }

    get(pool, id).await
}

/// CAS: transition notice to Cancelled.
/// Returns Ok(None) on status mismatch → caller maps to 409.
pub async fn cancel(
    pool: &PgPool,
    id: &str,
    expected_status: &str,
) -> Result<Option<OutageNotice>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let affected = sqlx::query(
        "UPDATE outage_notices \
         SET status = 'Cancelled', updated_at = NOW() \
         WHERE id = $1 AND status = $2",
    )
    .bind(uid)
    .bind(expected_status)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Ok(None);
    }

    get(pool, id).await
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 outage_comms_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod outage_comms_db_tests {
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

    async fn cleanup_notice(pool: &PgPool, id: &str) {
        if let Ok(uid) = Uuid::parse_str(id) {
            sqlx::query("DELETE FROM outage_notices WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await
                .ok();
        }
    }

    fn make_notice(site: &str, systems: Vec<&str>) -> OutageNotice {
        OutageNotice {
            id: String::new(), // assigned by insert
            site: site.to_string(),
            affected_systems: systems.into_iter().map(String::from).collect(),
            start_time: "2026-09-01T10:00:00Z".to_string(),
            end_time: "2026-09-01T14:00:00Z".to_string(),
            impact_level: ImpactLevel::Med,
            message_template: "Maintenance on {{site}}. Systems: {{systems}}.".to_string(),
            status: NoticeStatus::Draft,
            sent_at: None,
            acknowledged_by: None,
            created_at: String::new(),
            updated_at: String::new(),
            metadata: vec![],
        }
    }

    #[tokio::test]
    async fn list_returns_seeded_notices() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Migration 042 seeds 3 notices across DEFRA, GBLON, FRPAR.
        let all = list(&pool, "").await.expect("list all");
        assert!(all.len() >= 3, "migration 042 seeds 3 notices");

        let defra = list(&pool, "DEFRA").await.expect("list DEFRA");
        assert!(!defra.is_empty());
        for n in &defra {
            assert_eq!(n.site, "DEFRA");
        }
    }

    #[tokio::test]
    async fn get_by_id_and_malformed_uuid() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let notice = make_notice("DEHAM", vec!["deham-app-01"]);
        let inserted = insert(&pool, &notice).await.expect("insert");

        let found = get(&pool, &inserted.id).await.expect("get");
        assert!(found.is_some(), "should find inserted notice");
        let found = found.unwrap();
        assert_eq!(found.site, "DEHAM");

        let malformed = get(&pool, "not-a-uuid").await.expect("get malformed");
        assert!(malformed.is_none(), "malformed uuid → Ok(None)");

        cleanup_notice(&pool, &inserted.id).await;
    }

    #[tokio::test]
    async fn create_round_trip_with_child_systems() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let notice = make_notice("NLAMS", vec!["nlams-app-01", "nlams-db-01"]);
        let inserted = insert(&pool, &notice).await.expect("insert");

        assert!(!inserted.id.is_empty());
        assert_eq!(inserted.site, "NLAMS");
        assert_eq!(inserted.status, NoticeStatus::Draft);

        // Child systems round-trip
        let mut systems = inserted.affected_systems.clone();
        systems.sort();
        assert_eq!(systems, vec!["nlams-app-01", "nlams-db-01"]);

        // Verify systems are in the child table
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM outage_notice_systems WHERE notice_id = $1")
                .bind(Uuid::parse_str(&inserted.id).unwrap())
                .fetch_one(&pool)
                .await
                .expect("count systems");
        assert_eq!(count, 2, "two child rows for two systems");

        cleanup_notice(&pool, &inserted.id).await;
    }

    #[tokio::test]
    async fn send_lifecycle_transition_and_cas_rejection() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let notice = make_notice("DEBER", vec!["deber-app-01"]);
        let inserted = insert(&pool, &notice).await.expect("insert");

        // Successful send: Draft → Sent
        let sent = send(&pool, &inserted.id, "Draft")
            .await
            .expect("send")
            .expect("send should succeed");
        assert_eq!(sent.status, NoticeStatus::Sent);
        assert!(sent.sent_at.is_some());

        // CAS rejection: notice is now Sent, not Draft anymore
        let miss = send(&pool, &inserted.id, "Draft")
            .await
            .expect("send miss");
        assert!(miss.is_none(), "stale expected_status → Ok(None) / 409");

        // Illegal transition guard (engine-level): try sending again via Sent status
        let miss2 = send(&pool, &inserted.id, "Sent")
            .await
            .expect("send Sent→Sent");
        // Engine guard isn't in the repo — the CAS here would succeed if we pass the right status.
        // The caller (handler) runs the engine guard before calling the repo.
        // Here we just confirm the CAS works correctly (succeeds on matching status).
        assert!(
            miss2.is_some(),
            "CAS matches Sent→Sent at repo level (engine guard is handler's responsibility)"
        );
        // Roll back to prevent state pollution
        cancel(&pool, &inserted.id, "Sent")
            .await
            .expect("cancel to clean up");

        cleanup_notice(&pool, &inserted.id).await;
    }

    #[tokio::test]
    async fn acknowledge_appends_child_row() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let notice = make_notice("FRPAR", vec!["frpar-core"]);
        let inserted = insert(&pool, &notice).await.expect("insert");

        // Must be Sent before acknowledging
        let _sent = send(&pool, &inserted.id, "Draft")
            .await
            .expect("send")
            .expect("send succeeded");

        let ack = acknowledge(&pool, &inserted.id, "alice.operator", "Sent")
            .await
            .expect("acknowledge")
            .expect("acknowledge succeeded");

        assert_eq!(ack.notice_id, inserted.id);
        assert_eq!(ack.user, "alice.operator");
        assert!(!ack.acknowledged_at.is_empty());

        // Verify child acknowledgment row exists
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM outage_notice_acknowledgments WHERE notice_id = $1",
        )
        .bind(Uuid::parse_str(&inserted.id).unwrap())
        .fetch_one(&pool)
        .await
        .expect("count acks");
        assert_eq!(count, 1, "one acknowledgment row inserted");

        // Verify parent notice status changed to Acknowledged
        let updated = get(&pool, &inserted.id)
            .await
            .expect("get")
            .expect("notice exists");
        assert_eq!(updated.status, NoticeStatus::Acknowledged);
        assert_eq!(updated.acknowledged_by, Some("alice.operator".into()));

        // CAS rejection: notice no longer in Sent status
        let miss = acknowledge(&pool, &inserted.id, "bob", "Sent")
            .await
            .expect("ack miss");
        assert!(miss.is_none(), "stale Sent status → Ok(None) / 409");

        cleanup_notice(&pool, &inserted.id).await;
    }

    #[tokio::test]
    async fn complete_and_cancel_transitions() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Complete path: Draft → Sent → Acknowledged → Completed
        let n1 = make_notice("GBLON", vec!["gblon-srv"]);
        let i1 = insert(&pool, &n1).await.expect("insert n1");
        send(&pool, &i1.id, "Draft").await.expect("send").expect("sent");
        acknowledge(&pool, &i1.id, "user", "Sent")
            .await
            .expect("ack")
            .expect("acked");
        let completed = complete(&pool, &i1.id, "Acknowledged")
            .await
            .expect("complete")
            .expect("completed");
        assert_eq!(completed.status, NoticeStatus::Completed);

        // Cancel path: Draft → Cancelled
        let n2 = make_notice("DEFRA", vec!["defra-srv"]);
        let i2 = insert(&pool, &n2).await.expect("insert n2");
        let cancelled = cancel(&pool, &i2.id, "Draft")
            .await
            .expect("cancel")
            .expect("cancelled");
        assert_eq!(cancelled.status, NoticeStatus::Cancelled);

        cleanup_notice(&pool, &i1.id).await;
        cleanup_notice(&pool, &i2.id).await;
    }
}
