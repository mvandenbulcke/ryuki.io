use ryuki_engine::notifications::{
    drafts_for_transition, plan_dispatch, DispatchChannel, Notification, NotificationDraft,
    RecipientKind, Severity,
};
use sqlx::types::Uuid;
use sqlx::{Connection, PgPool};

// ── DB row ───────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct NotificationRow {
    id: String,
    recipient_kind: String,
    recipient_id: String,
    event: String,
    request_id: Option<Uuid>,
    severity: String,
    title: String,
    body: String,
    created_at: chrono::DateTime<chrono::Utc>,
    /// Computed per-querying-user from the read-receipts table (NOT a column on
    /// portal_notifications): true iff this user has a receipt for the row.
    read: bool,
}

impl NotificationRow {
    fn into_model(self) -> Result<Notification, sqlx::Error> {
        let recipient_kind = recipient_kind_from_db(&self.recipient_kind)?;
        let severity = severity_from_db(&self.severity)?;
        Ok(Notification {
            id: self.id,
            recipient_kind,
            recipient_id: self.recipient_id,
            event: self.event,
            request_id: self.request_id.map(|u| u.to_string()),
            severity,
            title: self.title,
            body: self.body,
            read: self.read,
            created_at: self.created_at.to_rfc3339(),
        })
    }
}

// ── Enum helpers ─────────────────────────────────────────────────────────────

fn recipient_kind_from_db(raw: &str) -> Result<RecipientKind, sqlx::Error> {
    match raw {
        "Role" => Ok(RecipientKind::Role),
        "User" => Ok(RecipientKind::User),
        other => Err(sqlx::Error::Decode(
            format!("portal_notifications.recipient_kind: unknown value '{other}'").into(),
        )),
    }
}

fn recipient_kind_to_db(k: &RecipientKind) -> &'static str {
    match k {
        RecipientKind::Role => "Role",
        RecipientKind::User => "User",
    }
}

fn severity_from_db(raw: &str) -> Result<Severity, sqlx::Error> {
    match raw {
        "Info" => Ok(Severity::Info),
        "Success" => Ok(Severity::Success),
        "Warning" => Ok(Severity::Warning),
        "Critical" => Ok(Severity::Critical),
        other => Err(sqlx::Error::Decode(
            format!("portal_notifications.severity: unknown value '{other}'").into(),
        )),
    }
}

fn severity_to_db(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Success => "Success",
        Severity::Warning => "Warning",
        Severity::Critical => "Critical",
    }
}

// ── Outcome type ──────────────────────────────────────────────────────────────

pub enum MarkOutcome {
    Updated(Box<Notification>),
    NotFound,
}

// SELECT column list shared by the queries that build a NotificationRow. The
// `read` flag is supplied separately by each query (a LEFT JOIN test, or a
// literal after a mark), never read from a column on portal_notifications.
const READ_COLUMNS: &str = "n.id, n.recipient_kind, n.recipient_id, n.event, n.request_id, \
                            n.severity, n.title, n.body, n.created_at";

// ── Repo functions ────────────────────────────────────────────────────────────

/// Best-effort, post-commit emit. Calls the pure engine to derive drafts, then
/// INSERTs one row per draft. Caller swallows errors (fail-open contract).
pub async fn emit_for_transition(
    pool: &PgPool,
    action: &str,
    request_id: &str,
    owner: Option<&str>,
) -> Result<(), sqlx::Error> {
    let drafts = drafts_for_transition(action, request_id, owner);
    if drafts.is_empty() {
        return Ok(());
    }

    let rid: Option<Uuid> = Uuid::parse_str(request_id).ok();

    let mut tx = pool.begin().await?;
    for draft in &drafts {
        let id = format!("pn-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO portal_notifications \
             (id, recipient_kind, recipient_id, event, request_id, severity, title, body) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&id)
        .bind(recipient_kind_to_db(&draft.recipient_kind))
        .bind(&draft.recipient_id)
        .bind(&draft.event)
        .bind(rid)
        .bind(severity_to_db(&draft.severity))
        .bind(&draft.title)
        .bind(&draft.body)
        .execute(&mut *tx)
        .await?;
        // Dry-run dispatch plan — best-effort + savepoint-isolated, so an outbox
        // failure can never roll back the in-app notification just inserted.
        record_dispatch_plan_best_effort(&mut tx, &id, &plan_dispatch(draft)).await;
        // (`&mut tx` deref-coerces to `&mut PgConnection`; the helper opens a SAVEPOINT.)
    }
    tx.commit().await?;
    Ok(())
}

/// Record the dry-run dispatch plan for a just-inserted notification, BEST-EFFORT.
///
/// The dry-run outbox is STRICTLY SUBORDINATE to the in-app notification (and to
/// any operational-alert tx it rides in): a failure here must NEVER roll back the
/// notification. In Postgres a single failed statement aborts the entire
/// surrounding transaction, so the inserts run inside a SAVEPOINT (sqlx nested
/// tx) which is explicitly rolled back — and the failure swallowed + logged — on
/// any error, leaving the outer tx (the notification/alert) intact. A
/// connection-level failure or an already-aborted outer tx cannot be made
/// fail-open here, by definition. `channels` empty (the common Info/Success path)
/// opens no savepoint at all.
async fn record_dispatch_plan_best_effort(
    conn: &mut sqlx::PgConnection,
    notification_id: &str,
    channels: &[DispatchChannel],
) {
    if channels.is_empty() {
        return;
    }
    let mut sp = match conn.begin().await {
        Ok(sp) => sp,
        Err(e) => {
            tracing::warn!(
                error = %e,
                notification_id,
                "dispatch-outbox: could not open savepoint; skipping plan (notification preserved)"
            );
            return;
        }
    };
    for ch in channels {
        let id = format!("ndo-{}", uuid::Uuid::new_v4());
        if let Err(e) = sqlx::query(
            "INSERT INTO notification_dispatch_outbox (id, notification_id, channel, status) \
             VALUES ($1, $2, $3, 'dry_run_logged') \
             ON CONFLICT (notification_id, channel) DO NOTHING",
        )
        .bind(&id)
        .bind(notification_id)
        .bind(ch.as_db())
        .execute(&mut *sp)
        .await
        {
            tracing::warn!(
                error = %e,
                notification_id,
                channel = ch.as_db(),
                "dispatch-outbox: plan insert failed; rolling back savepoint (notification preserved)"
            );
            let _ = sp.rollback().await;
            return;
        }
    }
    if let Err(e) = sp.commit().await {
        tracing::warn!(
            error = %e,
            notification_id,
            "dispatch-outbox: savepoint release failed (notification preserved)"
        );
    }
}

// ── Dispatch outbox (dry-run telemetry) ────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DispatchOutboxRow {
    id: String,
    notification_id: String,
    channel: String,
    status: String,
    planned_at: chrono::DateTime<chrono::Utc>,
    dispatched_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// List notification-dispatch-outbox rows newest-first for the admin telemetry
/// view. `status` filters when `Some` (the handler validates it against the
/// allowlist first); `limit` is the handler's clamped cap. Returns ONLY the
/// dispatch metadata — no notification body / recipient / target is joined, so
/// nothing sensitive leaves through this view.
pub async fn list_dispatch_outbox(
    pool: &PgPool,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows: Vec<DispatchOutboxRow> = match status {
        Some(s) => {
            sqlx::query_as(
                "SELECT id, notification_id, channel, status, planned_at, dispatched_at \
             FROM notification_dispatch_outbox WHERE status = $1 \
             ORDER BY planned_at DESC LIMIT $2",
            )
            .bind(s)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as(
                "SELECT id, notification_id, channel, status, planned_at, dispatched_at \
             FROM notification_dispatch_outbox \
             ORDER BY planned_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "notification_id": r.notification_id,
                "channel": r.channel,
                "status": r.status,
                "planned_at": r.planned_at.to_rfc3339(),
                "dispatched_at": r.dispatched_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect())
}

/// Persist one notification draft within the caller's transaction (#11 slice 2f).
/// Lets an emitter write an operational-alert notification ATOMICALLY with the
/// domain event + dedup flag it just wrote (no notification without the alert,
/// and none lost after). `request_id` is `None` for operational alerts.
pub async fn insert_draft_tx(
    conn: &mut sqlx::PgConnection,
    draft: &NotificationDraft,
    request_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let id = format!("pn-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO portal_notifications \
         (id, recipient_kind, recipient_id, event, request_id, severity, title, body) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(recipient_kind_to_db(&draft.recipient_kind))
    .bind(&draft.recipient_id)
    .bind(&draft.event)
    .bind(request_id)
    .bind(severity_to_db(&draft.severity))
    .bind(&draft.title)
    .bind(&draft.body)
    .execute(&mut *conn)
    .await?;
    // Dry-run dispatch plan — best-effort + savepoint-isolated, so an outbox
    // failure can NEVER abort the caller's atomic alert+event transaction.
    record_dispatch_plan_best_effort(conn, &id, &plan_dispatch(draft)).await;
    Ok(())
}

/// Returns the recipient's notification feed, newest first. The `read` flag is
/// resolved per-user from the read-receipts table (LEFT JOIN on this user_id),
/// so a shared role notification reads independently for each recipient.
pub async fn list_for_recipient(
    pool: &PgPool,
    user_id: &str,
    roles: &[String],
) -> Result<Vec<Notification>, sqlx::Error> {
    let sql = format!(
        "SELECT {READ_COLUMNS}, (r.notification_id IS NOT NULL) AS \"read\" \
         FROM portal_notifications n \
         LEFT JOIN portal_notification_reads r \
                ON r.notification_id = n.id AND r.user_id = $1 \
         WHERE (n.recipient_kind = 'User' AND n.recipient_id = $1) \
            OR (n.recipient_kind = 'Role' AND n.recipient_id = ANY($2)) \
         ORDER BY n.created_at DESC \
         LIMIT 200"
    );
    let rows: Vec<NotificationRow> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(roles)
        .fetch_all(pool)
        .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// COUNT of notifications visible to the recipient that this user has NOT yet
/// read (no receipt row for this user_id).
pub async fn unread_count(
    pool: &PgPool,
    user_id: &str,
    roles: &[String],
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) \
         FROM portal_notifications n \
         WHERE ((n.recipient_kind = 'User' AND n.recipient_id = $1) \
             OR (n.recipient_kind = 'Role' AND n.recipient_id = ANY($2))) \
           AND NOT EXISTS ( \
               SELECT 1 FROM portal_notification_reads r \
               WHERE r.notification_id = n.id AND r.user_id = $1 \
           )",
    )
    .bind(user_id)
    .bind(roles)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Atomically record a read receipt for ONE notification on behalf of `user_id`.
///
/// The CTE's `visible` filter is the authorization boundary: a non-recipient
/// matches zero rows and gets NotFound (no existence leak). The receipt INSERT
/// is idempotent (ON CONFLICT DO NOTHING), so re-marking an already-read
/// notification is a no-op that still returns Updated. The receipt is per-user,
/// so marking a shared role notification read does NOT clear it for other role
/// holders.
pub async fn mark_read(
    pool: &PgPool,
    id: &str,
    user_id: &str,
    roles: &[String],
) -> Result<MarkOutcome, sqlx::Error> {
    let row: Option<NotificationRow> = sqlx::query_as(
        "WITH visible AS ( \
             SELECT n.id, n.recipient_kind, n.recipient_id, n.event, n.request_id, \
                    n.severity, n.title, n.body, n.created_at \
             FROM portal_notifications n \
             WHERE n.id = $1 \
               AND ((n.recipient_kind = 'User' AND n.recipient_id = $2) \
                 OR (n.recipient_kind = 'Role' AND n.recipient_id = ANY($3))) \
         ), ins AS ( \
             INSERT INTO portal_notification_reads (notification_id, user_id) \
             SELECT id, $2 FROM visible \
             ON CONFLICT (notification_id, user_id) DO NOTHING \
         ) \
         SELECT id, recipient_kind, recipient_id, event, request_id, \
                severity, title, body, created_at, TRUE AS \"read\" \
         FROM visible",
    )
    .bind(id)
    .bind(user_id)
    .bind(roles)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(MarkOutcome::Updated(Box::new(r.into_model()?))),
        None => Ok(MarkOutcome::NotFound),
    }
}

/// Record read receipts for ALL of this user's currently-unread visible
/// notifications. Returns the number of receipts newly inserted.
pub async fn mark_all_read(
    pool: &PgPool,
    user_id: &str,
    roles: &[String],
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO portal_notification_reads (notification_id, user_id) \
         SELECT n.id, $1 \
         FROM portal_notifications n \
         WHERE ((n.recipient_kind = 'User' AND n.recipient_id = $1) \
             OR (n.recipient_kind = 'Role' AND n.recipient_id = ANY($2))) \
           AND NOT EXISTS ( \
               SELECT 1 FROM portal_notification_reads r \
               WHERE r.notification_id = n.id AND r.user_id = $1 \
           ) \
         ON CONFLICT (notification_id, user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(roles)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete notifications past their retention window, OLDEST FIRST, in one
/// bounded DELETE (retention fix for the unbounded portal_notifications feed;
/// index: mig 156). Returns the rows deleted. Per-user read receipts and
/// dry-run dispatch-outbox rows go with each notification via the existing
/// ON DELETE CASCADE FKs (migs 083 / 128).
///
/// Policy: a notification expires `retention_days` after creation when it is
/// READ (at least one receipt row exists — for a Role-targeted row ANY member's
/// receipt counts as acknowledged; role membership is not enumerable, see mig
/// 083) or when it is not Critical. An UNREAD (zero receipts) Critical
/// notification is retained for the longer `critical_unread_retention_days`,
/// then pruned unconditionally — a hard cap so the table stays bounded even
/// when nobody ever acknowledges.
///
/// Concurrency + failure posture: a single statement with a `LIMIT`ed id
/// subquery (the `prune_resolved_shift_queue` idiom), so a concurrent run on
/// another replica simply deletes a disjoint-or-empty set — no error, no
/// double-effect — and a cancelled/failed run leaves nothing partial. Uses
/// DB-server time only (`NOW()`), no client clock. Deterministic order via the
/// `id` tie-breaker.
pub async fn prune_expired(
    pool: &PgPool,
    retention_days: i64,
    critical_unread_retention_days: i64,
    max_per_run: i64,
) -> Result<u64, sqlx::Error> {
    // Fail-safe on nonsensical parameters: prune NOTHING (never everything).
    // A critical window shorter than the standard window would silently demote
    // the unread-Critical carve-out, so it is rejected the same way.
    if retention_days <= 0 || critical_unread_retention_days < retention_days || max_per_run <= 0 {
        return Ok(0);
    }
    // The outer DELETE reasserts the eligibility predicate (the
    // prune_resolved_shift_queue idiom) so a row mutated between the subquery
    // snapshot and the delete can never be removed while ineligible.
    let deleted = sqlx::query(
        "DELETE FROM portal_notifications \
         WHERE id IN ( \
             SELECT n.id FROM portal_notifications n \
             WHERE n.created_at < NOW() - ($1::bigint * INTERVAL '1 day') \
               AND (n.severity <> 'Critical' \
                 OR n.created_at < NOW() - ($2::bigint * INTERVAL '1 day') \
                 OR EXISTS (SELECT 1 FROM portal_notification_reads r \
                            WHERE r.notification_id = n.id)) \
             ORDER BY n.created_at ASC, n.id ASC \
             LIMIT $3 \
         ) \
         AND created_at < NOW() - ($1::bigint * INTERVAL '1 day') \
         AND (severity <> 'Critical' \
           OR created_at < NOW() - ($2::bigint * INTERVAL '1 day') \
           OR EXISTS (SELECT 1 FROM portal_notification_reads r2 \
                      WHERE r2.notification_id = portal_notifications.id))",
    )
    .bind(retention_days)
    .bind(critical_unread_retention_days)
    .bind(max_per_run)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(deleted)
}

// ── DB integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod notifications_db_tests {
    use super::*;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("notifications_db_tests: RYUKI_DATABASE_URL not set — skipping");
                return None;
            }
        };
        let db = PgPool::connect(&url).await.expect("DB connection failed");
        crate::database::run_migrations(&db)
            .await
            .expect("migrations must apply");
        Some(db)
    }

    /// Delete the notifications inserted by a test (CASCADE removes their
    /// receipts), identified by a unique recipient_id used only by that test.
    async fn cleanup_recipient(pool: &PgPool, recipient_id: &str) {
        sqlx::query("DELETE FROM portal_notifications WHERE recipient_id = $1")
            .bind(recipient_id)
            .execute(pool)
            .await
            .expect("cleanup failed");
    }

    // ── emit + list + unread_count ────────────────────────────────────────────

    #[tokio::test]
    async fn emit_approve_is_visible_to_owner() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-approve-001";
        let rid = "00000000-0000-0000-0000-000000000001";

        emit_for_transition(&pool, "request.approve", rid, Some(owner))
            .await
            .expect("emit must not fail");

        let items = list_for_recipient(&pool, owner, &[])
            .await
            .expect("list must not fail");
        let found = items
            .iter()
            .find(|n| n.recipient_id == owner && n.event == "request.approve")
            .expect("emitted notification must appear in the owner's feed");
        assert!(!found.read, "a freshly emitted notification is unread");

        let count = unread_count(&pool, owner, &[])
            .await
            .expect("unread_count must not fail");
        assert!(count >= 1, "unread count must be at least 1");

        cleanup_recipient(&pool, owner).await;
    }

    #[tokio::test]
    async fn emit_plan_is_visible_to_approver_role() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let rid = "00000000-0000-0000-0000-000000000002";
        emit_for_transition(&pool, "request.plan", rid, None)
            .await
            .expect("emit must not fail");

        let items =
            list_for_recipient(&pool, "x-no-such-user", &["DatacenterApprover".to_string()])
                .await
                .expect("list must not fail");
        assert!(
            items
                .iter()
                .any(|n| n.recipient_id == "DatacenterApprover" && n.event == "request.plan"),
            "plan notification must appear for a session that holds the DatacenterApprover role"
        );

        sqlx::query("DELETE FROM portal_notifications WHERE recipient_id = 'DatacenterApprover' AND event = 'request.plan' AND request_id = $1::uuid")
            .bind(rid)
            .execute(&pool)
            .await
            .expect("cleanup failed");
    }

    #[tokio::test]
    async fn emit_unmapped_action_inserts_nothing() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-lock-001";
        let rid = "00000000-0000-0000-0000-000000000003";

        let before = list_for_recipient(&pool, owner, &[])
            .await
            .expect("list before")
            .len();

        emit_for_transition(&pool, "request.lock", rid, Some(owner))
            .await
            .expect("emit must not fail (fail-open means no error)");

        let after = list_for_recipient(&pool, owner, &[])
            .await
            .expect("list after")
            .len();

        assert_eq!(before, after, "unmapped action must insert nothing");
    }

    // ── mark_read: auth + idempotency ─────────────────────────────────────────

    #[tokio::test]
    async fn mark_read_idempotent_and_auth() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-markread-001";
        let other = "test-owner-markread-other";
        let rid = "00000000-0000-0000-0000-000000000004";

        emit_for_transition(&pool, "request.approve", rid, Some(owner))
            .await
            .expect("emit");

        let items = list_for_recipient(&pool, owner, &[]).await.expect("list");
        let notif = items
            .iter()
            .find(|n| n.recipient_id == owner && n.event == "request.approve")
            .expect("notification must be present");
        let nid = notif.id.clone();

        // Non-recipient cannot mark it read (auth boundary is the CTE filter).
        let non_owner_result = mark_read(&pool, &nid, other, &[])
            .await
            .expect("mark_read must not err");
        assert!(
            matches!(non_owner_result, MarkOutcome::NotFound),
            "non-recipient must get NotFound"
        );

        // Owner marks it read.
        let first = mark_read(&pool, &nid, owner, &[])
            .await
            .expect("mark_read must not err");
        assert!(
            matches!(first, MarkOutcome::Updated(_)),
            "first mark_read must return Updated"
        );

        // Idempotent: marking an already-read notification read again is a no-op
        // that still returns Updated (the receipt already exists).
        let second = mark_read(&pool, &nid, owner, &[])
            .await
            .expect("mark_read must not err");
        assert!(
            matches!(second, MarkOutcome::Updated(_)),
            "re-marking is idempotent and returns Updated"
        );

        let count = unread_count(&pool, owner, &[]).await.expect("unread");
        assert_eq!(
            count, 0,
            "owner has no unread after marking the only one read"
        );

        cleanup_recipient(&pool, owner).await;
    }

    // ── per-user read isolation on a SHARED role notification ──────────────────

    #[tokio::test]
    async fn role_notification_read_is_per_user() {
        let Some(pool) = test_pool().await else {
            return;
        };
        // A bespoke role used only by this test, so the seed DatacenterApprover
        // rows do not interfere.
        let role = "test-role-isolation-001";
        let rid = "00000000-0000-0000-0000-000000000007";

        // A role-targeted notification is ONE shared row (mirrors what the plan
        // path emits for DatacenterApprover, but with an isolated role).
        let nid = format!("pn-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO portal_notifications \
             (id, recipient_kind, recipient_id, event, request_id, severity, title, body) \
             VALUES ($1, 'Role', $2, 'request.plan', $3::uuid, 'Info', 'Awaiting approval', 'A request awaits approval.')",
        )
        .bind(&nid)
        .bind(role)
        .bind(rid)
        .execute(&pool)
        .await
        .expect("seed role notification");

        let roles = [role.to_string()];

        // User A (holds the role) marks the shared notification read.
        let marked = mark_read(&pool, &nid, "user-a", &roles)
            .await
            .expect("mark_read");
        assert!(matches!(marked, MarkOutcome::Updated(_)));

        // For user A it now reads true; for user B (same role) it stays unread.
        let a_view = list_for_recipient(&pool, "user-a", &roles)
            .await
            .expect("list A");
        let a_row = a_view.iter().find(|n| n.id == nid).expect("A sees it");
        assert!(a_row.read, "user A has read the shared role notification");

        let b_view = list_for_recipient(&pool, "user-b", &roles)
            .await
            .expect("list B");
        let b_row = b_view.iter().find(|n| n.id == nid).expect("B sees it");
        assert!(
            !b_row.read,
            "user B must still see the shared role notification as UNREAD"
        );
        assert!(
            unread_count(&pool, "user-b", &roles)
                .await
                .expect("unread B")
                >= 1,
            "user B's unread count must still include the role notification"
        );

        cleanup_recipient(&pool, role).await;
    }

    // ── mark_all_read ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mark_all_read_clears_unread() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-markall-001";
        let rid1 = "00000000-0000-0000-0000-000000000005";
        let rid2 = "00000000-0000-0000-0000-000000000006";

        emit_for_transition(&pool, "request.approve", rid1, Some(owner))
            .await
            .expect("emit 1");
        emit_for_transition(&pool, "request.reject", rid2, Some(owner))
            .await
            .expect("emit 2");

        let before = unread_count(&pool, owner, &[])
            .await
            .expect("unread before");
        assert!(before >= 2, "must have at least 2 unread");

        mark_all_read(&pool, owner, &[])
            .await
            .expect("mark_all_read must not fail");

        let after = unread_count(&pool, owner, &[]).await.expect("unread after");
        assert_eq!(after, 0, "unread count must be 0 after mark_all_read");

        cleanup_recipient(&pool, owner).await;
    }

    // ── dispatch outbox (dry-run) ─────────────────────────────────────────────

    /// Count the outbox rows planned for a given recipient's notifications, via a
    /// join so the assertion is isolated to the test's own recipient_id.
    async fn outbox_rows_for(pool: &PgPool, recipient_id: &str) -> Vec<(String, String)> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT o.channel, o.status FROM notification_dispatch_outbox o \
             JOIN portal_notifications n ON n.id = o.notification_id \
             WHERE n.recipient_id = $1 ORDER BY o.channel",
        )
        .bind(recipient_id)
        .fetch_all(pool)
        .await
        .expect("outbox query")
    }

    #[tokio::test]
    async fn reject_emits_webhook_dry_run_dispatch_plan() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-ndo-reject-001";
        let rid = "00000000-0000-0000-0000-0000000000a1";

        emit_for_transition(&pool, "request.reject", rid, Some(owner))
            .await
            .expect("emit reject");

        let rows = outbox_rows_for(&pool, owner).await;
        assert_eq!(
            rows.len(),
            1,
            "a Warning notification plans exactly one channel"
        );
        assert_eq!(rows[0].0, "webhook", "Warning routes to webhook");
        assert_eq!(rows[0].1, "dry_run_logged", "slice 1 only records dry-run");

        cleanup_recipient(&pool, owner).await;
    }

    #[tokio::test]
    async fn approve_emits_no_dispatch_plan() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-ndo-approve-001";
        let rid = "00000000-0000-0000-0000-0000000000a2";

        emit_for_transition(&pool, "request.approve", rid, Some(owner))
            .await
            .expect("emit approve");

        // Success severity → in-app only → zero outbox rows.
        assert!(
            outbox_rows_for(&pool, owner).await.is_empty(),
            "a Success notification dispatches no external channel"
        );

        cleanup_recipient(&pool, owner).await;
    }

    #[tokio::test]
    async fn dispatch_plan_is_idempotent_per_channel() {
        use ryuki_engine::notifications::DispatchChannel;
        let Some(pool) = test_pool().await else {
            return;
        };
        let recipient = "test-recip-ndo-idem-001";
        let nid = format!("pn-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO portal_notifications \
             (id, recipient_kind, recipient_id, event, severity, title, body) \
             VALUES ($1, 'User', $2, 'request.reject', 'Warning', 't', 'b')",
        )
        .bind(&nid)
        .bind(recipient)
        .execute(&pool)
        .await
        .expect("seed notification");

        // Two plan-recordings for the same (notification, channel) → one row.
        let mut tx = pool.begin().await.expect("tx");
        record_dispatch_plan_best_effort(&mut tx, &nid, &[DispatchChannel::Webhook]).await;
        record_dispatch_plan_best_effort(&mut tx, &nid, &[DispatchChannel::Webhook]).await;
        tx.commit().await.expect("commit");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_dispatch_outbox WHERE notification_id = $1",
        )
        .bind(&nid)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(
            count, 1,
            "UNIQUE(notification_id, channel) + ON CONFLICT dedups"
        );

        cleanup_recipient(&pool, recipient).await;
    }

    /// FAIL-OPEN regression (codex BLOCKER): if the outbox insert fails inside the
    /// helper, the SAVEPOINT rollback must keep the OUTER tx usable so the in-app
    /// notification still commits. Force the failure with a bogus notification_id
    /// (an FK violation on the outbox insert) while a REAL notification rides in
    /// the same outer tx.
    #[tokio::test]
    async fn outbox_failure_does_not_roll_back_the_notification() {
        use ryuki_engine::notifications::DispatchChannel;
        let Some(pool) = test_pool().await else {
            return;
        };
        let recipient = "test-recip-ndo-failopen-001";
        let real_nid = format!("pn-{}", uuid::Uuid::new_v4());

        let mut tx = pool.begin().await.expect("tx");
        // A REAL notification in the outer tx.
        sqlx::query(
            "INSERT INTO portal_notifications \
             (id, recipient_kind, recipient_id, event, severity, title, body) \
             VALUES ($1, 'User', $2, 'request.reject', 'Warning', 't', 'b')",
        )
        .bind(&real_nid)
        .bind(recipient)
        .execute(&mut *tx)
        .await
        .expect("insert real notification");

        // Plan against a NON-EXISTENT notification id → the outbox INSERT hits the
        // FK and fails INSIDE the savepoint. The helper must swallow it.
        record_dispatch_plan_best_effort(
            &mut tx,
            "pn-does-not-exist-00000000",
            &[DispatchChannel::Webhook],
        )
        .await;

        // The crux: the outer tx is still usable and COMMITS the real notification.
        tx.commit()
            .await
            .expect("outer tx must still commit after the savepoint rollback");

        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM portal_notifications WHERE id = $1")
                .bind(&real_nid)
                .fetch_one(&pool)
                .await
                .expect("count notification");
        assert_eq!(
            exists, 1,
            "the in-app notification survived the outbox failure"
        );

        let bogus_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_dispatch_outbox WHERE notification_id = $1",
        )
        .bind("pn-does-not-exist-00000000")
        .fetch_one(&pool)
        .await
        .expect("count bogus outbox");
        assert_eq!(
            bogus_rows, 0,
            "the failed outbox row was rolled back, not written"
        );

        cleanup_recipient(&pool, recipient).await;
    }

    #[tokio::test]
    async fn list_dispatch_outbox_filters_by_status() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let owner = "test-owner-ndo-list-001";
        let rid = "00000000-0000-0000-0000-0000000000a3";
        emit_for_transition(&pool, "request.reject", rid, Some(owner))
            .await
            .expect("emit reject");

        // The dry-run row appears under its own status, and not under another.
        let dry = list_dispatch_outbox(&pool, Some("dry_run_logged"), 50)
            .await
            .expect("list dry_run");
        assert!(
            dry.iter().any(|d| d["channel"] == "webhook"),
            "the dry-run row is listed under dry_run_logged"
        );
        let sent = list_dispatch_outbox(&pool, Some("sent"), 50)
            .await
            .expect("list sent");
        // None of THIS owner's rows are 'sent' (slice 1 never sends).
        let sent_for_owner = outbox_rows_for(&pool, owner)
            .await
            .into_iter()
            .filter(|(_, status)| status == "sent")
            .count();
        assert_eq!(sent_for_owner, 0, "slice 1 records no 'sent' rows");
        let _ = sent; // the global 'sent' list may legitimately contain other tests' rows

        cleanup_recipient(&pool, owner).await;
    }

    // ── retention prune ───────────────────────────────────────────────────────

    /// Seed one notification with an EXPLICIT past `created_at` (repo lesson:
    /// never rely on NOW()-relative seed rows staying "old" — pin the age at
    /// insert time) and return its id.
    async fn seed_aged(pool: &PgPool, recipient: &str, severity: &str, age_days: i64) -> String {
        let id = format!("pn-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO portal_notifications \
             (id, recipient_kind, recipient_id, event, severity, title, body, created_at) \
             VALUES ($1, 'User', $2, 'request.approve', $3, 't', 'b', \
                     NOW() - ($4::bigint * INTERVAL '1 day'))",
        )
        .bind(&id)
        .bind(recipient)
        .bind(severity)
        .bind(age_days)
        .execute(pool)
        .await
        .expect("seed aged notification");
        id
    }

    async fn add_receipt(pool: &PgPool, notification_id: &str, user_id: &str) {
        sqlx::query(
            "INSERT INTO portal_notification_reads (notification_id, user_id) VALUES ($1, $2)",
        )
        .bind(notification_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed read receipt");
    }

    async fn add_outbox_row(pool: &PgPool, notification_id: &str) {
        sqlx::query(
            "INSERT INTO notification_dispatch_outbox (id, notification_id, channel, status) \
             VALUES ($1, $2, 'webhook', 'dry_run_logged')",
        )
        .bind(format!("ndo-{}", uuid::Uuid::new_v4()))
        .bind(notification_id)
        .execute(pool)
        .await
        .expect("seed outbox row");
    }

    async fn notification_exists(pool: &PgPool, id: &str) -> bool {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM portal_notifications WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("existence query");
        count == 1
    }

    async fn child_rows(pool: &PgPool, id: &str) -> (i64, i64) {
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM portal_notification_reads WHERE notification_id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("receipts count");
        let outbox: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_dispatch_outbox WHERE notification_id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("outbox count");
        (receipts, outbox)
    }

    #[tokio::test]
    async fn retention_prunes_old_read_keeps_recent_and_cascades() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let recipient = "test-recip-retention-basic-001";

        // Expired (120d > 90d), READ, with a dispatch-outbox child row.
        let old_read = seed_aged(&pool, recipient, "Info", 120).await;
        add_receipt(&pool, &old_read, recipient).await;
        add_outbox_row(&pool, &old_read).await;
        // Expired UNREAD non-Critical: the carve-out is Critical-only.
        let old_unread = seed_aged(&pool, recipient, "Warning", 120).await;
        // Recent (10d < 90d): kept regardless of read state.
        let recent = seed_aged(&pool, recipient, "Info", 10).await;

        let pruned = prune_expired(&pool, 90, 365, 20_000)
            .await
            .expect("prune must not fail");
        assert!(pruned >= 2, "both expired rows pruned (got {pruned})");

        assert!(
            !notification_exists(&pool, &old_read).await,
            "old READ notification is pruned"
        );
        assert!(
            !notification_exists(&pool, &old_unread).await,
            "old unread NON-Critical notification is pruned"
        );
        assert!(
            notification_exists(&pool, &recent).await,
            "recent notification is kept"
        );
        let (receipts, outbox) = child_rows(&pool, &old_read).await;
        assert_eq!(receipts, 0, "read receipts cascade with the notification");
        assert_eq!(outbox, 0, "outbox rows cascade with the notification");

        cleanup_recipient(&pool, recipient).await;
    }

    #[tokio::test]
    async fn retention_unread_critical_kept_until_hard_cap() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let recipient = "test-recip-retention-critical-001";

        // Past the standard window but UNREAD Critical → carve-out keeps it.
        let unread_within_cap = seed_aged(&pool, recipient, "Critical", 120).await;
        // Past even the hard cap (400d > 365d) → pruned despite being unread.
        let unread_past_cap = seed_aged(&pool, recipient, "Critical", 400).await;
        // READ Critical past the standard window → acknowledged, pruned at 90d.
        let read_old = seed_aged(&pool, recipient, "Critical", 120).await;
        add_receipt(&pool, &read_old, recipient).await;

        prune_expired(&pool, 90, 365, 20_000)
            .await
            .expect("prune must not fail");

        assert!(
            notification_exists(&pool, &unread_within_cap).await,
            "unread Critical younger than the hard cap is KEPT"
        );
        assert!(
            !notification_exists(&pool, &unread_past_cap).await,
            "unread Critical past the hard cap is pruned"
        );
        assert!(
            !notification_exists(&pool, &read_old).await,
            "READ Critical past the standard window is pruned"
        );

        cleanup_recipient(&pool, recipient).await;
    }

    #[tokio::test]
    async fn retention_batch_cap_prunes_oldest_first() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let recipient = "test-recip-retention-batch-001";

        let oldest = seed_aged(&pool, recipient, "Info", 300).await;
        let middle = seed_aged(&pool, recipient, "Info", 200).await;
        let newest_expired = seed_aged(&pool, recipient, "Info", 100).await;

        // Cap 2: at most two rows are deleted in one run, oldest first. A
        // SHARED DB may hold other tests' expired rows that are globally older
        // than these three, so the deterministic assertions are (a) the cap
        // bound — at least one of THIS test's three rows survives — and (b) the
        // oldest-first ORDER: the deleted set is a PREFIX of (created_at, id)
        // order, so a deleted row implies every strictly-older sibling was
        // deleted too.
        prune_expired(&pool, 90, 365, 2).await.expect("prune 1");
        let oldest_kept = notification_exists(&pool, &oldest).await;
        let middle_kept = notification_exists(&pool, &middle).await;
        let newest_kept = notification_exists(&pool, &newest_expired).await;
        assert!(
            oldest_kept || middle_kept || newest_kept,
            "a cap of 2 cannot delete all three expired rows in one run"
        );
        assert!(
            middle_kept || !oldest_kept,
            "oldest-first: middle deleted implies oldest deleted"
        );
        assert!(
            newest_kept || !middle_kept,
            "oldest-first: newest deleted implies middle deleted"
        );

        // Drain with the production cap — repeated runs converge until this
        // test's whole expired backlog is gone (bounded batches make progress).
        for _ in 0..3 {
            prune_expired(&pool, 90, 365, 20_000)
                .await
                .expect("prune drain");
        }
        assert!(!notification_exists(&pool, &oldest).await, "oldest drained");
        assert!(!notification_exists(&pool, &middle).await, "middle drained");
        assert!(
            !notification_exists(&pool, &newest_expired).await,
            "newest expired drained"
        );

        cleanup_recipient(&pool, recipient).await;
    }

    #[tokio::test]
    async fn retention_nonsense_config_prunes_nothing() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let recipient = "test-recip-retention-guard-001";
        let old = seed_aged(&pool, recipient, "Info", 500).await;

        // Fail-safe guards: each nonsensical parameter set deletes NOTHING.
        for (window, cap_window, batch) in [
            (0, 365, 20_000),  // zero standard window
            (-1, 365, 20_000), // negative window
            (90, 30, 20_000),  // critical cap SHORTER than the standard window
            (90, 365, 0),      // zero batch
        ] {
            let pruned = prune_expired(&pool, window, cap_window, batch)
                .await
                .expect("guarded prune must not fail");
            assert_eq!(
                pruned, 0,
                "guard ({window},{cap_window},{batch}) is a no-op"
            );
        }
        assert!(
            notification_exists(&pool, &old).await,
            "row survives every guarded no-op"
        );

        cleanup_recipient(&pool, recipient).await;
    }
}
