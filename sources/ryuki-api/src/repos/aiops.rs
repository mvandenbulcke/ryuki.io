//! Repository functions for `aiops_suggestions`.
//!
//! # ID type
//! `aiops_suggestions.id` is a TEXT PK (e.g. `'aiops-0001'`). Ids are bound
//! and decoded directly as `String` — no `Uuid::parse_str`.
//!
//! # Enum encoding
//! `suggestion_type` and `status` are stored in PascalCase DB form
//! (e.g. `'RightSizing'`, `'New'`).  The engine's serde derive uses
//! `rename_all = "snake_case"` so `serde_json::from_value(Value::String("RightSizing"))`
//! would fail.  We decode via the explicit `suggestion_type_from_db` /
//! `suggestion_status_from_db` match helpers exported from the engine, and
//! bind writes via `suggestion_type_to_db` / `suggestion_status_to_db`.
//!
//! # TEXT[] — affected_components
//! `affected_components TEXT[]` is decoded directly into `Vec<String>` by sqlx
//! (no JSON intermediary, no `::text` cast).  Writes bind a `&[String]` slice
//! which sqlx encodes as the Postgres array wire type.
//!
//! # DOUBLE PRECISION — estimated_savings / confidence_score
//! Both columns are `DOUBLE PRECISION`, which sqlx maps directly to `f64`.
//! We decode as `Option<f64>` / `f64` in the row struct; no `::text` cast.
//!
//! # TIMESTAMPTZ
//! `created_at` and `updated_at` are decoded as `DateTime<Utc>` then converted
//! via `.to_rfc3339()` — no locale-sensitive `::text` cast.
//!
//! # CAS design
//! Mutations load the row first, pass it through a pure engine guard to verify
//! the transition is legal (engine → 409 on illegal), then issue a
//! `UPDATE … WHERE id=$1 AND status=$expected RETURNING …` CAS.  A 0-row
//! result (concurrent modification beat us) is returned as `Ok(None)` → 409.

use chrono::{DateTime, Utc};
use ryuki_engine::aiops::{
    suggestion_status_from_db, suggestion_status_to_db, suggestion_type_from_db, AIOpsSuggestion,
    SuggestionStatus, SuggestionType,
};
use ryuki_engine::auth::ActorClass;
use sqlx::PgPool;

// ─── Column list ─────────────────────────────────────────────────────────────

pub const COLUMNS: &str = "id, suggestion_type, title, description, affected_components, \
     estimated_savings, confidence_score, status, reviewer, rejection_reason, \
     implementation_plan, site, created_at, updated_at";

fn list_by_type_sql(scoped: bool) -> String {
    if scoped {
        format!(
            "SELECT {COLUMNS} FROM aiops_suggestions \
             WHERE suggestion_type = $1 \
               AND site = ANY($2::text[]) \
               AND (status IN ('New', 'Rejected') OR reviewer_actor_class = 'verified-human') \
             ORDER BY created_at, id LIMIT $3"
        )
    } else {
        format!(
            "SELECT {COLUMNS} FROM aiops_suggestions \
             WHERE suggestion_type = $1 \
               AND (status IN ('New', 'Rejected') OR reviewer_actor_class = 'verified-human') \
             ORDER BY created_at, id LIMIT $2"
        )
    }
}

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct AiopsSuggestionRow {
    pub id: String,
    pub suggestion_type: String,
    pub title: String,
    pub description: String,
    /// Native TEXT[] decoded directly by sqlx — no JSON intermediary.
    pub affected_components: Vec<String>,
    /// DOUBLE PRECISION nullable → Option<f64>.
    pub estimated_savings: Option<f64>,
    /// DOUBLE PRECISION NOT NULL → f64.
    pub confidence_score: f64,
    pub status: String,
    pub reviewer: Option<String>,
    pub rejection_reason: Option<String>,
    pub implementation_plan: Option<String>,
    pub site: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AiopsSuggestionRow {
    /// Convert a DB row into the engine model.
    ///
    /// Both enum columns use explicit match helpers because the serde
    /// derive on the engine enums uses `rename_all = "snake_case"` which
    /// produces `"right_sizing"` — not the PascalCase `"RightSizing"` the
    /// DB CHECK stores.  A decode failure means the row is corrupt; surfaced
    /// as a `sqlx::Error::Decode` so the handler maps it to 500.
    pub fn into_model(self) -> Result<AIOpsSuggestion, sqlx::Error> {
        let suggestion_type: SuggestionType = suggestion_type_from_db(&self.suggestion_type)
            .map_err(|e| {
                sqlx::Error::Decode(
                    format!(
                        "aiops_suggestions.suggestion_type: corrupt value '{}': {e}",
                        self.suggestion_type
                    )
                    .into(),
                )
            })?;

        let status: SuggestionStatus = suggestion_status_from_db(&self.status).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "aiops_suggestions.status: corrupt value '{}': {e}",
                    self.status
                )
                .into(),
            )
        })?;

        Ok(AIOpsSuggestion {
            id: self.id,
            suggestion_type,
            title: self.title,
            description: self.description,
            affected_components: self.affected_components,
            estimated_savings: self.estimated_savings,
            confidence_score: self.confidence_score,
            status,
            reviewer: self.reviewer,
            rejection_reason: self.rejection_reason,
            implementation_plan: self.implementation_plan,
            site: self.site,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
        })
    }
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List suggestions for a site.
pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<AIOpsSuggestion>, sqlx::Error> {
    let rows: Vec<AiopsSuggestionRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM aiops_suggestions \
         WHERE site = $1 \
           AND (status IN ('New', 'Rejected') OR reviewer_actor_class = 'verified-human') \
         ORDER BY created_at"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List suggestions filtered by suggestion_type DB form.
///
/// This is the unrestricted variant. The result is still capped at the
/// repository boundary so a high-cardinality suggestion type cannot cause an
/// unbounded materialization. Scoped callers must use
/// [`list_by_type_for_sites`], which applies their site predicate before the
/// same bound.
pub async fn list_by_type(
    pool: &PgPool,
    suggestion_type_db: &str,
    limit: i64,
) -> Result<Vec<AIOpsSuggestion>, sqlx::Error> {
    let limit = bounded_type_list_limit(limit);
    let sql = list_by_type_sql(false);
    let rows: Vec<AiopsSuggestionRow> = sqlx::query_as(&sql)
        .bind(suggestion_type_db)
        .bind(limit)
        .fetch_all(pool)
        .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List suggestions of one type whose site is in the caller's authorized set.
///
/// The `site = ANY(...)` predicate is intentionally part of the database query
/// and precedes `LIMIT`: out-of-scope rows are never materialized in the API
/// process and cannot consume the bounded result window. An empty `sites`
/// slice fails closed to an empty result.
pub async fn list_by_type_for_sites(
    pool: &PgPool,
    suggestion_type_db: &str,
    sites: &[String],
    limit: i64,
) -> Result<Vec<AIOpsSuggestion>, sqlx::Error> {
    let limit = bounded_type_list_limit(limit);
    let sql = list_by_type_sql(true);
    let rows: Vec<AiopsSuggestionRow> = sqlx::query_as(&sql)
        .bind(suggestion_type_db)
        .bind(sites)
        .bind(limit)
        .fetch_all(pool)
        .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

const MAX_TYPE_LIST_ROWS: i64 = 1000;

fn bounded_type_list_limit(limit: i64) -> i64 {
    limit.clamp(0, MAX_TYPE_LIST_ROWS)
}

/// Get a single suggestion by TEXT id. Returns Ok(None) when absent.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<AIOpsSuggestion>, sqlx::Error> {
    let row: Option<AiopsSuggestionRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM aiops_suggestions WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

// ─── Mutation functions ───────────────────────────────────────────────────────
//
// Each mutation:
//   1. loads the row (Ok(None) → 404 at handler)
//   2. caller runs pure engine guard → 409 on illegal transition
//   3. CAS UPDATE conditioned on status=$expected_status
//   4. 0-row RETURNING → Ok(None) → 409 at handler (concurrent modification)

/// CAS: status='New' → 'Reviewed'. Sets reviewer, updated_at.
/// `expected_status` must be `"New"` (from `guard_review`).
pub async fn review(
    pool: &PgPool,
    id: &str,
    reviewer: &str,
    reviewer_actor_class: ActorClass,
    expected_status: &str,
    scope_site: &str,
) -> Result<Option<AIOpsSuggestion>, sqlx::Error> {
    // The persistence boundary accepts the typed classification itself, never
    // a caller-asserted string that an internal caller could forge.
    if reviewer_actor_class != ActorClass::VerifiedHuman {
        return Ok(None);
    }
    // `AND site = $6` (#2) — site-aware CAS, matching accept/reject/implement: if
    // the row was re-homed out of the caller's scope after the handler's scope
    // guard, this matches 0 rows and the handler reports a 409 instead of writing
    // off-scope (closes the load-then-write TOCTOU).
    let row: Option<AiopsSuggestionRow> = sqlx::query_as(&format!(
        "UPDATE aiops_suggestions \
         SET status = $5, reviewer = $2, reviewer_actor_class = $3, updated_at = NOW() \
         WHERE id = $1 AND status = $4 AND site = $6 \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(reviewer)
    .bind(reviewer_actor_class.as_str())
    .bind(expected_status)
    .bind(suggestion_status_to_db(&SuggestionStatus::Reviewed))
    .bind(scope_site)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// CAS: status='Reviewed' → 'Accepted'. Sets implementation_plan, updated_at.
/// `expected_status` must be `"Reviewed"` (from `guard_accept`).
pub async fn accept(
    pool: &PgPool,
    id: &str,
    implementation_plan: &str,
    expected_status: &str,
    scope_site: &str,
) -> Result<Option<AIOpsSuggestion>, sqlx::Error> {
    // The `AND site = $5` predicate (#2) makes the CAS site-aware: if the row was
    // re-homed out of the caller's scope after the handler's scope guard, this
    // matches 0 rows and the handler reports a 409 instead of writing off-scope.
    let row: Option<AiopsSuggestionRow> = sqlx::query_as(&format!(
        "UPDATE aiops_suggestions \
         SET status = $4, implementation_plan = $2, updated_at = NOW() \
         WHERE id = $1 AND status = $3 AND site = $5 \
           AND reviewer_actor_class = 'verified-human' \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(implementation_plan)
    .bind(expected_status)
    .bind(suggestion_status_to_db(&SuggestionStatus::Accepted))
    .bind(scope_site)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// CAS: status=$expected → 'Rejected'. Sets rejection_reason, updated_at.
/// `expected_status` is either `"New"` or `"Reviewed"` (from `guard_reject`).
pub async fn reject(
    pool: &PgPool,
    id: &str,
    rejection_reason: &str,
    expected_status: &str,
    scope_site: &str,
) -> Result<Option<AIOpsSuggestion>, sqlx::Error> {
    // `AND site = $5` (#2) — site-aware CAS; see `accept`.
    let row: Option<AiopsSuggestionRow> = sqlx::query_as(&format!(
        "UPDATE aiops_suggestions \
         SET status = $4, rejection_reason = $2, updated_at = NOW() \
         WHERE id = $1 AND status = $3 AND site = $5 \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(rejection_reason)
    .bind(expected_status)
    .bind(suggestion_status_to_db(&SuggestionStatus::Rejected))
    .bind(scope_site)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// CAS: status='Accepted' → 'Implemented'. Sets updated_at.
/// `expected_status` must be `"Accepted"` (from `guard_implement`).
pub async fn implement(
    pool: &PgPool,
    id: &str,
    expected_status: &str,
    scope_site: &str,
) -> Result<Option<AIOpsSuggestion>, sqlx::Error> {
    // `AND site = $4` (#2) — site-aware CAS; see `accept`.
    let row: Option<AiopsSuggestionRow> = sqlx::query_as(&format!(
        "UPDATE aiops_suggestions \
         SET status = $3, updated_at = NOW() \
         WHERE id = $1 AND status = $2 AND site = $4 \
           AND reviewer_actor_class = 'verified-human' \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(expected_status)
    .bind(suggestion_status_to_db(&SuggestionStatus::Implemented))
    .bind(scope_site)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   cargo test -p ryuki-api --bins aiops_db_tests -- --test-threads=1
//
// Tests SKIP when RYUKI_DATABASE_URL is unset or connection fails.
#[cfg(test)]
mod aiops_db_tests {
    use super::*;
    use ryuki_engine::aiops::{suggestion_type_to_db, SuggestionType};

    static DB_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn test_pool() -> Option<PgPool> {
        // Fail closed: with no DB configured these DB tests SKIP (callers handle the
        // None via `let Some(pool) = test_pool().await else { return }`). Previously
        // this fell back to a hard-coded localhost URL and `.expect`ed migrations,
        // so a no-DB or migration-drifted run PANICKED instead of skipping — breaking
        // the fail-closed + drift-tolerant test conventions the other repos follow.
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .ok()?;
        // Drift-tolerant: skip (None) rather than panic when migrations cannot apply
        // against a drifted local DB — matches `run_migrations(...).ok()?` elsewhere.
        crate::database::run_migrations(&pool).await.ok()?;
        Some(pool)
    }

    /// Insert a minimal test suggestion. Returns its id.
    async fn insert_test_suggestion(
        pool: &PgPool,
        id: &str,
        suggestion_type: &str,
        status: &str,
        site: &str,
        estimated_savings: Option<f64>,
    ) {
        sqlx::query(
            "INSERT INTO aiops_suggestions \
             (id, suggestion_type, title, description, affected_components, \
              estimated_savings, confidence_score, status, site) \
             VALUES ($1, $2, $3, 'test description', ARRAY['comp-a', 'comp-b']::text[], \
                     $4, 0.75, $5, $6)",
        )
        .bind(id)
        .bind(suggestion_type)
        .bind(format!("Test suggestion {id}"))
        .bind(estimated_savings)
        .bind(status)
        .bind(site)
        .execute(pool)
        .await
        .expect("insert_test_suggestion");
    }

    async fn cleanup(pool: &PgPool, id: &str) {
        sqlx::query("DELETE FROM aiops_suggestions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    // ─── list_by_site returns seeded rows ─────────────────────────────────────

    #[tokio::test]
    async fn list_returns_seeded_rows() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        // Migration 035 seeds 5 rows across DEFRA and GBLON.
        let defra = list_by_site(&pool, "DEFRA").await.expect("list DEFRA");
        assert!(defra.len() >= 3, "migration 035 seeds 3 DEFRA rows");

        let gblon = list_by_site(&pool, "GBLON").await.expect("list GBLON");
        assert!(gblon.len() >= 2, "migration 035 seeds 2 GBLON rows");
    }

    // ─── estimated_savings NULL → None and affected_components TEXT[] decode ──

    #[tokio::test]
    async fn null_estimated_savings_decodes_to_none_and_text_array_decodes() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let id = "test-aiops-null-savings-001";
        insert_test_suggestion(&pool, id, "Migration", "New", "DEFRA", None).await;

        let suggestion = get(&pool, id).await.expect("get").expect("row exists");
        assert!(
            suggestion.estimated_savings.is_none(),
            "NULL estimated_savings must decode to None"
        );
        // affected_components TEXT[] must decode to the two strings we inserted
        assert_eq!(
            suggestion.affected_components,
            vec!["comp-a".to_string(), "comp-b".to_string()],
            "affected_components TEXT[] must decode natively"
        );

        cleanup(&pool, id).await;
    }

    // ─── lifecycle transition: New → Reviewed ─────────────────────────────────

    #[tokio::test]
    async fn review_advances_status_and_sets_reviewer() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let id = "test-aiops-review-001";
        insert_test_suggestion(&pool, id, "RightSizing", "New", "DEFRA", Some(500.0)).await;

        // Load and run pure engine guard
        let suggestion = get(&pool, id).await.expect("get").expect("row exists");
        assert_eq!(suggestion.status, SuggestionStatus::New);

        let expected = ryuki_engine::aiops::guard_review(&suggestion).expect("guard ok");

        for actor_class in [
            ActorClass::Workload,
            ActorClass::Unknown,
            ActorClass::Simulated,
        ] {
            let denied = review(&pool, id, "machine-alice", actor_class, expected, "DEFRA")
                .await
                .expect("nonhuman review repo call");
            assert!(
                denied.is_none(),
                "a nonhuman must not create review evidence"
            );
        }
        let unchanged = get(&pool, id)
            .await
            .expect("get unchanged")
            .expect("row exists");
        assert_eq!(unchanged.status, SuggestionStatus::New);
        assert_eq!(unchanged.reviewer, None);
        assert_eq!(unchanged.updated_at, suggestion.updated_at);
        let unchanged_actor_class: Option<String> =
            sqlx::query_scalar("SELECT reviewer_actor_class FROM aiops_suggestions WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read unchanged actor provenance");
        assert_eq!(unchanged_actor_class, None);

        let updated = review(
            &pool,
            id,
            "alice",
            ActorClass::VerifiedHuman,
            expected,
            "DEFRA",
        )
        .await
        .expect("review repo")
        .expect("CAS hit");

        assert_eq!(updated.status, SuggestionStatus::Reviewed);
        assert_eq!(updated.reviewer, Some("alice".into()));
        let persisted_actor_class: Option<String> =
            sqlx::query_scalar("SELECT reviewer_actor_class FROM aiops_suggestions WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read review actor provenance");
        assert_eq!(persisted_actor_class.as_deref(), Some("verified-human"));

        let expected_accept =
            ryuki_engine::aiops::guard_accept(&updated).expect("verified review is acceptable");
        let accepted = accept(
            &pool,
            id,
            "verified provenance plan",
            expected_accept,
            "DEFRA",
        )
        .await
        .expect("accept repo")
        .expect("verified review provenance permits acceptance");
        assert_eq!(accepted.status, SuggestionStatus::Accepted);

        let rebind = sqlx::query(
            "UPDATE aiops_suggestions SET reviewer_actor_class = 'workload' WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect_err("reviewer actor provenance must be immutable");
        assert!(rebind
            .to_string()
            .contains("AIOps reviewer provenance is immutable"));

        cleanup(&pool, id).await;
    }

    #[tokio::test]
    async fn accept_quarantines_reviewed_rows_without_verified_human_provenance() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let id = "test-aiops-legacy-review-001";
        insert_test_suggestion(&pool, id, "Migration", "Reviewed", "DEFRA", None).await;
        sqlx::query(
            "UPDATE aiops_suggestions \
             SET reviewer = 'legacy-reviewer', reviewer_actor_class = 'unknown' \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect("seed pre-admission reviewer provenance");

        let suggestion = get(&pool, id).await.expect("get").expect("row exists");
        let expected = ryuki_engine::aiops::guard_accept(&suggestion).expect("engine status guard");
        let denied = accept(&pool, id, "legacy plan", expected, "DEFRA")
            .await
            .expect("accept repository call");
        assert!(
            denied.is_none(),
            "unknown legacy provenance must be quarantined"
        );
        let unchanged = get(&pool, id)
            .await
            .expect("get unchanged")
            .expect("row exists");
        assert_eq!(unchanged.status, SuggestionStatus::Reviewed);

        sqlx::query("UPDATE aiops_suggestions SET status = 'Accepted' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("seed a legacy accepted row");
        let legacy_accepted = get(&pool, id)
            .await
            .expect("get legacy accepted")
            .expect("row exists");
        let expected_implement =
            ryuki_engine::aiops::guard_implement(&legacy_accepted).expect("engine status guard");
        let implementation = implement(&pool, id, expected_implement, "DEFRA")
            .await
            .expect("implement repository call");
        assert!(
            implementation.is_none(),
            "unknown legacy provenance must not become implemented"
        );
        let trusted = list_by_site(&pool, "DEFRA")
            .await
            .expect("trusted site list");
        assert!(
            trusted.iter().all(|suggestion| suggestion.id != id),
            "legacy accepted evidence must be quarantined from trusted consumers"
        );
        let raw_status: String =
            sqlx::query_scalar("SELECT status FROM aiops_suggestions WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read unchanged legacy status");
        assert_eq!(raw_status, "Accepted");

        cleanup(&pool, id).await;
    }

    // ─── illegal transition → guard 409 ───────────────────────────────────────

    #[tokio::test]
    async fn guard_reject_on_accepted_returns_err() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let id = "test-aiops-guard-err-001";
        // Insert directly as Accepted to test the guard
        insert_test_suggestion(&pool, id, "Consolidation", "Accepted", "GBLON", None).await;

        let suggestion = get(&pool, id).await.expect("get").expect("row exists");
        let result = ryuki_engine::aiops::guard_reject(&suggestion);
        assert!(result.is_err(), "guard_reject must fail on Accepted status");

        cleanup(&pool, id).await;
    }

    // ─── CAS miss → Ok(None) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn cas_miss_returns_none() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let id = "test-aiops-cas-miss-001";
        insert_test_suggestion(&pool, id, "CostOptimization", "New", "DEFRA", Some(200.0)).await;

        // Attempt CAS with wrong expected status ("Reviewed" but row is "New")
        let result = review(
            &pool,
            id,
            "bob",
            ActorClass::VerifiedHuman,
            "Reviewed",
            "DEFRA",
        )
        .await
        .expect("query ok");
        assert!(
            result.is_none(),
            "wrong expected_status → Ok(None) (CAS miss)"
        );

        cleanup(&pool, id).await;
    }

    // ─── reject sets rejection_reason ─────────────────────────────────────────

    #[tokio::test]
    async fn reject_sets_rejection_reason() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let id = "test-aiops-reject-001";
        insert_test_suggestion(&pool, id, "RiskReduction", "New", "GBLON", None).await;

        let suggestion = get(&pool, id).await.expect("get").expect("row");
        let expected = ryuki_engine::aiops::guard_reject(&suggestion).expect("guard ok");

        let updated = reject(&pool, id, "Insufficient data", expected, &suggestion.site)
            .await
            .expect("reject repo")
            .expect("CAS hit");

        assert_eq!(updated.status, SuggestionStatus::Rejected);
        assert_eq!(updated.rejection_reason, Some("Insufficient data".into()));

        cleanup(&pool, id).await;
    }

    // ─── savings summary and stats reads ─────────────────────────────────────

    #[tokio::test]
    async fn savings_and_stats_read_from_db() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        // Use seeded data — read-only, no insert/cleanup needed.
        let defra = list_by_site(&pool, "DEFRA").await.expect("list");
        let summary = ryuki_engine::aiops::get_savings_summary("DEFRA", &defra);
        assert_eq!(summary["site"], "DEFRA");
        assert!(
            summary["total_potential_savings"].as_f64().unwrap() >= 0.0,
            "savings must be non-negative"
        );

        let stats = ryuki_engine::aiops::get_suggestion_stats("DEFRA", &defra);
        assert_eq!(stats["site"], "DEFRA");
        let total = stats["total"].as_u64().unwrap();
        let sum = stats["accepted"].as_u64().unwrap()
            + stats["rejected"].as_u64().unwrap()
            + stats["pending"].as_u64().unwrap()
            + stats["implemented"].as_u64().unwrap();
        assert_eq!(
            total, sum,
            "accepted+rejected+pending+implemented must equal total"
        );
        assert!(total >= 3, "migration 035 seeds 3 DEFRA rows");
    }

    // ─── list_by_type uses DB form ────────────────────────────────────────────

    #[test]
    fn type_list_limit_is_bounded_at_repository_boundary() {
        assert_eq!(bounded_type_list_limit(-1), 0);
        assert_eq!(bounded_type_list_limit(25), 25);
        assert_eq!(
            bounded_type_list_limit(MAX_TYPE_LIST_ROWS + 1),
            MAX_TYPE_LIST_ROWS
        );
    }

    #[test]
    fn scoped_type_query_applies_authorization_before_limit() {
        let sql = list_by_type_sql(true);
        let scope_position = sql
            .find("site = ANY($2::text[])")
            .expect("scoped query must bind the authorized sites");
        let limit_position = sql.find("LIMIT $3").expect("scoped query must be bounded");
        assert!(
            scope_position < limit_position,
            "site authorization must be applied before the result bound"
        );

        let unrestricted = list_by_type_sql(false);
        assert!(!unrestricted.contains("site = ANY"));
        assert!(unrestricted.contains("LIMIT $2"));
    }

    #[tokio::test]
    async fn list_by_type_rightsizing() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        // The DB stores 'RightSizing'; query with DB form, not display form.
        let rows = list_by_type(
            &pool,
            suggestion_type_to_db(&SuggestionType::RightSizing),
            MAX_TYPE_LIST_ROWS,
        )
        .await
        .expect("list_by_type");
        assert!(
            rows.iter()
                .all(|r| r.suggestion_type == SuggestionType::RightSizing),
            "all returned rows must be RightSizing"
        );
        assert!(
            !rows.is_empty(),
            "migration 035 seeds at least one RightSizing row"
        );
    }

    #[tokio::test]
    async fn list_by_type_scopes_before_materialization_and_honors_limit() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB unavailable");
            return;
        };

        let defra_id = "test-aiops-type-scope-defra-001";
        let gblon_id = "test-aiops-type-scope-gblon-001";
        cleanup(&pool, defra_id).await;
        cleanup(&pool, gblon_id).await;
        insert_test_suggestion(
            &pool,
            defra_id,
            "PerformanceImprovement",
            "New",
            "DEFRA",
            None,
        )
        .await;
        insert_test_suggestion(
            &pool,
            gblon_id,
            "PerformanceImprovement",
            "New",
            "GBLON",
            None,
        )
        .await;

        let defra_only = list_by_type_for_sites(
            &pool,
            "PerformanceImprovement",
            &["DEFRA".to_string()],
            MAX_TYPE_LIST_ROWS,
        )
        .await
        .expect("scoped type list");
        assert!(
            defra_only
                .iter()
                .all(|suggestion| suggestion.site == "DEFRA"),
            "the scoped SQL query must never materialize a foreign-site row"
        );
        assert!(defra_only
            .iter()
            .any(|suggestion| suggestion.id == defra_id));
        assert!(
            defra_only
                .iter()
                .all(|suggestion| suggestion.id != gblon_id),
            "a GBLON row must not cross the DEFRA persistence boundary"
        );

        let both_sites = vec!["DEFRA".to_string(), "GBLON".to_string()];
        let permitted = list_by_type_for_sites(
            &pool,
            "PerformanceImprovement",
            &both_sites,
            MAX_TYPE_LIST_ROWS,
        )
        .await
        .expect("multi-site type list");
        assert!(permitted.iter().any(|suggestion| suggestion.id == defra_id));
        assert!(permitted.iter().any(|suggestion| suggestion.id == gblon_id));

        let bounded = list_by_type_for_sites(&pool, "PerformanceImprovement", &both_sites, 1)
            .await
            .expect("bounded type list");
        assert_eq!(bounded.len(), 1, "LIMIT must bound materialized rows");

        let empty_scope =
            list_by_type_for_sites(&pool, "PerformanceImprovement", &[], MAX_TYPE_LIST_ROWS)
                .await
                .expect("empty scoped type list");
        assert!(empty_scope.is_empty(), "an empty scope must fail closed");

        cleanup(&pool, defra_id).await;
        cleanup(&pool, gblon_id).await;
    }
}
