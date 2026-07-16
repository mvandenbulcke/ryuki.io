//! Repository functions for `golden_images`.
//!
//! Read and ordinary transition helpers use `&PgPool`; governed promotion uses
//! a caller-owned `&mut PgConnection` so the handler can append its security
//! audit event before committing. Callers are responsible for mapping
//! `sqlx::Error` → 500 and `None` → 404/409 as appropriate.
//!
//! # Status encoding
//! `BuildStatus` uses `#[serde(rename_all = "kebab-case")]`, so serde variant
//! names are lowercase (`building`, `testing`, `promoted`, `superseded`,
//! `failed`). These match the existing DB CHECK constraint in migration 041
//! exactly — no PascalCase conversion is needed.
//!
//! # Promote transaction
//! `promote_in_tx` uses the caller's transaction: it CAS-transitions the target
//! image from `Testing` → `Promoted` AND supersedes all currently-`Promoted`
//! images with the same `site_scope + os_family`, so the invariant "at most one
//! promoted image per site+os" is never violated, even under concurrent requests.
//!
//! # supersedes_image_id
//! The column is a UUID FK self-reference. We bind it as `Option<Uuid>` and
//! select it as `supersedes_image_id::text` to produce `Option<String>` in the
//! row.

use chrono::{DateTime, Utc};
use ryuki_engine::image_factory::{BuildStatus, GoldenImage};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID columns → text so sqlx decodes into `String`.
/// `build_date` and `created_at` are `DateTime<Utc>` in the row and converted
/// to RFC-3339 strings in `into_model`. `supersedes_image_id` is a nullable
/// UUID FK; we cast it to text so `Option<String>` decodes cleanly.
pub const COLUMNS: &str = "id::text AS id, \
     image_name, \
     os_family, \
     os_version, \
     distro, \
     build_date, \
     status, \
     supersedes_image_id::text AS supersedes_image_id, \
     site_scope, \
     build_log";

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct GoldenImageRow {
    pub id: String,
    pub image_name: String,
    pub os_family: String,
    pub os_version: String,
    pub distro: String,
    pub build_date: DateTime<Utc>,
    pub status: String,
    pub supersedes_image_id: Option<String>,
    pub site_scope: String,
    pub build_log: String,
}

impl GoldenImageRow {
    /// Convert a DB row into the engine model.
    ///
    /// `status` is stored as its serde kebab-case name and decoded via
    /// `serde_json`. A parse failure means the persisted row is corrupt; we
    /// surface it as a decode error (caller → 500) rather than substituting a
    /// default — a subsequent `transition` would CAS against the wrong status.
    /// A DB CHECK constraint (migration 041) keeps status in the legal set.
    pub fn into_model(self) -> Result<GoldenImage, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("golden_images.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        // serde kebab-case: "building", "testing", etc.
        let status: BuildStatus = decode(&format!("\"{}\"", self.status), "status")?;

        Ok(GoldenImage {
            id: self.id,
            image_name: self.image_name,
            os_family: self.os_family,
            os_version: self.os_version,
            distro: self.distro,
            build_date: self.build_date.to_rfc3339(),
            status,
            supersedes_image_id: self.supersedes_image_id,
            site_scope: self.site_scope,
            build_log: self.build_log,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `BuildStatus` value as stored in the DB
/// (e.g. `"building"`, `"promoted"`). `pub` so handlers can supply the
/// `expected_status` argument to `transition` without duplicating this table.
pub fn status_str(s: &BuildStatus) -> &'static str {
    match s {
        BuildStatus::Building => "building",
        BuildStatus::Testing => "testing",
        BuildStatus::Promoted => "promoted",
        BuildStatus::Superseded => "superseded",
        BuildStatus::Failed => "failed",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Fetch one image by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<GoldenImage>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<GoldenImageRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM golden_images WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all images, optionally filtered by site. An empty `site` returns all
/// images. Results are ordered by `build_date DESC, id DESC` for stable listing.
pub async fn list(pool: &PgPool, site: &str) -> Result<Vec<GoldenImage>, sqlx::Error> {
    let rows: Vec<GoldenImageRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM golden_images ORDER BY build_date DESC, id DESC"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM golden_images WHERE site_scope = $1 \
             ORDER BY build_date DESC, id DESC"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all images with `status = 'promoted'` for a given site.
pub async fn list_promoted(pool: &PgPool, site: &str) -> Result<Vec<GoldenImage>, sqlx::Error> {
    let rows: Vec<GoldenImageRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM golden_images \
         WHERE site_scope = $1 AND status = 'promoted' \
         ORDER BY os_family, build_date DESC, id DESC"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Stale-scan projection (#60) ───────────────────────────────────────────────

/// Minimal raw projection for the bounded golden-image scheduler page. Scalar
/// columns only — no full-model deserialization — so the scan reads exactly
/// what it needs from real typed columns (no JSONB blob to corrupt or parse).
#[derive(sqlx::FromRow)]
pub struct StalePromotedRow {
    pub scan_seq: i64,
    pub id: String,
    pub image_name: String,
    pub site_scope: String,
    pub build_date: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

/// Repository-level ceiling for one golden-image scheduler page.
const MAX_SCHEDULER_SCAN_PAGE: i64 = 100;

/// Bound the current image cycle by its largest visible sequence.  Later
/// sequence allocations wait for the next cycle; an earlier allocation that
/// commits late is also recovered after the cursor resets on exhaustion.
pub async fn stale_scan_high_water(
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(MAX(scan_seq), 0) \
         FROM golden_image_scheduler_population",
    )
    .fetch_one(executor)
    .await
}

/// Fetch one immutable raw keyset page before status/staleness filtering.  The
/// caller advances through every image sequence, so non-promoted or fresh rows
/// cannot create cursor gaps or make a short matching page look exhausted.
/// Classification then uses the cycle's fixed cutoff in the scheduler.
pub async fn scheduler_scan_page(
    executor: impl sqlx::PgExecutor<'_>,
    cursor_seq: i64,
    high_water_seq: i64,
    limit: i64,
) -> Result<Vec<StalePromotedRow>, sqlx::Error> {
    if cursor_seq < 0
        || high_water_seq < cursor_seq
        || !(1..=MAX_SCHEDULER_SCAN_PAGE).contains(&limit)
    {
        return Err(sqlx::Error::Protocol(
            "golden-image scheduler page requires 0 <= cursor <= high-water and limit 1..=100"
                .to_string(),
        ));
    }
    sqlx::query_as(
        "SELECT population.scan_seq, image.id::text AS id, image.image_name, \
                image.site_scope, image.build_date, image.status \
         FROM ( \
             SELECT scan_seq, image_id \
             FROM golden_image_scheduler_population \
             WHERE scan_seq > $1 AND scan_seq <= $2 \
             ORDER BY scan_seq \
             LIMIT $3 \
         ) population \
         JOIN golden_images image ON image.id = population.image_id \
         ORDER BY population.scan_seq",
    )
    .bind(cursor_seq)
    .bind(high_water_seq)
    .bind(limit)
    .fetch_all(executor)
    .await
}

/// One `LIMIT`/`OFFSET` page of superseded images (#14) with the SITE SCOPE
/// pushed into SQL — the paged replacement for the handler's old fetch-all +
/// in-memory `retain_site_scoped`. `sites`: `None` = every site (an unrestricted
/// principal); `Some(list)` = only those `site_scope`s (a site-scoped principal)
/// via `site_scope = ANY($1)`. An environment-scoped principal is handled by the
/// caller (empty result), matching `retain_site_scoped`. `ORDER BY build_date
/// DESC, id DESC` ends in the unique PK, so each page is a stable cut.
pub async fn list_superseded_page(
    pool: &PgPool,
    sites: Option<&[String]>,
    limit: i64,
    offset: i64,
) -> Result<Vec<GoldenImage>, sqlx::Error> {
    let rows: Vec<GoldenImageRow> = match sites {
        None => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM golden_images WHERE status = 'superseded' \
                 ORDER BY build_date DESC, id DESC LIMIT $1 OFFSET $2"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
        Some(sites) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM golden_images \
                 WHERE status = 'superseded' AND site_scope = ANY($1) \
                 ORDER BY build_date DESC, id DESC LIMIT $2 OFFSET $3"
            ))
            .bind(sites)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count superseded images under the SAME site scope as [`list_superseded_page`]
/// — the pagination total. `None` = all sites; `Some(list)` = `site_scope = ANY($1)`.
pub async fn count_superseded(pool: &PgPool, sites: Option<&[String]>) -> Result<i64, sqlx::Error> {
    match sites {
        None => {
            sqlx::query_scalar("SELECT COUNT(*) FROM golden_images WHERE status = 'superseded'")
                .fetch_one(pool)
                .await
        }
        Some(sites) => {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM golden_images \
             WHERE status = 'superseded' AND site_scope = ANY($1)",
            )
            .bind(sites)
            .fetch_one(pool)
            .await
        }
    }
}

/// Insert a new image and return the persisted row. The caller supplies the
/// model with an already-generated UUID string as `id`.
///
/// `build_date` is bound from the RFC-3339 string in the model. `created_at`
/// is left to the DB default (NOW()). We RETURNING the inserted row so the
/// returned model carries DB-authoritative values.
pub async fn insert(pool: &PgPool, r: &GoldenImage) -> Result<GoldenImage, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let build_date: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.build_date)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let supersedes_id: Option<Uuid> = match &r.supersedes_image_id {
        Some(s) => Some(Uuid::parse_str(s).map_err(|e| sqlx::Error::Decode(Box::new(e)))?),
        None => None,
    };

    let row: GoldenImageRow = sqlx::query_as(&format!(
        "INSERT INTO golden_images \
         (id, image_name, os_family, os_version, distro, build_date, \
          status, supersedes_image_id, site_scope, build_log) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&r.image_name)
    .bind(&r.os_family)
    .bind(&r.os_version)
    .bind(&r.distro)
    .bind(build_date)
    .bind(status_str(&r.status))
    .bind(supersedes_id)
    .bind(&r.site_scope)
    .bind(&r.build_log)
    .fetch_one(pool)
    .await?;

    row.into_model()
}

/// Transition an image to `Promoted` and supersede every currently-promoted
/// peer for the same `site_scope + os_family` on the caller's transaction.
///
/// The transaction uses two `SELECT … FOR UPDATE` steps to serialize
/// concurrent promotions:
/// 1. Lock and re-read the target row — if it is no longer `testing`,
///    abort with `Ok(None)` (caller → 409).
/// 2. Lock all `promoted` rows in the same scope (`ORDER BY id` to avoid
///    deadlocks between two concurrent promotions in the same scope).
/// 3. Supersede those rows.
/// 4. Set the target to `promoted`.
/// 5. Return the promoted row and canonical peer-id set without committing.
///
/// The caller must append the actor-attributed security event and commit the
/// same transaction. This keeps promotion, collateral supersession, and audit
/// evidence atomic.
///
/// Returns `Ok(None)` when the CAS misses (caller → 409).
pub async fn promote_in_tx(
    conn: &mut PgConnection,
    img: &GoldenImage,
) -> Result<Option<(GoldenImage, Vec<String>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&img.id) else {
        return Ok(None);
    };

    // Step 1 — lock the target row and re-read its current state.
    let locked: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id::text, site_scope, os_family \
         FROM golden_images \
         WHERE id = $1 AND status = 'testing' \
         FOR UPDATE",
    )
    .bind(uid)
    .fetch_optional(&mut *conn)
    .await?;

    let Some((_id_text, site_scope, os_family)) = locked else {
        // Row missing or status is no longer 'testing'. The caller's
        // transaction remains uncommitted and contains no domain mutation.
        return Ok(None);
    };

    // Step 2 — serialize ALL promotions for this scope with a transaction-scoped
    // advisory lock keyed on (site_scope, os_family). A `FOR UPDATE` on the
    // promoted rows is NOT sufficient: when the scope has no promoted image yet
    // it locks zero rows and provides no mutual exclusion, so two concurrent
    // promotions of an empty scope could both commit as 'promoted'. The advisory
    // lock is always taken, so the second promotion blocks until the first
    // commits, then observes the first's promoted row and supersedes it —
    // guaranteeing at most one 'promoted' image per scope.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("golden_images:{site_scope}|{os_family}"))
        .execute(&mut *conn)
        .await?;

    // Step 3 — supersede prior promoted images for this scope (excluding
    // the image we are about to promote).
    let superseded_rows: Vec<(String,)> = sqlx::query_as(
        "UPDATE golden_images \
         SET status = 'superseded' \
         WHERE site_scope = $1 AND os_family = $2 AND status = 'promoted' AND id != $3 \
         RETURNING id::text",
    )
    .bind(&site_scope)
    .bind(&os_family)
    .bind(uid)
    .fetch_all(&mut *conn)
    .await?;

    // Step 4 — promote the target.
    let promoted_row: GoldenImageRow = sqlx::query_as(&format!(
        "UPDATE golden_images \
         SET status = 'promoted', build_log = $2 \
         WHERE id = $1 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(&img.build_log)
    .fetch_one(&mut *conn)
    .await?;

    let mut superseded_ids: Vec<String> = superseded_rows.into_iter().map(|(id,)| id).collect();
    superseded_ids.sort();
    let persisted = promoted_row.into_model()?;

    Ok(Some((persisted, superseded_ids)))
}

/// Atomically transition an image status using a compare-and-set.
/// Returns `Ok(None)` when no row with `id + expected_status` exists (caller
/// → 409). This covers `run_tests` (Building → Testing) and `reject_image`
/// (Building|Testing → Failed) transitions.
pub async fn transition(
    pool: &PgPool,
    expected_status: &str,
    img: &GoldenImage,
) -> Result<Option<GoldenImage>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&img.id) else {
        return Ok(None);
    };

    let row: Option<GoldenImageRow> = sqlx::query_as(&format!(
        "UPDATE golden_images \
         SET status = $2, build_log = $3 \
         WHERE id = $1 AND status = $4 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(status_str(&img.status))
    .bind(&img.build_log)
    .bind(expected_status)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

// ─── DB Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod golden_images_db_tests {
    use super::*;
    use ryuki_engine::image_factory::BuildStatus;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("golden_images_db_tests: RYUKI_DATABASE_URL not set — skipping DB tests");
                return None;
            }
        };
        let pool = PgPool::connect(&url)
            .await
            .expect("golden_images_db_tests: RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply cleanly when RYUKI_DATABASE_URL is set");
        Some(pool)
    }

    fn unique_image(site: &str, os_family: &str, status: BuildStatus) -> GoldenImage {
        let id = Uuid::new_v4().to_string();
        let suffix = &id[..8];
        GoldenImage {
            id: id.clone(),
            image_name: format!("test-img-{suffix}"),
            os_family: os_family.to_string(),
            os_version: "24.04".into(),
            distro: format!("Test {os_family}"),
            build_date: "2026-06-17T00:00:00Z".into(),
            status,
            supersedes_image_id: None,
            site_scope: site.to_string(),
            build_log: format!("seed-{suffix}"),
        }
    }

    async fn cleanup(pool: &PgPool, ids: &[String]) {
        // Delete child rows first (build_test_results has FK → golden_images, no CASCADE)
        for id in ids {
            if let Ok(uid) = Uuid::parse_str(id) {
                let _ = sqlx::query("DELETE FROM build_test_results WHERE image_id = $1")
                    .bind(uid)
                    .execute(pool)
                    .await;
                let _ = sqlx::query("DELETE FROM golden_images WHERE id = $1")
                    .bind(uid)
                    .execute(pool)
                    .await;
            }
        }
    }

    /// Repository-only tests that exercise the promotion primitive still own
    /// the commit explicitly, mirroring the production handler's transaction
    /// boundary (the handler additionally appends its audit before commit).
    async fn promote_committed(
        pool: &PgPool,
        image: &GoldenImage,
    ) -> Result<Option<(GoldenImage, Vec<String>)>, sqlx::Error> {
        let mut tx = pool.begin().await?;
        let result = promote_in_tx(&mut tx, image).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// #14: `list_superseded_page`/`count_superseded` push the site scope INTO SQL
    /// while keeping the `status = 'superseded'` filter. `None` = all sites,
    /// `Some(list)` = `site_scope = ANY(list)`. Verified against INDEPENDENT raw
    /// COUNTs; LIMIT/OFFSET give EXACT slices under the `build_date DESC, id DESC`
    /// tail; and a PROMOTED image in the same site never leaks into the page.
    #[tokio::test]
    async fn list_superseded_page_scopes_and_paginates() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Independent baselines (raw COUNT, NOT the fns under test).
        let raw_all: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM golden_images WHERE status = 'superseded'")
                .fetch_one(&pool)
                .await
                .expect("raw all superseded");
        let raw_defra: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM golden_images WHERE status = 'superseded' AND site_scope = $1",
        )
        .bind("DEFRA")
        .fetch_one(&pool)
        .await
        .expect("raw defra superseded");
        let defra = vec!["DEFRA".to_string()];
        assert_eq!(
            count_superseded(&pool, None).await.expect("count all"),
            raw_all,
            "count_superseded(None) == raw all-sites COUNT"
        );
        assert_eq!(
            count_superseded(&pool, Some(&defra))
                .await
                .expect("count defra"),
            raw_defra,
            "count_superseded(Some) == raw site-subset COUNT"
        );

        // Seed 3 superseded DEFRA images + 1 PROMOTED DEFRA image (must NOT leak in).
        let mut ids = Vec::new();
        for _ in 0..3 {
            let img = unique_image("DEFRA", "Linux", BuildStatus::Superseded);
            ids.push(img.id.clone());
            insert(&pool, &img).await.expect("insert superseded");
        }
        let promoted = unique_image("DEFRA", "Linux", BuildStatus::Promoted);
        let promoted_id = promoted.id.clone();
        ids.push(promoted_id.clone());
        insert(&pool, &promoted).await.expect("insert promoted");

        let total = count_superseded(&pool, Some(&defra))
            .await
            .expect("count defra after");
        assert_eq!(
            total,
            raw_defra + 3,
            "only the 3 superseded rows count — the promoted one is excluded"
        );
        assert_eq!(
            count_superseded(&pool, None)
                .await
                .expect("count all after"),
            raw_all + 3,
            "None counts every site's superseded rows"
        );

        // list_superseded_page(Some) returns exactly the DEFRA superseded subset.
        let all_defra = list_superseded_page(&pool, Some(&defra), 1000, 0)
            .await
            .expect("list defra");
        assert_eq!(
            all_defra.len() as i64,
            total,
            "full DEFRA page == its count"
        );
        assert!(
            all_defra
                .iter()
                .all(|i| i.site_scope == "DEFRA" && i.status == BuildStatus::Superseded),
            "page must be DEFRA + superseded only"
        );
        assert!(
            !all_defra.iter().any(|i| i.id == promoted_id),
            "the promoted image must never appear in the superseded page"
        );
        let ordered: Vec<&str> = all_defra.iter().map(|i| i.id.as_str()).collect();

        // LIMIT bounds the page; OFFSET yields the EXACT next slice (stable tail).
        let page1 = list_superseded_page(&pool, Some(&defra), 2, 0)
            .await
            .expect("page1");
        let page2 = list_superseded_page(&pool, Some(&defra), 2, 2)
            .await
            .expect("page2");
        let p1: Vec<&str> = page1.iter().map(|i| i.id.as_str()).collect();
        let p2: Vec<&str> = page2.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(p1, ordered[0..2], "page 1 is the first 2 of the full order");
        assert_eq!(
            p2,
            ordered[2..(ordered.len().min(4))],
            "page 2 is the EXACT next slice"
        );

        cleanup(&pool, &ids).await;
    }

    #[tokio::test]
    async fn test_insert_and_get_round_trip() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let img = unique_image("DEFRA", "Linux", BuildStatus::Building);
        let id = img.id.clone();

        let persisted = insert(&pool, &img).await.expect("insert");
        assert_eq!(persisted.id, id);
        assert_eq!(persisted.status, BuildStatus::Building);
        assert_eq!(persisted.site_scope, "DEFRA");

        let fetched = get(&pool, &id).await.expect("get").expect("row");
        assert_eq!(fetched.image_name, img.image_name);
        assert_eq!(fetched.build_log, img.build_log);

        cleanup(&pool, &[id]).await;
    }

    #[tokio::test]
    async fn test_transition_building_to_testing() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let img = unique_image("GBLON", "Windows", BuildStatus::Building);
        let id = img.id.clone();
        insert(&pool, &img).await.expect("insert");

        // Pure engine transition
        let testing = ryuki_engine::image_factory::run_tests(&img).expect("run_tests");
        let before = status_str(&img.status);
        let persisted = transition(&pool, before, &testing)
            .await
            .expect("transition")
            .expect("row returned");

        assert_eq!(persisted.status, BuildStatus::Testing);
        assert!(persisted.build_log.contains("Testing started"));

        cleanup(&pool, &[id]).await;
    }

    #[tokio::test]
    async fn test_promote_and_supersede() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Insert an already-promoted Linux image at NLAMS
        let old_promoted = unique_image("NLAMS", "Linux", BuildStatus::Promoted);
        let old_id = old_promoted.id.clone();
        insert(&pool, &old_promoted).await.expect("insert old");

        // Insert a new image in Testing state and promote it
        let testing_img = unique_image("NLAMS", "Linux", BuildStatus::Testing);
        let new_id = testing_img.id.clone();
        insert(&pool, &testing_img).await.expect("insert new");

        let promoted_val =
            ryuki_engine::image_factory::promote_image(&testing_img).expect("promote_image engine");

        let result = promote_committed(&pool, &promoted_val)
            .await
            .expect("promote repo")
            .expect("promote returned Some");

        let (persisted, superseded_ids) = result;
        assert_eq!(persisted.status, BuildStatus::Promoted);
        assert!(
            superseded_ids.contains(&old_id),
            "old image should be superseded"
        );

        // Verify the old image is now Superseded in the DB
        let old_row = get(&pool, &old_id).await.expect("get").expect("row");
        assert_eq!(old_row.status, BuildStatus::Superseded);

        cleanup(&pool, &[old_id, new_id]).await;
    }

    #[tokio::test]
    async fn test_concurrent_promote_single_winner() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Two Testing images in the SAME scope — only one should end up promoted.
        let img_a = unique_image("CONCURRENT-TEST", "Linux", BuildStatus::Testing);
        let img_b = unique_image("CONCURRENT-TEST", "Linux", BuildStatus::Testing);
        let id_a = img_a.id.clone();
        let id_b = img_b.id.clone();

        insert(&pool, &img_a).await.expect("insert a");
        insert(&pool, &img_b).await.expect("insert b");

        let promoted_a = ryuki_engine::image_factory::promote_image(&img_a).expect("engine a");
        let promoted_b = ryuki_engine::image_factory::promote_image(&img_b).expect("engine b");

        // Run both promotions concurrently. With scope-locking, exactly one
        // must win (Some) and the other must lose (None or also Some but
        // supersede the first). Either way, at most ONE 'promoted' row may
        // exist in this scope after both finish.
        let (res_a, res_b) = tokio::join!(
            promote_committed(&pool, &promoted_a),
            promote_committed(&pool, &promoted_b)
        );
        // Both must not return a DB error (only CAS miss / None is acceptable).
        let _ = res_a.expect("promote a no db error");
        let _ = res_b.expect("promote b no db error");

        // Assert: exactly one 'promoted' row in this scope.
        let promoted_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM golden_images \
             WHERE site_scope = 'CONCURRENT-TEST' AND os_family = 'Linux' AND status = 'promoted'",
        )
        .fetch_one(&pool)
        .await
        .expect("count query");

        assert_eq!(
            promoted_count, 1,
            "exactly one image must be promoted in the scope after concurrent promotions"
        );

        cleanup(&pool, &[id_a, id_b]).await;
    }

    #[tokio::test]
    async fn test_transition_cas_false() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Insert a Building image then try to CAS with wrong expected status
        let img = unique_image("DEFRA", "Windows", BuildStatus::Building);
        let id = img.id.clone();
        insert(&pool, &img).await.expect("insert");

        // Attempt transition expecting "testing" (wrong — row is "building")
        let testing_val = ryuki_engine::image_factory::run_tests(&img).expect("engine");
        let result = transition(&pool, "testing", &testing_val)
            .await
            .expect("no db error");
        assert!(
            result.is_none(),
            "CAS on wrong expected_status must return None"
        );

        cleanup(&pool, &[id]).await;
    }

    #[tokio::test]
    async fn test_promote_cas_false() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Insert a Building image (not Testing) and try to promote
        let img = unique_image("FRPAR", "Linux", BuildStatus::Building);
        let id = img.id.clone();
        insert(&pool, &img).await.expect("insert");

        // Construct a "promoted" value with the same id but wrong predecessor state
        let mut faux_promoted = img.clone();
        faux_promoted.status = BuildStatus::Promoted;

        let result = promote_committed(&pool, &faux_promoted)
            .await
            .expect("no db error");
        assert!(
            result.is_none(),
            "promote CAS from wrong state must return None"
        );

        cleanup(&pool, &[id]).await;
    }

    #[tokio::test]
    async fn test_list_promoted_and_superseded() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let promoted = unique_image("DEBER", "Linux", BuildStatus::Promoted);
        let superseded = unique_image("DEBER", "Linux", BuildStatus::Superseded);
        let ids = vec![promoted.id.clone(), superseded.id.clone()];
        insert(&pool, &promoted).await.expect("insert promoted");
        insert(&pool, &superseded).await.expect("insert superseded");

        let active = list_promoted(&pool, "DEBER").await.expect("list_promoted");
        assert!(active.iter().any(|i| i.id == promoted.id));
        assert!(!active.iter().any(|i| i.id == superseded.id));

        let all_superseded = list_superseded_page(&pool, None, 1000, 0)
            .await
            .expect("list_superseded_page");
        assert!(all_superseded.iter().any(|i| i.id == superseded.id));

        cleanup(&pool, &ids).await;
    }

    #[tokio::test]
    async fn test_reject_persists() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let img = unique_image("DEFRA", "Linux", BuildStatus::Building);
        let id = img.id.clone();
        insert(&pool, &img).await.expect("insert");

        let failed =
            ryuki_engine::image_factory::reject_image(&img, "CVE-2026-test").expect("engine");
        let before = status_str(&img.status);
        let persisted = transition(&pool, before, &failed)
            .await
            .expect("no db error")
            .expect("row");

        assert_eq!(persisted.status, BuildStatus::Failed);
        assert!(persisted.build_log.contains("CVE-2026-test"));

        cleanup(&pool, &[id]).await;
    }

    #[tokio::test]
    async fn test_get_nonexistent_and_malformed() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Non-existent UUID → Ok(None)
        let missing = get(&pool, &Uuid::new_v4().to_string())
            .await
            .expect("no error");
        assert!(missing.is_none());

        // Malformed id → Ok(None) (not an error)
        let malformed = get(&pool, "not-a-uuid").await.expect("no error");
        assert!(malformed.is_none());
    }
}
