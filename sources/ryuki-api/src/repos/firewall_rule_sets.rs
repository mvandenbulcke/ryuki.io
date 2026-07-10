//! Repository functions for `firewall_rule_sets`.
//!
//! Full `FirewallRuleSet` round-tripped through `rule_set_json` JSONB column.
//! Scalar `status` and `site` columns kept in sync for queryability.
//! xmin CAS in `transition` guards all mutations.

use ryuki_engine::firewall_rules::{FirewallRuleSet, RuleSetStatus};
use sqlx::{PgConnection, PgPool};

pub const COLUMNS: &str =
    "id, status, site, rule_set_json::text AS rule_set_json, xmin::text AS row_version";

#[derive(sqlx::FromRow)]
pub struct FirewallRuleSetRow {
    pub id: String,
    pub status: String,
    pub site: String,
    pub rule_set_json: Option<String>,
    pub row_version: String,
}

impl FirewallRuleSetRow {
    pub fn into_model(self) -> Result<FirewallRuleSet, sqlx::Error> {
        let raw = self
            .rule_set_json
            .ok_or_else(|| sqlx::Error::Decode("firewall_rule_sets.rule_set_json: NULL".into()))?;
        let mut entity: FirewallRuleSet = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("firewall_rule_sets.rule_set_json: corrupt persisted value: {e}").into(),
            )
        })?;
        // DB status column is authoritative on read
        entity.status = decode_status(&self.status)
            .map_err(|e| sqlx::Error::Decode(format!("firewall_rule_sets.status: {e}").into()))?;
        // DB scalar `site` column is authoritative on read too (#2): scope checks
        // run against it, so it must not silently drift from the persisted JSON.
        entity.site = self.site;
        entity.id = self.id;
        Ok(entity)
    }
}

/// Canonical serde variant name for a `RuleSetStatus` as stored in the DB.
/// Matches the `#[serde(rename_all = "kebab-case")]` derivation.
pub fn status_str(s: &RuleSetStatus) -> &'static str {
    match s {
        RuleSetStatus::Draft => "draft",
        RuleSetStatus::Applied => "applied",
        RuleSetStatus::Revoked => "revoked",
    }
}

fn decode_status(s: &str) -> Result<RuleSetStatus, String> {
    serde_json::from_str(&format!("\"{s}\""))
        .map_err(|e| format!("unknown firewall_rule_sets status '{s}': {e}"))
}

pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    rs: &FirewallRuleSet,
) -> Result<(), sqlx::Error> {
    let rule_set_json = serde_json::to_value(rs).map_err(|e| {
        sqlx::Error::Decode(format!("firewall_rule_sets: serialize failed: {e}").into())
    })?;
    sqlx::query(
        "INSERT INTO firewall_rule_sets (id, name, site, status, rule_set_json) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&rs.id)
    .bind(&rs.name)
    .bind(&rs.site)
    .bind(status_str(&rs.status))
    .bind(rule_set_json)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get(
    pool: &PgPool,
    id: &str,
) -> Result<Option<(FirewallRuleSet, String)>, sqlx::Error> {
    let row: Option<FirewallRuleSetRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM firewall_rule_sets WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => {
            let version = r.row_version.clone();
            Ok(Some((r.into_model()?, version)))
        }
        None => Ok(None),
    }
}

/// One `LIMIT`/`OFFSET` page (#14) with the SITE SCOPE pushed into SQL — the
/// paged replacement for the handler's old fetch-all + in-memory
/// `retain_site_scoped`. `sites`: `None` = every site (an unrestricted
/// principal); `Some(list)` = only those sites (a site-scoped principal, or an
/// explicit `?site` as a one-element list) via `site = ANY($1)`. An
/// environment-scoped principal is handled by the caller (empty result), matching
/// `retain_site_scoped`. `ORDER BY created_at DESC, id DESC` ends in the unique
/// PK, so each page is a stable cut.
pub async fn list_page(
    pool: &PgPool,
    sites: Option<&[String]>,
    limit: i64,
    offset: i64,
) -> Result<Vec<FirewallRuleSet>, sqlx::Error> {
    let rows: Vec<FirewallRuleSetRow> = match sites {
        None => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM firewall_rule_sets \
                 ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
        Some(sites) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM firewall_rule_sets WHERE site = ANY($1) \
                 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
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

/// Count rule sets under the SAME site scope as [`list_page`] — the pagination
/// total. `None` = all sites; `Some(list)` = `site = ANY($1)`.
pub async fn count(pool: &PgPool, sites: Option<&[String]>) -> Result<i64, sqlx::Error> {
    match sites {
        None => {
            sqlx::query_scalar("SELECT COUNT(*) FROM firewall_rule_sets")
                .fetch_one(pool)
                .await
        }
        Some(sites) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM firewall_rule_sets WHERE site = ANY($1)")
                .bind(sites)
                .fetch_one(pool)
                .await
        }
    }
}

/// Atomically update a rule set IFF the row has NOT been written since it was
/// read (xmin CAS). Returns `Ok(false)` on CAS mismatch — handler maps this to 409.
/// The caller owns the transaction; pass `&mut *tx` where `tx: Transaction<'_, Postgres>`.
pub async fn transition(
    conn: &mut PgConnection,
    id: &str,
    expected_version: &str,
    updated: &FirewallRuleSet,
) -> Result<bool, sqlx::Error> {
    let rule_set_json = serde_json::to_value(updated).map_err(|e| {
        sqlx::Error::Decode(format!("firewall_rule_sets: serialize failed: {e}").into())
    })?;
    let res = sqlx::query(
        "UPDATE firewall_rule_sets SET \
         status = $2, \
         rule_set_json = $3, \
         updated_at = NOW() \
         WHERE id = $1 AND xmin = $4::xid",
    )
    .bind(id)
    .bind(status_str(&updated.status))
    .bind(rule_set_json)
    .bind(expected_version)
    .execute(conn)
    .await?;
    Ok(res.rows_affected() > 0)
}

// To run ONLY these DB tests:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//   cargo test -p ryuki-api --bins firewall_rule_sets_db_tests -- --test-threads=1
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod firewall_rule_sets_db_tests {
    use super::*;
    use ryuki_engine::firewall_rules::{apply_rule_set_pure, build_rule_set, revoke_rule_set_pure};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!(
                    "firewall_rule_sets_db_tests: RYUKI_DATABASE_URL not set — skipping DB tests"
                );
                return None;
            }
        };
        let pool = PgPool::connect(&url)
            .await
            .expect("firewall_rule_sets_db_tests: connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    fn unique_id() -> String {
        format!("fws-test-{}", &Uuid::new_v4().to_string()[..8])
    }

    async fn cleanup(pool: &PgPool, id: &str) {
        sqlx::query("DELETE FROM firewall_rule_sets WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn create_and_get() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let id = unique_id();
        let rs = build_rule_set(
            &id,
            "Test rule set",
            vec!["fw-defra-001".into()],
            "DEFRA",
            "defra-test-fw",
        )
        .expect("build");
        insert(&pool, &rs).await.expect("insert");

        let (fetched, _version) = get(&pool, &id).await.expect("get").expect("row");
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.name, "Test rule set");
        assert_eq!(fetched.site, "DEFRA");
        assert_eq!(fetched.status, RuleSetStatus::Draft);
        assert_eq!(fetched.rules, vec!["fw-defra-001"]);

        cleanup(&pool, &id).await;
    }

    /// #14: `list_page`/`count` push the site scope INTO SQL. `None` = all sites,
    /// `Some(list)` = `site = ANY(list)`. Verified against INDEPENDENT raw COUNTs;
    /// LIMIT/OFFSET give EXACT slices under the `created_at DESC, id DESC` tail; and
    /// a multi-site `ANY` equals the sum of the disjoint per-site subsets.
    #[tokio::test]
    async fn list_page_scopes_and_paginates() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Independent baselines (raw COUNT, NOT the fns under test).
        let raw_all: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_rule_sets")
            .fetch_one(&pool)
            .await
            .expect("raw all");
        let raw_defra: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM firewall_rule_sets WHERE site = $1")
                .bind("DEFRA")
                .fetch_one(&pool)
                .await
                .expect("raw defra");
        let defra = vec!["DEFRA".to_string()];
        assert_eq!(
            count(&pool, None).await.expect("count all"),
            raw_all,
            "count(None) == raw all-sites COUNT"
        );
        assert_eq!(
            count(&pool, Some(&defra)).await.expect("count defra"),
            raw_defra,
            "count(Some) == raw site-subset COUNT"
        );

        // Seed 3 DEFRA rule sets.
        let mut ids = Vec::new();
        for i in 0..3 {
            let id = unique_id();
            ids.push(id.clone());
            let rs = build_rule_set(
                &id,
                &format!("pg-{i}"),
                vec!["fw-defra-001".into()],
                "DEFRA",
                "edge",
            )
            .expect("build");
            insert(&pool, &rs).await.expect("insert");
        }
        let total = count(&pool, Some(&defra)).await.expect("count defra after");
        assert_eq!(
            total,
            raw_defra + 3,
            "3 DEFRA rows added to the site subset"
        );
        assert_eq!(
            count(&pool, None).await.expect("count all after"),
            raw_all + 3,
            "None counts every site"
        );

        // list_page(Some) returns exactly the DEFRA subset — nothing else leaks in.
        let all_defra = list_page(&pool, Some(&defra), 1000, 0)
            .await
            .expect("list defra");
        assert_eq!(
            all_defra.len() as i64,
            total,
            "full DEFRA page == its count"
        );
        assert!(
            all_defra.iter().all(|r| r.site == "DEFRA"),
            "Some(&[DEFRA]) must filter to DEFRA only"
        );
        let ordered: Vec<&str> = all_defra.iter().map(|r| r.id.as_str()).collect();

        // LIMIT bounds the page; OFFSET yields the EXACT next slice (stable tail).
        let page1 = list_page(&pool, Some(&defra), 2, 0).await.expect("page1");
        let page2 = list_page(&pool, Some(&defra), 2, 2).await.expect("page2");
        let p1: Vec<&str> = page1.iter().map(|r| r.id.as_str()).collect();
        let p2: Vec<&str> = page2.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(p1, ordered[0..2], "page 1 is the first 2 of the full order");
        assert_eq!(
            p2,
            ordered[2..(ordered.len().min(4))],
            "page 2 is the EXACT next slice"
        );

        // Multi-site ANY equals the sum of the disjoint per-site subsets.
        let defra_gblon = vec!["DEFRA".to_string(), "GBLON".to_string()];
        let gblon = vec!["GBLON".to_string()];
        let c_union = count(&pool, Some(&defra_gblon)).await.expect("count union");
        let c_gblon = count(&pool, Some(&gblon)).await.expect("count gblon");
        assert_eq!(
            c_union,
            total + c_gblon,
            "ANY(multi) == sum of the disjoint per-site counts"
        );

        for id in &ids {
            cleanup(&pool, id).await;
        }
    }

    #[tokio::test]
    async fn apply_persists() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let id = unique_id();
        let rs = build_rule_set(
            &id,
            "Apply test set",
            vec!["fw-gblon-001".into()],
            "GBLON",
            "gblon-test-fw",
        )
        .expect("build");
        insert(&pool, &rs).await.expect("insert");

        let (fetched, version) = get(&pool, &id).await.expect("get").expect("row");
        let updated = apply_rule_set_pure(&fetched).expect("apply");
        let mut conn = pool.acquire().await.expect("acquire");
        let cas_ok = transition(&mut conn, &id, &version, &updated)
            .await
            .expect("transition");
        assert!(cas_ok, "CAS should succeed");

        let (after, _) = get(&pool, &id).await.expect("get2").expect("row2");
        assert_eq!(after.status, RuleSetStatus::Applied);

        cleanup(&pool, &id).await;
    }

    #[tokio::test]
    async fn revoke_persists() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let id = unique_id();
        let rs = build_rule_set(
            &id,
            "Revoke test set",
            vec!["fw-nlams-001".into()],
            "NLAMS",
            "nlams-test-fw",
        )
        .expect("build");
        insert(&pool, &rs).await.expect("insert");

        let (fetched, version) = get(&pool, &id).await.expect("get").expect("row");
        let updated = revoke_rule_set_pure(&fetched).expect("revoke");
        let mut conn = pool.acquire().await.expect("acquire");
        let cas_ok = transition(&mut conn, &id, &version, &updated)
            .await
            .expect("transition");
        assert!(cas_ok);

        let (after, _) = get(&pool, &id).await.expect("get2").expect("row2");
        assert_eq!(after.status, RuleSetStatus::Revoked);

        cleanup(&pool, &id).await;
    }

    #[tokio::test]
    async fn apply_revoked_errs() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        // Build a revoked set by inserting then revoking
        let id = unique_id();
        let rs = build_rule_set(
            &id,
            "Revoked set",
            vec!["fw-defra-001".into()],
            "DEFRA",
            "defra-fw",
        )
        .expect("build");
        insert(&pool, &rs).await.expect("insert");
        let (fetched, version) = get(&pool, &id).await.expect("get").expect("row");
        let revoked = revoke_rule_set_pure(&fetched).expect("revoke");
        let mut conn = pool.acquire().await.expect("acquire");
        transition(&mut conn, &id, &version, &revoked)
            .await
            .expect("transition to revoked");

        // Now try to apply the revoked set
        let (revoked_rs, _) = get(&pool, &id).await.expect("get2").expect("row2");
        let result = apply_rule_set_pure(&revoked_rs);
        assert!(result.is_err(), "applying a revoked set must fail");
        assert!(result
            .unwrap_err()
            .contains("Cannot apply revoked rule set"));

        cleanup(&pool, &id).await;
    }

    #[tokio::test]
    async fn missing_id_404() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let result = get(&pool, "nonexistent-fws-id").await.expect("get");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cas_conflict() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let id = unique_id();
        let rs = build_rule_set(
            &id,
            "CAS conflict test",
            vec!["fw-defra-001".into()],
            "DEFRA",
            "defra-fw",
        )
        .expect("build");
        insert(&pool, &rs).await.expect("insert");

        let (fetched, version) = get(&pool, &id).await.expect("get").expect("row");
        let updated = apply_rule_set_pure(&fetched).expect("apply");

        // Use a wrong version
        let mut conn1 = pool.acquire().await.expect("acquire conn1");
        let cas_ok = transition(&mut conn1, &id, "0", &updated)
            .await
            .expect("transition");
        assert!(!cas_ok, "wrong version must return false (CAS miss)");

        // Original version should still work
        let mut conn2 = pool.acquire().await.expect("acquire conn2");
        let cas_ok2 = transition(&mut conn2, &id, &version, &updated)
            .await
            .expect("transition2");
        assert!(cas_ok2);

        cleanup(&pool, &id).await;
    }

    #[tokio::test]
    async fn list_returns_seeded() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let all = list_page(&pool, None, 1000, 0).await.expect("list_page");
        assert!(
            all.len() >= 3,
            "migration 089 seeds 3 rule sets, got {}",
            all.len()
        );
    }

    #[tokio::test]
    async fn list_by_site_filters() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };
        let id = unique_id();
        let rs = build_rule_set(
            &id,
            "Site filter test",
            vec!["fw-frpar-001".into()],
            "FRPAR",
            "frpar-fw",
        )
        .expect("build");
        insert(&pool, &rs).await.expect("insert");

        let frpar = vec!["FRPAR".to_string()];
        let frpar_sets = list_page(&pool, Some(&frpar), 1000, 0)
            .await
            .expect("list_page FRPAR");
        assert!(
            frpar_sets.iter().any(|r| r.id == id),
            "inserted FRPAR set must appear in the FRPAR-scoped page"
        );

        // Other sites must not bleed in
        let defra = vec!["DEFRA".to_string()];
        let defra_sets = list_page(&pool, Some(&defra), 1000, 0)
            .await
            .expect("list_page DEFRA");
        assert!(
            !defra_sets.iter().any(|r| r.id == id),
            "FRPAR set must not appear in the DEFRA-scoped page"
        );

        cleanup(&pool, &id).await;
    }
}
