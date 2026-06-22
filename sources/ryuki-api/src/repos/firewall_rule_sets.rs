//! Repository functions for `firewall_rule_sets`.
//!
//! Full `FirewallRuleSet` round-tripped through `rule_set_json` JSONB column.
//! Scalar `status` and `site` columns kept in sync for queryability.
//! xmin CAS in `transition` guards all mutations.

use ryuki_engine::firewall_rules::{FirewallRuleSet, RuleSetStatus};
use sqlx::PgPool;

pub const COLUMNS: &str =
    "id, status, rule_set_json::text AS rule_set_json, xmin::text AS row_version";

#[derive(sqlx::FromRow)]
pub struct FirewallRuleSetRow {
    pub id: String,
    pub status: String,
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

pub async fn insert(pool: &PgPool, rs: &FirewallRuleSet) -> Result<(), sqlx::Error> {
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
    .execute(pool)
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

pub async fn list(pool: &PgPool) -> Result<Vec<FirewallRuleSet>, sqlx::Error> {
    let rows: Vec<FirewallRuleSetRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM firewall_rule_sets ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<FirewallRuleSet>, sqlx::Error> {
    let rows: Vec<FirewallRuleSetRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM firewall_rule_sets WHERE site = $1 \
         ORDER BY created_at DESC, id DESC"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically update a rule set IFF the row has NOT been written since it was
/// read (xmin CAS). Returns `Ok(false)` on CAS mismatch — handler maps this to 409.
pub async fn transition(
    pool: &PgPool,
    id: &str,
    expected_version: &str,
    updated: &FirewallRuleSet,
) -> Result<bool, sqlx::Error> {
    let rule_set_json = serde_json::to_value(updated).map_err(|e| {
        sqlx::Error::Decode(format!("firewall_rule_sets: serialize failed: {e}").into())
    })?;
    let mut tx = pool.begin().await?;
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
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
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
        let cas_ok = transition(&pool, &id, &version, &updated)
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
        let cas_ok = transition(&pool, &id, &version, &updated)
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
        transition(&pool, &id, &version, &revoked)
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
        let cas_ok = transition(&pool, &id, "0", &updated)
            .await
            .expect("transition");
        assert!(!cas_ok, "wrong version must return false (CAS miss)");

        // Original version should still work
        let cas_ok2 = transition(&pool, &id, &version, &updated)
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
        let all = list(&pool).await.expect("list");
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

        let frpar_sets = list_by_site(&pool, "FRPAR").await.expect("list_by_site");
        assert!(
            frpar_sets.iter().any(|r| r.id == id),
            "inserted FRPAR set must appear in list_by_site(FRPAR)"
        );

        // Other sites must not bleed in
        let defra_sets = list_by_site(&pool, "DEFRA")
            .await
            .expect("list_by_site DEFRA");
        assert!(
            !defra_sets.iter().any(|r| r.id == id),
            "FRPAR set must not appear in list_by_site(DEFRA)"
        );

        cleanup(&pool, &id).await;
    }
}
