//! Repository functions for `gmsa_accounts` + `gmsa_host_assignments`.
//!
//! Ordinary reads use `&PgPool`; mutations accept a caller-owned transaction
//! connection where row/site locks and atomic audit are required. Operational
//! paths expose only Verified rows whose exact persisted owner site is active.
//!
//! # Design: engine vs. repo responsibility split
//! The engine functions (`assign_to_host`, `remove_from_host`) are the pure
//! lifecycle specification. The repo `add_host`/`remove_host` functions repeat
//! the mutable invariants under database locks, including current owner-site
//! authorization, so a stale read or concurrent mutation fails closed.
//!
//! # Child table join
//! `authorized_hosts` is stored in the `gmsa_host_assignments` child table,
//! one row per host. All read queries aggregate hosts via `array_agg` with a
//! LEFT JOIN so accounts with no hosts return an empty array rather than NULL.
//!
//! # TEXT[] native bind
//! `service_principal_names` is a native Postgres `TEXT[]` column; sqlx binds
//! and decodes `Vec<String>` ↔ `TEXT[]` directly — no JSON serialization and
//! no `::text` cast needed in SELECT.

use chrono::{DateTime, Utc};
use ryuki_engine::gmsa_lifecycle::{GMSAAccount, GMSAStatus};
use ryuki_engine::site_registry::DIRECTORY_NAMESPACE_POLICY_VERSION;
#[cfg(test)]
use sqlx::Row;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

// ─── SELECT fragment ─────────────────────────────────────────────────────────

/// Aggregating SELECT that joins the child table to build `authorized_hosts`.
/// The GROUP BY is mandatory because of the `array_agg` window.
///
/// Note: `service_principal_names` is TEXT[] — decoded directly by sqlx into
/// `Vec<String>`, no JSON cast required. `authorized_hosts` is derived via
/// `array_agg(h.host) FILTER (WHERE h.host IS NOT NULL)` so that LEFT JOINs
/// with no matching child rows return `'{}'::text[]` rather than `{NULL}`.
const SELECT_AGG: &str = "SELECT \
     a.id::text AS id, \
     a.name, \
     a.sam_account_name, \
     a.dns_host_name, \
     a.service_principal_names, \
     COALESCE(array_agg(h.host ORDER BY h.host) FILTER (WHERE h.host IS NOT NULL), '{}') AS authorized_hosts, \
     a.site, \
     a.status, \
     a.managed_password_interval_days, \
     a.created_at, \
     a.last_rotation_at \
     FROM gmsa_accounts a \
     LEFT JOIN gmsa_host_assignments h ON h.gmsa_account_id = a.id";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct GmsaAccountRow {
    pub id: String,
    pub name: String,
    pub sam_account_name: String,
    pub dns_host_name: String,
    /// Native TEXT[] decoded directly by sqlx — no JSON intermediary.
    pub service_principal_names: Vec<String>,
    /// Aggregated from `gmsa_host_assignments` via array_agg.
    pub authorized_hosts: Vec<String>,
    pub site: String,
    pub status: String,
    /// Postgres INTEGER → i32; converted to u32 in `into_model`.
    pub managed_password_interval_days: i32,
    pub created_at: DateTime<Utc>,
    pub last_rotation_at: DateTime<Utc>,
}

impl GmsaAccountRow {
    /// Convert a DB row into the engine model.
    ///
    /// The status enum is stored as its serde PascalCase name and decoded via
    /// `serde_json`. A parse failure means the persisted row is corrupt; we
    /// surface it as a decode error (caller → 500) rather than substituting a
    /// default — a subsequent write would otherwise CAS against the wrong
    /// status. A DB CHECK constraint (migration 020) keeps status in the legal
    /// set.
    pub fn into_model(self) -> Result<GMSAAccount, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("gmsa_accounts.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let status: GMSAStatus = decode(&format!("\"{}\"", self.status), "status")?;

        let managed_password_interval_days = u32::try_from(self.managed_password_interval_days)
            .map_err(|_| {
                sqlx::Error::Decode(
                    format!(
                        "gmsa_accounts.managed_password_interval_days: negative value {}",
                        self.managed_password_interval_days
                    )
                    .into(),
                )
            })?;

        Ok(GMSAAccount {
            id: self.id,
            name: self.name,
            sam_account_name: self.sam_account_name,
            dns_host_name: self.dns_host_name,
            service_principal_names: self.service_principal_names,
            authorized_hosts: self.authorized_hosts,
            site: self.site,
            status,
            managed_password_interval_days,
            created_at: self.created_at.to_rfc3339(),
            last_rotation_at: self.last_rotation_at.to_rfc3339(),
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `GMSAStatus` value as stored in the DB
/// (e.g. `"Active"`, `"Revoked"`). `pub` so handlers can supply guard-checked
/// expected_status values without duplicating this table.
pub fn status_str(s: &GMSAStatus) -> &'static str {
    match s {
        GMSAStatus::Active => "Active",
        GMSAStatus::Expiring => "Expiring",
        GMSAStatus::Expired => "Expired",
        GMSAStatus::Revoked => "Revoked",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Fetch one account by name (the domain key). Returns `Ok(None)` when no row
/// matches — callers map to 404.
pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<Option<GMSAAccount>, sqlx::Error> {
    let row: Option<GmsaAccountRow> = sqlx::query_as(&format!(
        "{SELECT_AGG} WHERE a.namespace_state = 'Verified' AND a.name = $1 \
             AND EXISTS (SELECT 1 FROM site_registry AS registry \
                         WHERE registry.unlocode = a.namespace_owner_site \
                           AND registry.active \
                           AND a.namespace_owner_site = a.site) \
             GROUP BY a.id"
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all accounts ordered by name. When `site` is non-empty the result is
/// filtered to that site; an empty string returns all sites.
pub async fn list(pool: &PgPool, site: &str) -> Result<Vec<GMSAAccount>, sqlx::Error> {
    let rows: Vec<GmsaAccountRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "{SELECT_AGG} WHERE a.namespace_state = 'Verified' \
             AND EXISTS (SELECT 1 FROM site_registry AS registry \
                         WHERE registry.unlocode = a.namespace_owner_site \
                           AND registry.active \
                           AND a.namespace_owner_site = a.site) \
             GROUP BY a.id ORDER BY a.name"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "{SELECT_AGG} WHERE a.namespace_state = 'Verified' AND a.site = $1 \
             AND EXISTS (SELECT 1 FROM site_registry AS registry \
                         WHERE registry.unlocode = a.namespace_owner_site \
                           AND registry.active \
                           AND a.namespace_owner_site = a.site) \
             GROUP BY a.id ORDER BY a.name"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List accounts (optionally site-filtered) bounded to one `LIMIT`/`OFFSET`
/// page (#14). SEPARATE from [`list`] because the expiry sweep (`gmsa_expiring`)
/// scans every account. `a.name` is unique, and `a.id` (PK) is appended for a
/// guaranteed-stable page. The `LIMIT`/`OFFSET` apply AFTER `GROUP BY a.id`, so
/// they bound DISTINCT accounts (not the array_agg-joined rows).
pub async fn list_page(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<GMSAAccount>, sqlx::Error> {
    let rows: Vec<GmsaAccountRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "{SELECT_AGG} WHERE a.namespace_state = 'Verified' \
             AND EXISTS (SELECT 1 FROM site_registry AS registry \
                         WHERE registry.unlocode = a.namespace_owner_site \
                           AND registry.active \
                           AND a.namespace_owner_site = a.site) \
             GROUP BY a.id ORDER BY a.name, a.id LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "{SELECT_AGG} WHERE a.namespace_state = 'Verified' AND a.site = $1 \
             AND EXISTS (SELECT 1 FROM site_registry AS registry \
                         WHERE registry.unlocode = a.namespace_owner_site \
                           AND registry.active \
                           AND a.namespace_owner_site = a.site) \
             GROUP BY a.id ORDER BY a.name, a.id LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count DISTINCT accounts (optionally site-filtered) — the pagination total for
/// [`list_page`]. Counts the BASE `gmsa_accounts` table (NOT the LEFT-JOIN +
/// array_agg query, whose pre-GROUP row count would over-count).
pub async fn count(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM gmsa_accounts AS account \
             WHERE namespace_state = 'Verified' \
               AND EXISTS (SELECT 1 FROM site_registry AS registry \
                           WHERE registry.unlocode = account.namespace_owner_site \
                             AND registry.active \
                             AND account.namespace_owner_site = account.site)",
        )
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM gmsa_accounts AS account \
             WHERE namespace_state = 'Verified' AND site = $1 \
               AND EXISTS (SELECT 1 FROM site_registry AS registry \
                           WHERE registry.unlocode = account.namespace_owner_site \
                             AND registry.active \
                             AND account.namespace_owner_site = account.site)",
        )
        .bind(site)
        .fetch_one(pool)
        .await
    }
}

/// Insert a new account and its initial authorized-host rows inside a
/// caller-owned transaction, then return the persisted account.
///
/// The caller opens the tx, passes `conn = &mut *tx`, and commits on success.
/// A duplicate `name` violates the UNIQUE constraint and propagates as a
/// `sqlx::Error` with `is_unique_violation() == true` — callers map this to 409.
///
/// The re-read to return DB-authoritative timestamps must happen AFTER the
/// caller has committed; callers do a post-commit `get_by_name(pool, name)`
/// with the pool (not the tx) as the final response.
pub async fn insert(conn: &mut PgConnection, r: &GMSAAccount) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let created_at: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let last_rotation_at: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.last_rotation_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let interval_days = i32::try_from(r.managed_password_interval_days).map_err(|_| {
        sqlx::Error::Decode(
            format!(
                "gmsa_accounts.managed_password_interval_days: {} exceeds i32",
                r.managed_password_interval_days
            )
            .into(),
        )
    })?;

    sqlx::query(
        "INSERT INTO gmsa_accounts \
         (id, name, sam_account_name, dns_host_name, service_principal_names, \
          site, status, managed_password_interval_days, created_at, last_rotation_at, \
          namespace_owner_site, namespace_policy_version, namespace_state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'Verified')",
    )
    .bind(id)
    .bind(&r.name)
    .bind(&r.sam_account_name)
    .bind(&r.dns_host_name)
    .bind(&r.service_principal_names)
    .bind(&r.site)
    .bind(status_str(&r.status))
    .bind(interval_days)
    .bind(created_at)
    .bind(last_rotation_at)
    .bind(&r.site)
    .bind(DIRECTORY_NAMESPACE_POLICY_VERSION)
    .execute(&mut *conn)
    .await?;

    // Dedup the input hosts so a repeated host in the request can't trip the
    // child-table UNIQUE constraint (which the caller would otherwise misreport
    // as a duplicate *name*); ON CONFLICT is belt-and-suspenders.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for host in &r.authorized_hosts {
        if !seen.insert(host.as_str()) {
            continue;
        }
        sqlx::query(
            "INSERT INTO gmsa_host_assignments (gmsa_account_id, host) VALUES ($1, $2) \
             ON CONFLICT (gmsa_account_id, host) DO NOTHING",
        )
        .bind(id)
        .bind(host)
        .execute(&mut *conn)
        .await?;
    }

    Ok(())
}

/// Outcome of a host-assignment mutation. The repo enforces the lifecycle
/// invariants at WRITE time, under a `FOR UPDATE` lock on the account row, so
/// two concurrent callers can never both pass a stale-read guard. The handler
/// maps each outcome to an HTTP status.
#[derive(Debug, PartialEq, Eq)]
pub enum HostOpOutcome {
    /// The change was applied.
    Applied,
    /// No account with that name exists (→ 404).
    AccountNotFound,
    /// The account is revoked, so hosts cannot be assigned (→ 409).
    AccountRevoked,
    /// The host is not currently assigned, so it cannot be removed (→ 409).
    HostNotPresent,
    /// Removing the host would leave the account with zero hosts (→ 409).
    LastHost,
}

/// Rotate a gMSA's managed password: set `last_rotation_at = NOW()` and status
/// `Active`, IFF the row still has the `expected_status` the caller loaded
/// (optimistic lock). Returns `Ok(None)` when no row matches — the account is
/// gone or was concurrently changed (e.g. revoked) — which the caller maps to
/// 404/409. Only the rotation-relevant columns are written, so a concurrent
/// metadata change (SPNs/site/etc.) is never clobbered by a stale full-row write.
///
/// Accepts any `sqlx::PgExecutor<'_>` (pool reference OR `&mut *tx`) so a
/// handler can compose the mutation and an audit row in a single atomic tx.
/// The caller re-reads via `get_by_name(pool, name)` after commit for the response.
pub async fn rotate(
    executor: impl sqlx::PgExecutor<'_>,
    name: &str,
    expected_status: &str,
) -> Result<bool, sqlx::Error> {
    let affected = sqlx::query(
        "UPDATE gmsa_accounts \
         SET last_rotation_at = NOW(), status = 'Active', updated_at = NOW() \
         WHERE name = $1 AND status = $2 AND namespace_state = 'Verified' \
           AND EXISTS (SELECT 1 FROM site_registry AS registry \
                       WHERE registry.unlocode = gmsa_accounts.namespace_owner_site \
                         AND registry.active \
                         AND gmsa_accounts.namespace_owner_site = gmsa_accounts.site)",
    )
    .bind(name)
    .bind(expected_status)
    .execute(executor)
    .await?
    .rows_affected();

    Ok(affected > 0)
}

/// Assign a host to an account, concurrency-safely. Locks the account row
/// (`FOR UPDATE`) so a concurrent revoke cannot slip between the guard and the
/// insert; re-checks the revoked guard under the lock; then upserts the child
/// row (idempotent via ON CONFLICT). The engine `assign_to_host` is the pure
/// spec of this logic; this is its concurrency-safe persistence.
///
/// The caller owns the transaction: pass `conn = &mut *tx`, and commit only
/// on `Applied`. Early-return outcomes roll back via tx drop at the call site.
pub async fn add_host(
    conn: &mut PgConnection,
    name: &str,
    host: &str,
) -> Result<HostOpOutcome, sqlx::Error> {
    let acct: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT account.id, account.status \
         FROM gmsa_accounts AS account \
         JOIN site_registry AS registry \
           ON registry.unlocode = account.namespace_owner_site \
          AND registry.active \
         WHERE account.name = $1 \
           AND account.namespace_state = 'Verified' \
           AND account.namespace_owner_site = account.site \
         FOR UPDATE OF account FOR SHARE OF registry",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((acct_id, status)) = acct else {
        return Ok(HostOpOutcome::AccountNotFound);
    };
    if status == "Revoked" {
        return Ok(HostOpOutcome::AccountRevoked);
    }

    sqlx::query(
        "INSERT INTO gmsa_host_assignments (gmsa_account_id, host) VALUES ($1, $2) \
         ON CONFLICT (gmsa_account_id, host) DO NOTHING",
    )
    .bind(acct_id)
    .bind(host)
    .execute(&mut *conn)
    .await?;

    Ok(HostOpOutcome::Applied)
}

/// Remove a host from an account, concurrency-safely. Locks the account row
/// (`FOR UPDATE`) so two concurrent removes serialize: the host-present and
/// last-host invariants are checked under the lock, immediately before the
/// delete, so concurrent callers can never both pass a stale last-host guard
/// and drain the account to zero authorized hosts.
///
/// The caller owns the transaction: pass `conn = &mut *tx`, and commit only
/// on `Applied`. Early-return outcomes roll back via tx drop at the call site.
pub async fn remove_host(
    conn: &mut PgConnection,
    name: &str,
    host: &str,
) -> Result<HostOpOutcome, sqlx::Error> {
    let acct: Option<Uuid> = sqlx::query_scalar(
        "SELECT account.id \
         FROM gmsa_accounts AS account \
         JOIN site_registry AS registry \
           ON registry.unlocode = account.namespace_owner_site \
          AND registry.active \
         WHERE account.name = $1 \
           AND account.namespace_state = 'Verified' \
           AND account.namespace_owner_site = account.site \
         FOR UPDATE OF account FOR SHARE OF registry",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(acct_id) = acct else {
        return Ok(HostOpOutcome::AccountNotFound);
    };

    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM gmsa_host_assignments WHERE gmsa_account_id = $1 AND host = $2",
    )
    .bind(acct_id)
    .bind(host)
    .fetch_one(&mut *conn)
    .await?;
    if present == 0 {
        return Ok(HostOpOutcome::HostNotPresent);
    }

    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM gmsa_host_assignments WHERE gmsa_account_id = $1")
            .bind(acct_id)
            .fetch_one(&mut *conn)
            .await?;
    if total <= 1 {
        return Ok(HostOpOutcome::LastHost);
    }

    sqlx::query("DELETE FROM gmsa_host_assignments WHERE gmsa_account_id = $1 AND host = $2")
        .bind(acct_id)
        .bind(host)
        .execute(&mut *conn)
        .await?;

    Ok(HostOpOutcome::Applied)
}

/// Return only the `authorized_hosts` for an account. Used in tests to verify
/// child-row state without deserializing the full model.
#[cfg(test)]
pub async fn fetch_hosts(pool: &PgPool, name: &str) -> Result<Vec<String>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COALESCE(array_agg(h.host ORDER BY h.host), '{}') AS hosts \
         FROM gmsa_accounts a \
         LEFT JOIN gmsa_host_assignments h ON h.gmsa_account_id = a.id \
         WHERE a.namespace_state = 'Verified' AND a.name = $1 \
           AND EXISTS (SELECT 1 FROM site_registry AS registry \
                       WHERE registry.unlocode = a.namespace_owner_site \
                         AND registry.active \
                         AND a.namespace_owner_site = a.site) \
         GROUP BY a.id",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(vec![]),
        Some(r) => {
            let hosts: Vec<String> = r.try_get("hosts")?;
            Ok(hosts)
        }
    }
}
