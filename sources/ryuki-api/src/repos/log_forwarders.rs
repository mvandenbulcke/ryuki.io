//! Repository functions for `log_forwarders`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # ID type
//! `log_forwarders.id` is a plain `TEXT` primary key (not UUID). Ids are bound
//! and decoded directly as `String` — no `Uuid::parse_str` and no early-return
//! guard for malformed UUIDs.
//!
//! # Enum encoding
//! `status` and `source_type` are stored as their serde PascalCase variant names
//! (e.g. `"NotConfigured"`, `"WindowsEventLog"`). A parse failure means the
//! persisted row is corrupt; we surface it as a decode error (caller → 500)
//! rather than substituting a default. DB CHECK constraints (migration 065) keep
//! the values in the legal set.

use ryuki_engine::log_forwarder::{ForwardingStatus, LogSource, LogSourceType};
use sqlx::PgPool;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. `id` is TEXT so no cast is needed.
pub const COLUMNS: &str =
    "id, hostname, source_type, site, status, log_volume_per_day_mb, retention_days";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct LogForwarderRow {
    pub id: String,
    pub hostname: String,
    pub source_type: String,
    pub site: String,
    pub status: String,
    pub log_volume_per_day_mb: i32,
    pub retention_days: i32,
}

impl LogForwarderRow {
    /// Convert a DB row into the engine model.
    ///
    /// Both enum columns are stored as their serde PascalCase names and decoded
    /// via `serde_json`. A parse failure is surfaced as a decode error (caller →
    /// 500) rather than substituting a default — a subsequent transition would
    /// otherwise CAS against the wrong status string.
    pub fn into_model(self) -> Result<LogSource, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("log_forwarders.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let source_type: LogSourceType =
            decode(&format!("\"{}\"", self.source_type), "source_type")?;
        let status: ForwardingStatus = decode(&format!("\"{}\"", self.status), "status")?;

        Ok(LogSource {
            id: self.id,
            hostname: self.hostname,
            source_type,
            site: self.site,
            status,
            log_volume_per_day_mb: u32::try_from(self.log_volume_per_day_mb).map_err(|e| {
                sqlx::Error::Decode(
                    format!("log_forwarders.log_volume_per_day_mb: negative value: {e}").into(),
                )
            })?,
            retention_days: u32::try_from(self.retention_days).map_err(|e| {
                sqlx::Error::Decode(
                    format!("log_forwarders.retention_days: negative value: {e}").into(),
                )
            })?,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `ForwardingStatus` value as stored in the DB.
pub fn status_str(s: &ForwardingStatus) -> &'static str {
    match s {
        ForwardingStatus::NotConfigured => "NotConfigured",
        ForwardingStatus::Configured => "Configured",
        ForwardingStatus::Active => "Active",
        ForwardingStatus::Failed => "Failed",
    }
}

/// Canonical serde variant name for a `LogSourceType` value as stored in the DB.
pub fn source_type_str(t: &LogSourceType) -> &'static str {
    match t {
        LogSourceType::WindowsEventLog => "WindowsEventLog",
        LogSourceType::Syslog => "Syslog",
        LogSourceType::Auditd => "Auditd",
        LogSourceType::IIS => "IIS",
        LogSourceType::Apache => "Apache",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Fetch one log forwarder by id. Returns `Ok(None)` when no row is found
/// (caller → 404). `Err` is reserved for genuine DB failures (caller → 500).
///
/// Unlike UUID-keyed repos, there is no malformed-id early return: any string
/// is a valid TEXT key.
///
/// Currently used in db_tests only; retained for future single-item GET route.
#[allow(dead_code)]
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<LogSource>, sqlx::Error> {
    let row: Option<LogForwarderRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM log_forwarders WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all log forwarders ordered by site then id.
///
/// Currently used in db_tests only; retained for future list-all route.
#[allow(dead_code)]
pub async fn list(pool: &PgPool) -> Result<Vec<LogSource>, sqlx::Error> {
    let rows: Vec<LogForwarderRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM log_forwarders ORDER BY site, id"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all log forwarders for a given site, ordered by id.
pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<LogSource>, sqlx::Error> {
    let rows: Vec<LogForwarderRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM log_forwarders WHERE site = $1 ORDER BY id"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all log forwarders for a given hostname, ordered by id.
pub async fn list_by_hostname(
    pool: &PgPool,
    hostname: &str,
) -> Result<Vec<LogSource>, sqlx::Error> {
    let rows: Vec<LogForwarderRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM log_forwarders WHERE hostname = $1 ORDER BY id"
    ))
    .bind(hostname)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Insert a new log forwarder and return the persisted row. The caller supplies
/// the model with an already-generated id.
///
/// We `RETURNING` the inserted row so the returned model is DB-authoritative
/// (the response then matches a subsequent `get`).
#[allow(dead_code)]
pub async fn insert(pool: &PgPool, r: &LogSource) -> Result<LogSource, sqlx::Error> {
    let row: LogForwarderRow = sqlx::query_as(&format!(
        "INSERT INTO log_forwarders \
         (id, hostname, source_type, site, status, log_volume_per_day_mb, retention_days) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {COLUMNS}"
    ))
    .bind(&r.id)
    .bind(&r.hostname)
    .bind(source_type_str(&r.source_type))
    .bind(&r.site)
    .bind(status_str(&r.status))
    .bind(
        i32::try_from(r.log_volume_per_day_mb)
            .map_err(|e| sqlx::Error::Decode(format!("log_volume_per_day_mb: {e}").into()))?,
    )
    .bind(
        i32::try_from(r.retention_days)
            .map_err(|e| sqlx::Error::Decode(format!("retention_days: {e}").into()))?,
    )
    .fetch_one(pool)
    .await?;

    row.into_model()
}

/// Insert a new log forwarder within an existing transaction and return the
/// persisted row. Accepts a mutable reference to a `sqlx::Transaction` so the
/// caller can batch multiple inserts in a single atomic operation.
#[allow(dead_code)]
pub async fn insert_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    r: &LogSource,
) -> Result<LogSource, sqlx::Error> {
    let row: LogForwarderRow = sqlx::query_as(&format!(
        "INSERT INTO log_forwarders \
         (id, hostname, source_type, site, status, log_volume_per_day_mb, retention_days) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {COLUMNS}"
    ))
    .bind(&r.id)
    .bind(&r.hostname)
    .bind(source_type_str(&r.source_type))
    .bind(&r.site)
    .bind(status_str(&r.status))
    .bind(
        i32::try_from(r.log_volume_per_day_mb)
            .map_err(|e| sqlx::Error::Decode(format!("log_volume_per_day_mb: {e}").into()))?,
    )
    .bind(
        i32::try_from(r.retention_days)
            .map_err(|e| sqlx::Error::Decode(format!("retention_days: {e}").into()))?,
    )
    .fetch_one(&mut **tx)
    .await?;

    row.into_model()
}

/// Atomically transition a single log forwarder to its new status IFF the DB
/// row still has `expected_status`. Returns `Ok(None)` when the row is absent or
/// was concurrently modified (caller → 409), or `Ok(Some(persisted))` on success.
///
/// Single-row CAS helper retained for db_tests and future per-source routes; the
/// `logs_disable` handler now uses [`disable_all_for_hostname`] for an atomic,
/// advisory-locked bulk disable instead of looping this.
#[allow(dead_code)]
pub async fn transition(
    pool: &PgPool,
    id: &str,
    expected_status: &str,
    new_status: &str,
) -> Result<Option<LogSource>, sqlx::Error> {
    let row: Option<LogForwarderRow> = sqlx::query_as(&format!(
        "UPDATE log_forwarders \
         SET status = $3, updated_at = NOW() \
         WHERE id = $1 AND status = $2 \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(expected_status)
    .bind(new_status)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Persist a batch of log forwarders for a single `hostname`, serialized so two
/// concurrent onboard (or onboard/disable) calls for the same host cannot race.
///
/// The host "scope" may have zero existing rows, so a row-level `FOR UPDATE`
/// lock is not sufficient on its own — we first take a transaction-scoped
/// advisory lock keyed on the hostname, then lock any existing rows for the
/// hostname. For each requested source type: if absent, INSERT a `Configured`
/// row; if present and already `Configured`/`Active`, it is an idempotent no-op;
/// if present but `NotConfigured`/`Failed`, re-enable it (UPDATE to `Configured`,
/// refresh `site`) so re-onboarding a previously-disabled source is not silently
/// a no-op. Returns the rows this call inserted or re-enabled. The
/// `(hostname, source_type)` UNIQUE constraint (migration 066) is the hard
/// backstop behind this serialization.
pub async fn onboard_sources(
    conn: &mut sqlx::PgConnection,
    hostname: &str,
    sources: &[LogSource],
) -> Result<Vec<LogSource>, sqlx::Error> {
    // Serialize all onboard/disable activity for this hostname.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("log_forwarders:{hostname}"))
        .execute(&mut *conn)
        .await?;

    // Lock the hostname's existing rows and index them by source type.
    let existing: Vec<LogForwarderRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM log_forwarders WHERE hostname = $1 FOR UPDATE"
    ))
    .bind(hostname)
    .fetch_all(&mut *conn)
    .await?;
    let existing_by_type: std::collections::HashMap<String, (String, String)> = existing
        .into_iter()
        .map(|r| (r.source_type, (r.id, r.status)))
        .collect();

    let configured = status_str(&ForwardingStatus::Configured);
    let active = status_str(&ForwardingStatus::Active);

    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut persisted = Vec::new();
    for source in sources {
        let st = source_type_str(&source.source_type);
        // Dedupe within this batch so a duplicate never reaches the UNIQUE constraint.
        if !handled.insert(st.to_string()) {
            continue;
        }
        match existing_by_type.get(st) {
            // No row yet for this (hostname, source_type) — insert it under the
            // locked hostname, so a caller passing a source whose hostname
            // differs from the lock key can never write outside the locked scope.
            None => {
                let mut to_insert = source.clone();
                to_insert.hostname = hostname.to_string();
                let row: LogForwarderRow = sqlx::query_as(&format!(
                    "INSERT INTO log_forwarders \
                     (id, hostname, source_type, site, status, log_volume_per_day_mb, retention_days) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) \
                     RETURNING {COLUMNS}"
                ))
                .bind(&to_insert.id)
                .bind(&to_insert.hostname)
                .bind(source_type_str(&to_insert.source_type))
                .bind(&to_insert.site)
                .bind(status_str(&to_insert.status))
                .bind(
                    i32::try_from(to_insert.log_volume_per_day_mb)
                        .map_err(|e| sqlx::Error::Decode(format!("log_volume_per_day_mb: {e}").into()))?,
                )
                .bind(
                    i32::try_from(to_insert.retention_days)
                        .map_err(|e| sqlx::Error::Decode(format!("retention_days: {e}").into()))?,
                )
                .fetch_one(&mut *conn)
                .await?;
                persisted.push(row.into_model()?);
            }
            // Already Configured/Active — onboarding is an idempotent no-op.
            Some((_, status)) if status == configured || status == active => {}
            // Present but NotConfigured/Failed — re-enable it. Re-onboarding must
            // not silently leave a previously-disabled source disabled.
            Some((id, _)) => {
                let row: LogForwarderRow = sqlx::query_as(&format!(
                    "UPDATE log_forwarders SET status = $2, site = $3, updated_at = NOW() \
                     WHERE id = $1 RETURNING {COLUMNS}"
                ))
                .bind(id)
                .bind(configured)
                .bind(&source.site)
                .fetch_one(&mut *conn)
                .await?;
                persisted.push(row.into_model()?);
            }
        }
    }

    Ok(persisted)
}

/// Disable every still-active log source for `hostname` in one atomic step,
/// serialized against concurrent onboard/disable for the same host.
///
/// Takes the same per-hostname advisory lock as [`onboard_sources`], then issues
/// a single `UPDATE ... WHERE status <> 'NotConfigured'` so the transition is
/// atomic and cannot be left partial, and a concurrent onboard (which waits on
/// the same lock) cannot insert a new forwarding row mid-disable. Returns the
/// rows that were actually transitioned — their `source_type`s are the sources
/// that were disabled by this call.
pub async fn disable_all_for_hostname(
    conn: &mut sqlx::PgConnection,
    hostname: &str,
) -> Result<Vec<LogSource>, sqlx::Error> {
    // Serialize against concurrent onboard/disable for this hostname.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("log_forwarders:{hostname}"))
        .execute(&mut *conn)
        .await?;

    let not_configured = status_str(&ForwardingStatus::NotConfigured);
    let disabled: Vec<LogForwarderRow> = sqlx::query_as(&format!(
        "UPDATE log_forwarders SET status = $2, updated_at = NOW() \
         WHERE hostname = $1 AND status <> $2 \
         RETURNING {COLUMNS}"
    ))
    .bind(hostname)
    .bind(not_configured)
    .fetch_all(&mut *conn)
    .await?;

    disabled.into_iter().map(|r| r.into_model()).collect()
}

/// Disable log forwarding for a hostname, confined to a set of sites (#2 site
/// scope). Same advisory-locked, atomic, idempotent semantics as
/// [`disable_all_for_hostname`], but the UPDATE only touches rows whose `site`
/// is in `sites` — so a site-scoped principal can never disable another site's
/// forwarders. The handler derives `sites` from the rows it is actually
/// permitted to see, so an unrestricted principal still uses the unfiltered
/// path above.
pub async fn disable_for_hostname_in_sites(
    conn: &mut sqlx::PgConnection,
    hostname: &str,
    sites: &[String],
) -> Result<Vec<LogSource>, sqlx::Error> {
    // Serialize against concurrent onboard/disable for this hostname.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("log_forwarders:{hostname}"))
        .execute(&mut *conn)
        .await?;

    let not_configured = status_str(&ForwardingStatus::NotConfigured);
    let disabled: Vec<LogForwarderRow> = sqlx::query_as(&format!(
        "UPDATE log_forwarders SET status = $2, updated_at = NOW() \
         WHERE hostname = $1 AND status <> $2 AND site = ANY($3) \
         RETURNING {COLUMNS}"
    ))
    .bind(hostname)
    .bind(not_configured)
    .bind(sites)
    .fetch_all(&mut *conn)
    .await?;

    disabled.into_iter().map(|r| r.into_model()).collect()
}
