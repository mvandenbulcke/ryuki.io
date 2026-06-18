//! Repository functions for `switch_ports`, `vlans`, and `port_reservations`
//! (migration 019_network_readiness.sql).
//!
//! # UUID discipline
//! All PK `id` columns are UUID. SELECT casts: `id::text AS id`.
//! Bind via `Uuid::parse_str` — malformed id → `Ok(None)` (caller → 404).
//!
//! # Status values
//! switch_ports.status   ∈ { Available, InUse, Reserved, Disabled }
//! port_reservations.status ∈ { reserved, released }
//! All stored as plain TEXT — no serde mismatch, no enum-decode helper needed.
//!
//! # Concurrency design
//! reserve_ports:        SELECT … FOR UPDATE to lock candidate rows before UPDATE.
//! reserve_ips:          Atomic capacity check+decrement via
//!                       UPDATE … WHERE available_ips >= $count RETURNING vlan_id.
//! release_reservation:  SELECT … FOR UPDATE on the reservation row; short-circuit
//!                       if already 'released' (idempotency guard — no double-restore).
//!
//! # port_ids TEXT[] handling
//! switch_ports.id is a UUID PK but is stored in port_reservations.port_ids as
//! TEXT[] (text representations of the UUIDs).  We bind/cast all port ids as
//! text throughout.  When we need to UPDATE switch_ports by those ids we cast
//! the array elements back to UUID: `WHERE id = ANY($1::uuid[])`.
//!
//! # Timestamps
//! All TIMESTAMPTZ columns decoded as `DateTime<Utc>`, converted to RFC 3339
//! strings in `into_model`. NEVER `::text` on a timestamp column.

use chrono::{DateTime, Utc};
use ryuki_engine::network_readiness::{PortReservation, SwitchPort, VLAN};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

pub const PORT_COLUMNS: &str = "id::text AS id, \
     switch_name, \
     port_number, \
     vlan_id, \
     vlan_name, \
     status, \
     connected_device, \
     site, \
     created_at, \
     updated_at";

pub const VLAN_COLUMNS: &str = "id::text AS id, \
     vlan_id, \
     vlan_name, \
     subnet, \
     gateway, \
     site, \
     purpose, \
     available_ips, \
     created_at, \
     updated_at";

pub const RESERVATION_COLUMNS: &str = "id::text AS id, \
     reservation_id, \
     site, \
     resource_type, \
     vlan_id, \
     port_ids, \
     ip_count, \
     purpose, \
     status, \
     created_at, \
     updated_at";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct SwitchPortRow {
    pub id: String,
    pub switch_name: String,
    pub port_number: i32,
    pub vlan_id: i32,
    pub vlan_name: String,
    pub status: String,
    pub connected_device: Option<String>,
    pub site: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SwitchPortRow {
    pub fn into_model(self) -> Result<SwitchPort, sqlx::Error> {
        let port_number = u32::try_from(self.port_number).map_err(|e| {
            sqlx::Error::Decode(format!("switch_ports.port_number out of range: {e}").into())
        })?;
        let vlan_id = u32::try_from(self.vlan_id).map_err(|e| {
            sqlx::Error::Decode(format!("switch_ports.vlan_id out of range: {e}").into())
        })?;
        Ok(SwitchPort {
            id: self.id,
            switch_name: self.switch_name,
            port_number,
            vlan_id,
            vlan_name: self.vlan_name,
            status: self.status,
            connected_device: self.connected_device,
            site: self.site,
        })
    }
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct VlanRow {
    pub id: String,
    pub vlan_id: i32,
    pub vlan_name: String,
    pub subnet: String,
    pub gateway: String,
    pub site: String,
    pub purpose: String,
    pub available_ips: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VlanRow {
    pub fn into_model(self) -> Result<VLAN, sqlx::Error> {
        let vlan_id = u32::try_from(self.vlan_id)
            .map_err(|e| sqlx::Error::Decode(format!("vlans.vlan_id out of range: {e}").into()))?;
        let available_ips = u32::try_from(self.available_ips).map_err(|e| {
            sqlx::Error::Decode(format!("vlans.available_ips out of range: {e}").into())
        })?;
        Ok(VLAN {
            id: self.id,
            vlan_id,
            vlan_name: self.vlan_name,
            subnet: self.subnet,
            gateway: self.gateway,
            site: self.site,
            purpose: self.purpose,
            available_ips,
        })
    }
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct ReservationRow {
    pub id: String,
    pub reservation_id: String,
    pub site: String,
    pub resource_type: String,
    pub vlan_id: Option<i32>,
    pub port_ids: Vec<String>,
    pub ip_count: i32,
    pub purpose: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ReservationRow {
    pub fn into_model(self) -> Result<PortReservation, sqlx::Error> {
        let vlan_id = self
            .vlan_id
            .map(|v| {
                u32::try_from(v).map_err(|e| {
                    sqlx::Error::Decode(
                        format!("port_reservations.vlan_id out of range: {e}").into(),
                    )
                })
            })
            .transpose()?;
        let ip_count = u32::try_from(self.ip_count).map_err(|e| {
            sqlx::Error::Decode(format!("port_reservations.ip_count out of range: {e}").into())
        })?;
        Ok(PortReservation {
            reservation_id: self.reservation_id,
            site: self.site,
            resource_type: self.resource_type,
            vlan_id,
            port_ids: self.port_ids,
            ip_count,
            purpose: self.purpose,
            status: self.status,
            created_at: self.created_at.to_rfc3339(),
        })
    }
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List all switch ports, optionally filtered by site.
pub async fn list_ports(pool: &PgPool, site: &str) -> Result<Vec<SwitchPort>, sqlx::Error> {
    let rows: Vec<SwitchPortRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {PORT_COLUMNS} FROM switch_ports ORDER BY site, switch_name, port_number"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {PORT_COLUMNS} FROM switch_ports WHERE site = $1 ORDER BY switch_name, port_number"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List switch ports for a specific switch.
pub async fn list_ports_by_switch(
    pool: &PgPool,
    switch_name: &str,
) -> Result<Vec<SwitchPort>, sqlx::Error> {
    let rows: Vec<SwitchPortRow> = sqlx::query_as(&format!(
        "SELECT {PORT_COLUMNS} FROM switch_ports WHERE switch_name = $1 ORDER BY port_number"
    ))
    .bind(switch_name)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List all VLANs, optionally filtered by site.
pub async fn list_vlans(pool: &PgPool, site: &str) -> Result<Vec<VLAN>, sqlx::Error> {
    let rows: Vec<VlanRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {VLAN_COLUMNS} FROM vlans ORDER BY site, vlan_id"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {VLAN_COLUMNS} FROM vlans WHERE site = $1 ORDER BY vlan_id"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Get a single reservation by its `reservation_id` TEXT key.
/// Returns `Ok(None)` if not found.
pub async fn get_reservation(
    pool: &PgPool,
    reservation_id: &str,
) -> Result<Option<PortReservation>, sqlx::Error> {
    let row: Option<ReservationRow> = sqlx::query_as(&format!(
        "SELECT {RESERVATION_COLUMNS} FROM port_reservations WHERE reservation_id = $1"
    ))
    .bind(reservation_id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

// ─── Mutation functions ───────────────────────────────────────────────────────

/// Reserve `count` Available ports at `site` in a single transaction.
///
/// Locking: `SELECT … FOR UPDATE` locks the candidate rows so two concurrent
/// callers cannot allocate the same ports.
///
/// Returns `Err("insufficient")` when fewer than `count` ports are available
/// (callers map to 409).  Other `sqlx::Error` variants → 500.
pub async fn reserve_ports(
    pool: &PgPool,
    site: &str,
    count: u32,
    purpose: &str,
) -> Result<PortReservation, ReserveError> {
    if count == 0 {
        return Err(ReserveError::Invalid(
            "count must be greater than zero".into(),
        ));
    }

    let mut tx = pool.begin().await?;

    // Lock candidate rows so concurrent callers cannot pick the same ports.
    // SKIP LOCKED makes two concurrent reservations for the same site each grab
    // a DISTINCT set of free ports without blocking: the second caller skips the
    // rows the first has locked and the LIMIT is filled from the remaining
    // Available ports, so neither double-allocates nor sees a spurious shortage.
    let candidate_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT id::text FROM switch_ports \
         WHERE site = $1 AND status = 'Available' \
         ORDER BY id \
         LIMIT $2 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(site)
    .bind(count as i64)
    .fetch_all(&mut *tx)
    .await?;

    if candidate_rows.len() < count as usize {
        tx.rollback().await?;
        return Err(ReserveError::Insufficient {
            needed: count,
            available: candidate_rows.len() as u32,
        });
    }

    let port_ids: Vec<String> = candidate_rows.into_iter().map(|(id,)| id).collect();

    // Parse all port id strings as UUIDs for the UPDATE.
    let port_uuids: Vec<Uuid> = port_ids
        .iter()
        .map(|s| Uuid::parse_str(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| sqlx::Error::Decode(format!("port id UUID parse: {e}").into()))?;

    sqlx::query(
        "UPDATE switch_ports \
         SET status = 'Reserved', updated_at = NOW() \
         WHERE id = ANY($1)",
    )
    .bind(&port_uuids)
    .execute(&mut *tx)
    .await?;

    let reservation_id = ryuki_engine::network_readiness::new_reservation_id();

    sqlx::query(
        "INSERT INTO port_reservations \
         (reservation_id, site, resource_type, vlan_id, port_ids, ip_count, purpose, status, \
          created_at, updated_at) \
         VALUES ($1, $2, 'ports', NULL, $3, 0, $4, 'reserved', NOW(), NOW())",
    )
    .bind(&reservation_id)
    .bind(site)
    .bind(&port_ids)
    .bind(purpose)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Re-read to return the canonical model.
    get_reservation(pool, &reservation_id)
        .await?
        .ok_or_else(|| {
            sqlx::Error::Decode("port_reservations: row vanished immediately after insert".into())
                .into()
        })
}

/// Reserve `count` IPs from VLAN `(site, vlan_id_)` in a single transaction.
///
/// The capacity check and decrement are atomic: the UPDATE's `WHERE available_ips >= $count`
/// prevents a race where two concurrent callers both see sufficient capacity.
///
/// Returns:
/// - `Err(ReserveError::NotFound)` when the VLAN doesn't exist at `site`.
/// - `Err(ReserveError::Insufficient)` when the VLAN exists but lacks capacity.
pub async fn reserve_ips(
    pool: &PgPool,
    site: &str,
    vlan_id_: u32,
    count: u32,
    purpose: &str,
) -> Result<PortReservation, ReserveError> {
    // Validate the request BEFORE touching the DB. `count`/`vlan_id` arrive as
    // u32 from the JSON body; binding them to an INTEGER column with `as i32`
    // would WRAP a value above i32::MAX to a negative number, which defeats the
    // `available_ips >= $count` guard (always true for a negative) and turns the
    // decrement into an INCREMENT — committed capacity inflation. Convert with
    // checked try_from and reject zero so a degenerate request can't allocate.
    if count == 0 {
        return Err(ReserveError::Invalid(
            "count must be greater than zero".into(),
        ));
    }
    let count_i32 = i32::try_from(count).map_err(|_| {
        ReserveError::Invalid(format!("count {count} exceeds the maximum of {}", i32::MAX))
    })?;
    let vlan_i32 = i32::try_from(vlan_id_).map_err(|_| {
        ReserveError::Invalid(format!(
            "vlan_id {vlan_id_} exceeds the maximum of {}",
            i32::MAX
        ))
    })?;

    let mut tx = pool.begin().await?;

    // Atomic decrement — only succeeds if available_ips >= count.
    let row: Option<(i32,)> = sqlx::query_as(
        "UPDATE vlans \
         SET available_ips = available_ips - $1, updated_at = NOW() \
         WHERE site = $2 AND vlan_id = $3 AND available_ips >= $1 \
         RETURNING available_ips",
    )
    .bind(count_i32)
    .bind(site)
    .bind(vlan_i32)
    .fetch_optional(&mut *tx)
    .await?;

    if row.is_none() {
        // Determine whether the VLAN is absent (not-found) or just insufficient.
        let exists: Option<(bool,)> =
            sqlx::query_as("SELECT TRUE FROM vlans WHERE site = $1 AND vlan_id = $2")
                .bind(site)
                .bind(vlan_i32)
                .fetch_optional(&mut *tx)
                .await?;
        tx.rollback().await?;
        if exists.is_none() {
            return Err(ReserveError::NotFound);
        } else {
            return Err(ReserveError::Insufficient {
                needed: count,
                available: 0, // exact value not critical; caller gets 409
            });
        }
    }

    let reservation_id = ryuki_engine::network_readiness::new_reservation_id();

    sqlx::query(
        "INSERT INTO port_reservations \
         (reservation_id, site, resource_type, vlan_id, port_ids, ip_count, purpose, status, \
          created_at, updated_at) \
         VALUES ($1, $2, 'ips', $3, '{}', $4, $5, 'reserved', NOW(), NOW())",
    )
    .bind(&reservation_id)
    .bind(site)
    .bind(vlan_i32)
    .bind(count_i32)
    .bind(purpose)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    get_reservation(pool, &reservation_id)
        .await?
        .ok_or_else(|| {
            sqlx::Error::Decode("port_reservations: row vanished immediately after insert".into())
                .into()
        })
}

/// Release a reservation, restoring the consumed resources.
///
/// Idempotency guard: if the reservation is already 'released', returns
/// `Err(ReleaseError::AlreadyReleased)` WITHOUT restoring anything (prevents
/// double-restore / capacity inflation).
///
/// Returns `Err(ReleaseError::NotFound)` if no row with `reservation_id` exists.
pub async fn release_reservation(
    pool: &PgPool,
    reservation_id: &str,
) -> Result<PortReservation, ReleaseError> {
    let mut tx = pool.begin().await?;

    // Lock the reservation row to serialize concurrent release attempts.
    let row: Option<ReservationRow> = sqlx::query_as(&format!(
        "SELECT {RESERVATION_COLUMNS} FROM port_reservations \
         WHERE reservation_id = $1 \
         FOR UPDATE"
    ))
    .bind(reservation_id)
    .fetch_optional(&mut *tx)
    .await?;

    let resv_row = match row {
        None => {
            tx.rollback().await?;
            return Err(ReleaseError::NotFound);
        }
        Some(r) => r,
    };

    // Idempotency guard — do NOT restore if already released.
    if resv_row.status == "released" {
        tx.rollback().await?;
        return Err(ReleaseError::AlreadyReleased);
    }

    if resv_row.resource_type == "ports" {
        // Parse every stored port id strictly. A malformed id means the row is
        // corrupt; fail loudly (rolling the tx back via the `?` early return)
        // rather than silently dropping the port from the restore and then
        // marking the reservation released with that port stuck in 'Reserved'.
        let port_uuids: Vec<Uuid> = resv_row
            .port_ids
            .iter()
            .map(|s| Uuid::parse_str(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                sqlx::Error::Decode(format!("port_reservations.port_ids UUID parse: {e}").into())
            })?;

        if !port_uuids.is_empty() {
            // Restore only ports still in 'Reserved' state AND not claimed by a
            // DIFFERENT active reservation. The status guard avoids overriding a
            // port someone moved to InUse; the NOT EXISTS guard avoids freeing a
            // port that — after out-of-band repair — was re-reserved by another
            // active reservation (releasing this one must not clobber that one).
            sqlx::query(
                "UPDATE switch_ports sp \
                 SET status = 'Available', updated_at = NOW() \
                 WHERE sp.id = ANY($1) AND sp.status = 'Reserved' \
                 AND NOT EXISTS ( \
                     SELECT 1 FROM port_reservations pr \
                     WHERE pr.reservation_id <> $2 \
                       AND pr.status = 'reserved' \
                       AND sp.id::text = ANY(pr.port_ids) \
                 )",
            )
            .bind(&port_uuids)
            .bind(reservation_id)
            .execute(&mut *tx)
            .await?;
        }
    } else if resv_row.resource_type == "ips" {
        if let Some(vlan_id_db) = resv_row.vlan_id {
            sqlx::query(
                "UPDATE vlans \
                 SET available_ips = available_ips + $1, updated_at = NOW() \
                 WHERE site = $2 AND vlan_id = $3",
            )
            .bind(resv_row.ip_count)
            .bind(&resv_row.site)
            .bind(vlan_id_db)
            .execute(&mut *tx)
            .await?;
        }
    }

    sqlx::query(
        "UPDATE port_reservations SET status = 'released', updated_at = NOW() \
         WHERE reservation_id = $1",
    )
    .bind(reservation_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    get_reservation(pool, reservation_id).await?.ok_or_else(|| {
        sqlx::Error::Decode("port_reservations: row vanished after release".into()).into()
    })
}

// ─── Error types ─────────────────────────────────────────────────────────────

/// Errors that can occur during a reservation attempt.
#[derive(Debug)]
pub enum ReserveError {
    /// A request value is out of the valid range, e.g. count == 0 or a count /
    /// vlan_id above i32::MAX that cannot be bound to an INTEGER column without
    /// wrapping negative (→ 400 Bad Request).
    Invalid(String),
    /// Fewer resources available than requested (→ 409 Conflict).
    Insufficient { needed: u32, available: u32 },
    /// The target resource (VLAN) does not exist (→ 404 Not Found).
    NotFound,
    /// Database / transport error (→ 500).
    Db(sqlx::Error),
}

impl std::fmt::Display for ReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveError::Invalid(msg) => write!(f, "invalid request: {msg}"),
            ReserveError::Insufficient { needed, available } => {
                write!(
                    f,
                    "insufficient capacity: needed {needed}, available {available}"
                )
            }
            ReserveError::NotFound => write!(f, "resource not found"),
            ReserveError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl From<sqlx::Error> for ReserveError {
    fn from(e: sqlx::Error) -> Self {
        ReserveError::Db(e)
    }
}

/// Errors that can occur during a release attempt.
#[derive(Debug)]
pub enum ReleaseError {
    /// No reservation with that id (→ 404 Not Found).
    NotFound,
    /// Reservation already released — idempotency guard (→ 409 Conflict).
    AlreadyReleased,
    /// Database / transport error (→ 500).
    Db(sqlx::Error),
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseError::NotFound => write!(f, "reservation not found"),
            ReleaseError::AlreadyReleased => write!(f, "reservation already released"),
            ReleaseError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl From<sqlx::Error> for ReleaseError {
    fn from(e: sqlx::Error) -> Self {
        ReleaseError::Db(e)
    }
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 network_readiness_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod network_readiness_db_tests {
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

    /// Delete a reservation by its reservation_id TEXT key and restore any
    /// port/vlan state it may have left behind (best-effort cleanup).
    async fn cleanup_reservation(pool: &PgPool, reservation_id: &str) {
        // Best-effort: ignore errors (reservation may already be released/cleaned)
        let _ = sqlx::query("DELETE FROM port_reservations WHERE reservation_id = $1")
            .bind(reservation_id)
            .execute(pool)
            .await;
    }

    /// Reset all switch_ports for a site back to Available (cleanup helper).
    async fn reset_ports_to_available(pool: &PgPool, site: &str) {
        let _ = sqlx::query(
            "UPDATE switch_ports SET status = 'Available', updated_at = NOW() \
             WHERE site = $1 AND status IN ('Reserved')",
        )
        .bind(site)
        .execute(pool)
        .await;
    }

    #[tokio::test]
    async fn reserve_ports_happy_path() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Ensure clean state for our test site
        reset_ports_to_available(&pool, "DEFRA").await;

        let resv = reserve_ports(&pool, "DEFRA", 3, "test-reserve-ports")
            .await
            .expect("reserve_ports should succeed");

        assert_eq!(resv.resource_type, "ports");
        assert_eq!(resv.port_ids.len(), 3, "3 port_ids in reservation");
        assert_eq!(resv.status, "reserved");
        assert_eq!(resv.site, "DEFRA");

        // Verify the ports are now Reserved in the DB
        let reserved_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM switch_ports \
             WHERE id = ANY($1::uuid[]) AND status = 'Reserved'",
        )
        .bind(
            resv.port_ids
                .iter()
                .filter_map(|s| Uuid::parse_str(s).ok())
                .collect::<Vec<_>>(),
        )
        .fetch_one(&pool)
        .await
        .expect("count reserved ports");
        assert_eq!(reserved_count.0, 3, "all 3 ports should be Reserved");

        // Verify port_ids stored in the DB
        let stored: Option<(Vec<String>,)> =
            sqlx::query_as("SELECT port_ids FROM port_reservations WHERE reservation_id = $1")
                .bind(&resv.reservation_id)
                .fetch_optional(&pool)
                .await
                .expect("fetch reservation");
        assert!(stored.is_some(), "reservation row must exist");
        let (stored_ids,) = stored.unwrap();
        assert_eq!(stored_ids.len(), 3, "port_ids TEXT[] has 3 entries");

        cleanup_reservation(&pool, &resv.reservation_id).await;
        reset_ports_to_available(&pool, "DEFRA").await;
    }

    #[tokio::test]
    async fn reserve_ports_insufficient_capacity() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let result = reserve_ports(&pool, "DEFRA", 9999, "test-insufficient").await;

        match result {
            Err(ReserveError::Insufficient { .. }) => {} // expected
            other => panic!("expected Insufficient, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn reserve_ips_happy_path_and_insufficient() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Reset DEFRA VLAN 100 available_ips to a known value
        sqlx::query(
            "UPDATE vlans SET available_ips = 200, updated_at = NOW() \
             WHERE site = 'DEFRA' AND vlan_id = 100",
        )
        .execute(&pool)
        .await
        .expect("reset vlan available_ips");

        let resv = reserve_ips(&pool, "DEFRA", 100, 5, "test-reserve-ips")
            .await
            .expect("reserve_ips should succeed");

        assert_eq!(resv.resource_type, "ips");
        assert_eq!(resv.ip_count, 5);
        assert_eq!(resv.vlan_id, Some(100));
        assert_eq!(resv.status, "reserved");

        // Verify available_ips decremented
        let (available,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'DEFRA' AND vlan_id = 100",
        )
        .fetch_one(&pool)
        .await
        .expect("fetch vlan");
        assert_eq!(available, 195, "available_ips should be 200 - 5 = 195");

        cleanup_reservation(&pool, &resv.reservation_id).await;

        // Now test insufficient: request more than available
        sqlx::query(
            "UPDATE vlans SET available_ips = 3, updated_at = NOW() \
             WHERE site = 'DEFRA' AND vlan_id = 100",
        )
        .execute(&pool)
        .await
        .expect("set low available_ips");

        let result = reserve_ips(&pool, "DEFRA", 100, 10, "test-insufficient-ips").await;
        match result {
            Err(ReserveError::Insufficient { .. }) => {} // expected
            other => panic!("expected Insufficient, got {:?}", other),
        }

        // Restore
        sqlx::query(
            "UPDATE vlans SET available_ips = 200, updated_at = NOW() \
             WHERE site = 'DEFRA' AND vlan_id = 100",
        )
        .execute(&pool)
        .await
        .expect("restore vlan available_ips");
    }

    #[tokio::test]
    async fn reserve_ips_vlan_not_found() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let result = reserve_ips(&pool, "DEFRA", 99999, 1, "test-vlan-not-found").await;
        match result {
            Err(ReserveError::NotFound) => {} // expected
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    /// Regression for the integer-overflow HIGH: a `count` above i32::MAX once
    /// wrapped negative via `as i32`, passed the `available_ips >= $count` guard,
    /// and INCREASED available_ips (capacity inflation). It must now be rejected
    /// as Invalid before the transaction, leaving capacity untouched. Zero is
    /// rejected too.
    #[tokio::test]
    async fn reserve_ips_rejects_invalid_count_without_corrupting_capacity() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        sqlx::query(
            "UPDATE vlans SET available_ips = 50, updated_at = NOW() \
             WHERE site = 'DEFRA' AND vlan_id = 100",
        )
        .execute(&pool)
        .await
        .expect("seed vlan capacity");

        let huge = reserve_ips(&pool, "DEFRA", 100, 4_000_000_000, "attack").await;
        assert!(
            matches!(huge, Err(ReserveError::Invalid(_))),
            "oversized count must be rejected as Invalid, got {:?}",
            huge
        );

        let zero = reserve_ips(&pool, "DEFRA", 100, 0, "zero").await;
        assert!(
            matches!(zero, Err(ReserveError::Invalid(_))),
            "zero count must be rejected as Invalid, got {:?}",
            zero
        );

        let (available,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'DEFRA' AND vlan_id = 100",
        )
        .fetch_one(&pool)
        .await
        .expect("fetch vlan");
        assert_eq!(
            available, 50,
            "capacity must be untouched by rejected invalid-count requests"
        );
    }

    #[tokio::test]
    async fn release_reservation_restores_ports() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        reset_ports_to_available(&pool, "GBLON").await;

        let resv = reserve_ports(&pool, "GBLON", 2, "test-release-ports")
            .await
            .expect("reserve_ports");

        // Verify ports are Reserved
        let reserved_uuids: Vec<Uuid> = resv
            .port_ids
            .iter()
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();
        let (reserved_before,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM switch_ports WHERE id = ANY($1) AND status = 'Reserved'",
        )
        .bind(&reserved_uuids)
        .fetch_one(&pool)
        .await
        .expect("count reserved");
        assert_eq!(reserved_before, 2);

        // Release
        let released = release_reservation(&pool, &resv.reservation_id)
            .await
            .expect("release_reservation");
        assert_eq!(released.status, "released");

        // Verify ports are back to Available
        let (available_after,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM switch_ports WHERE id = ANY($1) AND status = 'Available'",
        )
        .bind(&reserved_uuids)
        .fetch_one(&pool)
        .await
        .expect("count available after release");
        assert_eq!(
            available_after, 2,
            "ports should be Available after release"
        );

        cleanup_reservation(&pool, &resv.reservation_id).await;
    }

    #[tokio::test]
    async fn release_reservation_restores_ips() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        sqlx::query(
            "UPDATE vlans SET available_ips = 100, updated_at = NOW() \
             WHERE site = 'GBLON' AND vlan_id = 110",
        )
        .execute(&pool)
        .await
        .expect("reset GBLON vlan 110");

        let resv = reserve_ips(&pool, "GBLON", 110, 7, "test-release-ips")
            .await
            .expect("reserve_ips");

        let (after_reserve,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'GBLON' AND vlan_id = 110",
        )
        .fetch_one(&pool)
        .await
        .expect("fetch vlan after reserve");
        assert_eq!(after_reserve, 93, "100 - 7 = 93");

        let released = release_reservation(&pool, &resv.reservation_id)
            .await
            .expect("release");
        assert_eq!(released.status, "released");

        let (after_release,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'GBLON' AND vlan_id = 110",
        )
        .fetch_one(&pool)
        .await
        .expect("fetch vlan after release");
        assert_eq!(after_release, 100, "IPs restored: 93 + 7 = 100");

        cleanup_reservation(&pool, &resv.reservation_id).await;
    }

    #[tokio::test]
    async fn release_already_released_does_not_double_restore() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        sqlx::query(
            "UPDATE vlans SET available_ips = 50, updated_at = NOW() \
             WHERE site = 'DEFRA' AND vlan_id = 200",
        )
        .execute(&pool)
        .await
        .expect("reset vlan");

        let resv = reserve_ips(&pool, "DEFRA", 200, 5, "test-double-release")
            .await
            .expect("reserve_ips");

        let (after_reserve,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'DEFRA' AND vlan_id = 200",
        )
        .fetch_one(&pool)
        .await
        .expect("fetch after reserve");
        assert_eq!(after_reserve, 45);

        // First release
        release_reservation(&pool, &resv.reservation_id)
            .await
            .expect("first release");

        let (after_first_release,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'DEFRA' AND vlan_id = 200",
        )
        .fetch_one(&pool)
        .await
        .expect("after first release");
        assert_eq!(after_first_release, 50, "restored to 50");

        // Second release — must return AlreadyReleased, NOT restore again
        let result = release_reservation(&pool, &resv.reservation_id).await;
        match result {
            Err(ReleaseError::AlreadyReleased) => {} // expected
            other => panic!("expected AlreadyReleased, got {:?}", other),
        }

        let (after_second_release,): (i32,) = sqlx::query_as(
            "SELECT available_ips FROM vlans WHERE site = 'DEFRA' AND vlan_id = 200",
        )
        .fetch_one(&pool)
        .await
        .expect("after second release attempt");
        assert_eq!(after_second_release, 50, "must NOT have increased to 55");

        sqlx::query(
            "UPDATE vlans SET available_ips = 180, updated_at = NOW() \
             WHERE site = 'DEFRA' AND vlan_id = 200",
        )
        .execute(&pool)
        .await
        .expect("restore seed value");

        cleanup_reservation(&pool, &resv.reservation_id).await;
    }

    #[tokio::test]
    async fn inventory_and_capacity_reads() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // list_ports
        let ports = list_ports(&pool, "DEFRA").await.expect("list_ports DEFRA");
        assert!(!ports.is_empty(), "DEFRA has seed ports");
        for p in &ports {
            assert_eq!(p.site, "DEFRA");
        }

        // list_ports_by_switch
        let sw_ports = list_ports_by_switch(&pool, "defra-sw-01")
            .await
            .expect("list_ports_by_switch");
        assert_eq!(sw_ports.len(), 8, "defra-sw-01 has 8 seed ports");

        // list_vlans
        let vlans = list_vlans(&pool, "GBLON").await.expect("list_vlans GBLON");
        assert!(!vlans.is_empty(), "GBLON has seed VLANs");
        for v in &vlans {
            assert_eq!(v.site, "GBLON");
        }

        // get_reservation for a nonexistent id
        let missing = get_reservation(&pool, "presv-nonexistent")
            .await
            .expect("get_reservation should not error");
        assert!(missing.is_none(), "nonexistent reservation_id → Ok(None)");
    }
}
