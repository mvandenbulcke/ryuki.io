//! Repository layer — pure I/O functions over `&PgPool`.
//!
//! # Contract
//!
//! - Every function takes `&PgPool` and returns `Result<T, sqlx::Error>`.
//! - No business logic lives here; engines remain I/O-free.
//! - Handlers in `contracts.rs` own the error-mapping: `sqlx::Error` → `db_error`,
//!   `None` → `status_404`, state conflicts → `status_409`.
//! - All UUID primary keys are cast to `TEXT` in SELECT (`id::text AS id`) so
//!   sqlx decodes them into Rust `String` without a raw-UUID column binding.
//! - JSONB columns are cast to `TEXT` in SELECT and deserialized by the repo.
//!   On writes they are serialized to JSON strings and bound as TEXT.

pub mod backup_coverage_reports;
pub mod certificates;
pub mod decommissions;
pub mod gmsa_accounts;
pub mod patch_waves;
pub mod restore_requests;
pub mod snapshots;
