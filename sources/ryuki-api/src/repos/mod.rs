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

pub mod aiops;
pub mod access_recertification;
pub mod ad_computers;
pub mod backup_coverage_reports;
pub mod certificates;
pub mod compliance_reporting;
pub mod container_namespace;
pub mod cost_capacity;
pub mod datacenter_readiness;
pub mod decommissions;
pub mod file_share_ntfs;
pub mod firmware_lifecycle;
pub mod gmsa_accounts;
pub mod golden_images;
pub mod hardware_assets;
pub mod immutability_compliance;
pub mod load_balancer;
pub mod log_forwarders;
pub mod network_readiness;
pub mod os_baseline;
pub mod outage_comms;
pub mod patch_waves;
pub mod repository_capacity;
pub mod restore_requests;
pub mod snapshots;
pub mod sql_deployment;
pub mod storage_provisioning;
pub mod synthetic_health;
pub mod zabbix_drift;
