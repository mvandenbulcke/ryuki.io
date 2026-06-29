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

pub mod access_recertification;
pub mod ad_computers;
pub mod aiops;
pub mod backup_coverage_reports;
pub mod certificates;
pub mod compliance_reporting;
pub mod configuration_items;
pub mod container_namespace;
pub mod cost_capacity;
pub mod datacenter_readiness;
pub mod decommissions;
pub mod degradation;
pub mod domain_events;
pub mod dr_plans;
pub mod dr_test_runs;
pub mod file_share_ntfs;
pub mod firewall_rule_sets;
pub mod firmware_lifecycle;
pub mod gmsa_accounts;
pub mod golden_images;
pub mod hardware_assets;
pub mod immutability_compliance;
pub mod incident_contexts;
pub mod integration_connections;
pub mod linux_deployment_requests;
pub mod load_balancer;
pub mod log_forwarders;
pub mod network_readiness;
pub mod notifications;
pub mod oidc_login_states;
pub mod os_baseline;
pub mod outage_comms;
pub mod patch_waves;
pub mod repository_capacity;
pub mod restore_requests;
pub mod runbook_executions;
pub mod shift_queue;
pub mod site_registry;
pub mod snapshots;
pub mod sql_deployment;
pub mod storage_provisioning;
pub mod synthetic_health;
pub mod vm_day2_operations;
pub mod zabbix_drift;
