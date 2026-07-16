use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool};
use std::collections::{BTreeMap, BTreeSet};
use std::env::VarError;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(not(test))]
static POOL: OnceLock<Option<PgPool>> = OnceLock::new();
static MIGRATION_STATUS: AtomicU8 = AtomicU8::new(MigrationStatus::NotApplied as u8);

/// Compile-time migration inventory used by every startup mode. The macro
/// embeds every migration present at build time; there is deliberately no
/// hard-coded latest version, so a newly added migration is automatically part
/// of apply-only and verify-only decisions in the same image.
pub static EMBEDDED_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const DEFAULT_MIGRATION_STATEMENT_TIMEOUT_SECS: u64 = 1_800;
const DEFAULT_MIGRATION_LOCK_TIMEOUT_SECS: u64 = 60;
const MIN_MIGRATION_STATEMENT_TIMEOUT_SECS: u64 = 60;
const MAX_MIGRATION_STATEMENT_TIMEOUT_SECS: u64 = 7_200;
const MIN_MIGRATION_LOCK_TIMEOUT_SECS: u64 = 1;
const MAX_MIGRATION_LOCK_TIMEOUT_SECS: u64 = 300;
const MIGRATION_CONNECTION_ACQUIRE_TIMEOUT_SECS: u64 = 30;

/// Selects who owns schema mutation during process startup.
///
/// `local-auto` preserves the historical local-development behavior, but now
/// uses the same isolated migration connection and reviewed DDL timeouts as the
/// one-shot runner. Kubernetes sets `verify-only` on the API Deployment and
/// runs a separate `apply-only` Job with a distinct database identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStartupMode {
    LocalAuto,
    ApplyOnly,
    VerifyOnly,
}

impl MigrationStartupMode {
    pub fn serves_http(self) -> bool {
        !matches!(self, Self::ApplyOnly)
    }

    /// Final process gate after the mode-specific migration action. Only the
    /// deliberate no-database local-development path may serve without an
    /// applied inventory; production verify-only always requires exact proof.
    pub fn permits_serving_with(self, status: MigrationStatus, pool_present: bool) -> bool {
        match self {
            Self::LocalAuto => matches!(
                (status, pool_present),
                (MigrationStatus::Applied, true) | (MigrationStatus::NotApplied, false)
            ),
            Self::VerifyOnly => status == MigrationStatus::Applied && pool_present,
            Self::ApplyOnly => false,
        }
    }
}

impl fmt::Display for MigrationStartupMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LocalAuto => "local-auto",
            Self::ApplyOnly => "apply-only",
            Self::VerifyOnly => "verify-only",
        })
    }
}

impl FromStr for MigrationStartupMode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "local-auto" => Ok(Self::LocalAuto),
            "apply-only" => Ok(Self::ApplyOnly),
            "verify-only" => Ok(Self::VerifyOnly),
            _ => Err(
                "RYUKI_MIGRATION_MODE must be one of local-auto, apply-only, verify-only".into(),
            ),
        }
    }
}

fn migration_startup_mode_from_value(raw: Option<&str>) -> Result<MigrationStartupMode, String> {
    let Some(raw) = raw else {
        return Err(
            "RYUKI_MIGRATION_MODE is required; choose local-auto, apply-only, or verify-only"
                .into(),
        );
    };
    raw.parse()
}

pub fn migration_startup_mode_from_env() -> Result<MigrationStartupMode, String> {
    let raw = optional_unicode_env("RYUKI_MIGRATION_MODE")?;
    migration_startup_mode_from_value(raw.as_deref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationTimeouts {
    pub statement_timeout_secs: u64,
    pub lock_timeout_secs: u64,
}

impl Default for MigrationTimeouts {
    fn default() -> Self {
        Self {
            statement_timeout_secs: DEFAULT_MIGRATION_STATEMENT_TIMEOUT_SECS,
            lock_timeout_secs: DEFAULT_MIGRATION_LOCK_TIMEOUT_SECS,
        }
    }
}

impl MigrationTimeouts {
    fn parse_value(label: &str, raw: Option<&str>, default: u64) -> Result<u64, String> {
        match raw {
            Some(value) => value
                .parse::<u64>()
                .map_err(|_| format!("{label} must be an integer number of seconds")),
            None => Ok(default),
        }
    }

    fn from_values(statement: Option<&str>, lock: Option<&str>) -> Result<Self, String> {
        let statement_timeout_secs = Self::parse_value(
            "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS",
            statement,
            DEFAULT_MIGRATION_STATEMENT_TIMEOUT_SECS,
        )?;
        let lock_timeout_secs = Self::parse_value(
            "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS",
            lock,
            DEFAULT_MIGRATION_LOCK_TIMEOUT_SECS,
        )?;
        if !(MIN_MIGRATION_STATEMENT_TIMEOUT_SECS..=MAX_MIGRATION_STATEMENT_TIMEOUT_SECS)
            .contains(&statement_timeout_secs)
        {
            return Err(format!(
                "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS must be between {MIN_MIGRATION_STATEMENT_TIMEOUT_SECS} and {MAX_MIGRATION_STATEMENT_TIMEOUT_SECS}"
            ));
        }
        if !(MIN_MIGRATION_LOCK_TIMEOUT_SECS..=MAX_MIGRATION_LOCK_TIMEOUT_SECS)
            .contains(&lock_timeout_secs)
        {
            return Err(format!(
                "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS must be between {MIN_MIGRATION_LOCK_TIMEOUT_SECS} and {MAX_MIGRATION_LOCK_TIMEOUT_SECS}"
            ));
        }
        if lock_timeout_secs >= statement_timeout_secs {
            return Err(
                "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS must be less than RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS"
                    .into(),
            );
        }
        Ok(Self {
            statement_timeout_secs,
            lock_timeout_secs,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        let statement = optional_unicode_env("RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS")?;
        let lock = optional_unicode_env("RYUKI_MIGRATION_LOCK_TIMEOUT_SECS")?;
        Self::from_values(statement.as_deref(), lock.as_deref())
    }
}

fn optional_unicode_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(format!("{name} must contain valid Unicode")),
    }
}

const MAX_DATABASE_ROLE_NAME_BYTES: usize = 63;

fn canonical_database_role_name(variable: &str, raw: String) -> Result<String, String> {
    let bytes = raw.as_bytes();
    let first_is_valid = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_');
    let rest_is_valid = bytes
        .iter()
        .skip(1)
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_');
    if raw.is_empty()
        || raw.len() > MAX_DATABASE_ROLE_NAME_BYTES
        || !first_is_valid
        || !rest_is_valid
    {
        return Err(format!("{variable} must match [a-z_][a-z0-9_]{{0,62}}"));
    }
    Ok(raw)
}

fn required_role_env(name: &str) -> Result<String, String> {
    let Some(raw) = optional_unicode_env(name)? else {
        return Err(format!("{name} is required for this migration mode"));
    };
    canonical_database_role_name(name, raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationRoleContract {
    expected: String,
    forbidden: String,
}

impl ApplicationRoleContract {
    fn from_values(expected: String, forbidden: String) -> Result<Self, String> {
        let expected = canonical_database_role_name("RYUKI_DATABASE_EXPECTED_ROLE", expected)?;
        let forbidden = canonical_database_role_name("RYUKI_DATABASE_FORBIDDEN_ROLE", forbidden)?;
        if expected == forbidden {
            return Err(
                "RYUKI_DATABASE_EXPECTED_ROLE and RYUKI_DATABASE_FORBIDDEN_ROLE must differ".into(),
            );
        }
        Ok(Self {
            expected,
            forbidden,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_values(
            required_role_env("RYUKI_DATABASE_EXPECTED_ROLE")?,
            required_role_env("RYUKI_DATABASE_FORBIDDEN_ROLE")?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRoleContract {
    expected: String,
    application: String,
}

impl MigrationRoleContract {
    fn from_values(expected: String, application: String) -> Result<Self, String> {
        let expected = canonical_database_role_name("RYUKI_MIGRATION_EXPECTED_ROLE", expected)?;
        let application =
            canonical_database_role_name("RYUKI_APPLICATION_DATABASE_ROLE", application)?;
        if expected == application {
            return Err(
                "RYUKI_MIGRATION_EXPECTED_ROLE and RYUKI_APPLICATION_DATABASE_ROLE must differ"
                    .into(),
            );
        }
        Ok(Self {
            expected,
            application,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_values(
            required_role_env("RYUKI_MIGRATION_EXPECTED_ROLE")?,
            required_role_env("RYUKI_APPLICATION_DATABASE_ROLE")?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TablePolicy {
    name: &'static str,
    insert: bool,
    update: bool,
    delete: bool,
}

impl TablePolicy {
    const fn new(name: &'static str, insert: bool, update: bool, delete: bool) -> Self {
        Self {
            name,
            insert,
            update,
            delete,
        }
    }
}

/// Exact runtime table authority for the embedded migration inventory. There
/// is deliberately no default for a newly added table: migration postflight
/// and every strict application connection compare the public schema against
/// this complete list and fail closed on an omission. SELECT is required for
/// every entry; the booleans represent INSERT, UPDATE, and DELETE respectively.
/// TRUNCATE, REFERENCES, TRIGGER, MAINTAIN, and every grant option are denied
/// for every table.
const APPLICATION_TABLE_POLICIES: &[TablePolicy] = &[
    TablePolicy::new("access_reviews", true, true, true),
    TablePolicy::new("ad_computers", true, true, false),
    TablePolicy::new("ad_quarantine_recovery_reviews", true, true, false),
    TablePolicy::new("agent_enrollment_challenges", true, true, false),
    TablePolicy::new("agent_jobs", true, true, false),
    TablePolicy::new("agents", true, true, false),
    TablePolicy::new("aiops_suggestions", true, true, true),
    TablePolicy::new("alert_acks", true, true, true),
    TablePolicy::new("alert_routes", true, true, true),
    TablePolicy::new("api_tokens", true, true, false),
    TablePolicy::new("app_environments", true, true, true),
    TablePolicy::new("approved_packages", true, true, true),
    TablePolicy::new("audit_chain_verification_jobs", true, true, true),
    TablePolicy::new("audit_log", false, false, false),
    TablePolicy::new("backup_coverage_reports", true, true, true),
    TablePolicy::new("backup_repositories", true, true, true),
    TablePolicy::new("baseline_checks", true, true, true),
    TablePolicy::new("baseline_results", true, true, true),
    TablePolicy::new("build_test_results", true, true, true),
    TablePolicy::new("capacity_history", true, true, true),
    TablePolicy::new("certificate_site_authority_quarantine", false, false, false),
    TablePolicy::new("certificates", true, true, true),
    TablePolicy::new("check_results", true, true, true),
    TablePolicy::new("ci_relationships", true, true, true),
    TablePolicy::new("circuit_breakers", true, true, true),
    TablePolicy::new("compliance_controls", true, true, true),
    TablePolicy::new("compliance_findings", true, true, true),
    TablePolicy::new("compliance_frameworks", true, true, true),
    TablePolicy::new("compliance_reports", true, true, true),
    TablePolicy::new("component_status", true, true, true),
    TablePolicy::new("configuration_item_environment_authority", true, true, true),
    TablePolicy::new("configuration_items", true, true, true),
    TablePolicy::new("connection_health_checks", true, true, true),
    TablePolicy::new("container_requests", true, true, false),
    TablePolicy::new("cost_rates", true, true, true),
    TablePolicy::new("datacenter_readiness_checks", true, true, true),
    TablePolicy::new("decommission_requests", true, true, true),
    TablePolicy::new("dns_records", true, true, true),
    TablePolicy::new("domain_events", true, false, false),
    TablePolicy::new("dr_plans", true, true, true),
    TablePolicy::new("dr_test_runs", true, true, true),
    TablePolicy::new("drift_reports", true, true, true),
    TablePolicy::new("emergency_changes", true, true, true),
    TablePolicy::new("environment_tiers", true, true, true),
    TablePolicy::new("evidence_blobs", true, true, true),
    TablePolicy::new("failure_patterns", true, true, true),
    TablePolicy::new("file_share_recertification_decisions", true, false, false),
    TablePolicy::new("file_share_recertification_evidence", true, false, false),
    TablePolicy::new("file_shares", true, true, true),
    TablePolicy::new("firewall_rule_sets", true, true, true),
    TablePolicy::new("firewall_rules", true, true, true),
    TablePolicy::new("firmware_exceptions", true, true, false),
    TablePolicy::new("firmware_history", true, true, true),
    TablePolicy::new("firmware_records", true, true, false),
    TablePolicy::new("gmsa_accounts", true, true, false),
    TablePolicy::new("gmsa_host_assignments", true, true, true),
    TablePolicy::new("golden_image_scheduler_population", true, true, true),
    TablePolicy::new("golden_images", true, true, true),
    TablePolicy::new("hardware_assets", true, true, true),
    TablePolicy::new("health_checks", true, true, true),
    TablePolicy::new("human_authority_assignments", true, true, false),
    TablePolicy::new("idempotency_records", true, true, true),
    TablePolicy::new("identity_authorities", true, true, false),
    TablePolicy::new("immutability_checks", true, true, true),
    TablePolicy::new("inbound_webhook_receipts", true, true, true),
    TablePolicy::new("incident_contexts", true, true, true),
    TablePolicy::new("integration_connections", true, true, true),
    TablePolicy::new("integration_secrets", true, true, true),
    TablePolicy::new("ip_reservations", true, true, true),
    TablePolicy::new("ipam_subnets", true, true, true),
    TablePolicy::new("job_executions", true, true, true),
    TablePolicy::new("job_steps", true, true, false),
    TablePolicy::new("k8s_cluster_environment_scopes", false, false, false),
    TablePolicy::new("k8s_cluster_registry", false, false, false),
    TablePolicy::new("k8s_namespaces", true, true, false),
    TablePolicy::new("lb_pool_members", true, true, true),
    TablePolicy::new("lb_pools", true, true, true),
    TablePolicy::new("lb_requests", true, true, true),
    TablePolicy::new("lb_virtual_servers", true, true, true),
    TablePolicy::new("legal_holds", true, true, true),
    TablePolicy::new("linux_deployment_requests", true, true, true),
    TablePolicy::new("linux_distro_catalog", true, true, true),
    TablePolicy::new("log_forwarders", true, true, true),
    TablePolicy::new("maintenance_windows", true, true, true),
    TablePolicy::new("managed_secret_scheduler_population", true, true, true),
    TablePolicy::new("managed_secrets", true, true, true),
    TablePolicy::new("metric_budgets", true, true, true),
    TablePolicy::new("metric_samples", true, true, true),
    TablePolicy::new("monitoring_review_queue", true, true, true),
    TablePolicy::new("noisy_trigger_site_authority", false, false, false),
    TablePolicy::new("noisy_triggers", true, true, true),
    TablePolicy::new("notification_dispatch_outbox", true, true, true),
    TablePolicy::new("ntfs_permissions", true, true, true),
    TablePolicy::new("oidc_login_states", true, true, true),
    TablePolicy::new("on_call_contacts", true, true, true),
    TablePolicy::new("oob_endpoints", true, true, true),
    TablePolicy::new("outage_notice_acknowledgments", true, true, true),
    TablePolicy::new("outage_notice_systems", true, true, true),
    TablePolicy::new("outage_notices", true, true, true),
    TablePolicy::new("patch_wave_servers", true, true, true),
    TablePolicy::new("patch_waves", true, true, true),
    TablePolicy::new("platform_config", true, true, true),
    TablePolicy::new("port_reservations", true, true, true),
    TablePolicy::new("portal_notification_reads", true, true, true),
    TablePolicy::new("portal_notifications", true, true, true),
    TablePolicy::new("quarantine_log", true, true, true),
    TablePolicy::new("recertification_campaigns", true, true, true),
    TablePolicy::new("request_approval_decisions", true, false, false),
    TablePolicy::new("requests", true, true, true),
    TablePolicy::new("restore_requests", true, true, true),
    TablePolicy::new("restore_scheduler_system_summary", true, true, true),
    TablePolicy::new("rotation_runs", true, true, true),
    TablePolicy::new("route_decisions", true, true, true),
    TablePolicy::new("runbook_executions", true, true, true),
    TablePolicy::new("scheduler_protocol_versions", false, false, false),
    TablePolicy::new("scheduler_scan_progress", true, true, true),
    TablePolicy::new("schedules", true, true, true),
    TablePolicy::new("servicenow_queue", true, true, true),
    TablePolicy::new("sessions", true, true, false),
    TablePolicy::new("shift_queue", true, true, true),
    TablePolicy::new("shift_queue_scope_reconciliation_reviews", true, true, true),
    TablePolicy::new("site_capacity", true, true, true),
    TablePolicy::new("site_registry", true, true, false),
    TablePolicy::new("site_status", true, true, true),
    TablePolicy::new("slo_definitions", true, true, true),
    TablePolicy::new("snapshots", true, true, true),
    TablePolicy::new("software_deployments", true, true, true),
    TablePolicy::new("sql_deployment_operations", true, true, true),
    TablePolicy::new("sql_deployments", true, true, true),
    TablePolicy::new("storage_arrays", true, true, true),
    TablePolicy::new("storage_requests", true, true, true),
    TablePolicy::new("storage_volumes", true, true, true),
    TablePolicy::new("switch_ports", true, true, true),
    TablePolicy::new("user_preferences", true, true, true),
    TablePolicy::new("vlans", true, true, true),
    TablePolicy::new("vm_day2_operations", true, true, true),
    TablePolicy::new("vm_utilization", true, true, true),
];

pub fn migration_database_url_from_env() -> Result<String, String> {
    let Some(url) = optional_unicode_env("RYUKI_MIGRATION_DATABASE_URL")? else {
        return Err("RYUKI_MIGRATION_DATABASE_URL is required in apply-only mode".into());
    };
    if url.trim().is_empty()
        || url != url.trim()
        || (!url.starts_with("postgres://") && !url.starts_with("postgresql://"))
    {
        return Err(
            "RYUKI_MIGRATION_DATABASE_URL must be a canonical non-empty PostgreSQL connection URL"
                .into(),
        );
    }
    if optional_unicode_env("RYUKI_DATABASE_URL")?.as_deref() == Some(url.as_str()) {
        return Err(
            "apply-only mode requires a migration database identity distinct from RYUKI_DATABASE_URL"
                .into(),
        );
    }
    Ok(url)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationInventory {
    pub embedded_count: usize,
    pub latest_version: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationVerificationError {
    #[error("migration metadata could not be read: {0}")]
    Metadata(#[source] sqlx::Error),
    #[error("migration {0} is partially applied")]
    Dirty(i64),
    #[error("applied migration {0} is not embedded in this image")]
    UnexpectedApplied(i64),
    #[error("applied migration {0} checksum differs from this image")]
    ChecksumMismatch(i64),
    #[error("embedded migrations are not applied: {0:?}")]
    Missing(Vec<i64>),
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationRunError {
    #[error("dedicated migration database connection failed: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("embedded migration execution failed: {0}")]
    Apply(#[source] sqlx::migrate::MigrateError),
    #[error("application database privileges could not be reconciled: {0}")]
    Privileges(#[source] sqlx::Error),
    #[error(transparent)]
    Verify(#[from] MigrationVerificationError),
}

#[cfg(test)]
thread_local! {
    // Each `#[tokio::test]` owns a short-lived runtime on its test thread.
    // Keeping one process-global SQLx pool crosses reactor lifetimes and loses
    // pool permits after a few tests. A thread-local owned pool gives every
    // handler-style test a pool registered to its own runtime and drops it with
    // that test thread. Production remains process-global below.
    static TEST_POOL: std::cell::RefCell<Option<Box<PgPool>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrationStatus {
    NotApplied = 0,
    Applied = 1,
    Failed = 2,
}

impl MigrationStatus {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Applied,
            2 => Self::Failed,
            _ => Self::NotApplied,
        }
    }
}

#[cfg(not(test))]
pub fn get_db() -> Option<&'static PgPool> {
    POOL.get().and_then(|o| o.as_ref())
}

#[cfg(test)]
pub fn get_db() -> Option<&'static PgPool> {
    TEST_POOL.with(|slot| {
        let borrowed = slot.borrow();
        let pointer = borrowed.as_deref()? as *const PgPool;
        drop(borrowed);
        // SAFETY: TEST_POOL owns the Box at a stable address until the current
        // Rust test thread exits. API tests use current-thread Tokio runtimes;
        // references are consumed within that test. Detached work clones PgPool
        // before spawning, so it does not retain this borrowed handle.
        Some(unsafe { &*pointer })
    })
}

pub fn migration_status() -> MigrationStatus {
    MigrationStatus::from_u8(MIGRATION_STATUS.load(Ordering::Acquire))
}

fn set_migration_status(status: MigrationStatus) {
    MIGRATION_STATUS.store(status as u8, Ordering::Release);
}

pub struct PoolMetrics {
    pub connected: bool,
    pub size: usize,
    pub idle: usize,
    pub active: usize,
}

/// Build a platform-health board whose database component reflects a REAL
/// connectivity probe when a pool is configured.
///
/// `health_monitor::run_all_checks()` is a simulated, always-healthy board: its
/// gauge would report `platform-db = 1` even during a total database outage,
/// silently defeating any alert wired to it. When a pool exists this probes it
/// (`SELECT 1`) and folds the real verdict in, so the gauge and aggregate tell
/// the truth. With no pool it returns the simulated board unchanged, so a
/// deliberate dry-run deployment is not misreported as a database outage.
/// Alerting-safe: a probe that errors reports the database `Unhealthy`.
pub async fn live_platform_health() -> ryuki_engine::health_monitor::PlatformHealth {
    use ryuki_engine::health_monitor;
    let mut health = health_monitor::run_all_checks();
    if let Some(pool) = get_db() {
        // Bound the probe so a /metrics scrape can never hang on a saturated or
        // wedged pool up to the 30s acquire timeout: a database that cannot
        // answer SELECT 1 within a few seconds is itself unhealthy. Alerting-safe
        // — a timeout, a query error, or any non-1 answer all map to Unhealthy,
        // never silently healthy.
        let probe = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool);
        let probe_ok = matches!(
            tokio::time::timeout(Duration::from_secs(3), probe).await,
            Ok(Ok(1))
        );
        health_monitor::override_check(
            &mut health,
            health_monitor::database_health_from_probe(probe_ok),
        );
    }
    health
}

pub fn pool_metrics() -> PoolMetrics {
    match get_db() {
        Some(pool) => {
            let size = pool.size() as usize;
            let idle = pool.num_idle();
            let active = size.saturating_sub(idle);
            PoolMetrics {
                connected: true,
                size,
                idle,
                active,
            }
        }
        None => PoolMetrics {
            connected: false,
            size: 0,
            idle: 0,
            active: 0,
        },
    }
}

#[cfg(test)]
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    EMBEDDED_MIGRATOR.run(pool).await
}

fn expected_embedded_migrations() -> BTreeMap<i64, &'static [u8]> {
    EMBEDDED_MIGRATOR
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .map(|migration| (migration.version, migration.checksum.as_ref()))
        .collect()
}

fn verify_migration_inventory(
    applied: &[(i64, Vec<u8>)],
    dirty_version: Option<i64>,
) -> Result<MigrationInventory, MigrationVerificationError> {
    if let Some(version) = dirty_version {
        return Err(MigrationVerificationError::Dirty(version));
    }

    let expected = expected_embedded_migrations();
    let mut seen = BTreeSet::new();
    for (version, checksum) in applied {
        let Some(expected_checksum) = expected.get(version) else {
            return Err(MigrationVerificationError::UnexpectedApplied(*version));
        };
        if checksum.as_slice() != *expected_checksum {
            return Err(MigrationVerificationError::ChecksumMismatch(*version));
        }
        seen.insert(*version);
    }

    let missing: Vec<i64> = expected
        .keys()
        .filter(|version| !seen.contains(*version))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(MigrationVerificationError::Missing(missing));
    }

    Ok(MigrationInventory {
        embedded_count: expected.len(),
        latest_version: expected.keys().next_back().copied(),
    })
}

/// Read-only verification of the database migration ledger. This deliberately
/// does not call SQLx's `ensure_migrations_table`, `lock`, or `run` methods:
/// the application role may read migration metadata but cannot create schema
/// objects or apply a pending migration in verify-only mode.
async fn verify_embedded_migrations_on_connection(
    connection: &mut PgConnection,
) -> Result<MigrationInventory, MigrationVerificationError> {
    let dirty_version: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM public._sqlx_migrations \
         WHERE success = false ORDER BY version LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(MigrationVerificationError::Metadata)?;
    let applied: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT version, checksum FROM public._sqlx_migrations \
         WHERE success = true ORDER BY version",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(MigrationVerificationError::Metadata)?;
    verify_migration_inventory(&applied, dirty_version)
}

pub async fn verify_embedded_migrations(
    pool: &PgPool,
) -> Result<MigrationInventory, MigrationVerificationError> {
    let result = match pool.acquire().await {
        Ok(mut connection) => verify_embedded_migrations_on_connection(&mut connection).await,
        Err(error) => Err(MigrationVerificationError::Metadata(error)),
    };
    set_migration_status(if result.is_ok() {
        MigrationStatus::Applied
    } else {
        MigrationStatus::Failed
    });
    result
}

fn role_protocol_error(message: impl Into<String>) -> sqlx::Error {
    sqlx::Error::Protocol(message.into())
}

async fn assume_and_attest_database_role(
    connection: &mut PgConnection,
    expected: &str,
    counterpart: &str,
) -> Result<(), sqlx::Error> {
    let admitted: bool = sqlx::query_scalar(
        r#"
        WITH login AS (
            SELECT * FROM pg_catalog.pg_roles WHERE rolname = session_user
        ),
        target AS (
            SELECT * FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        counterpart AS (
            SELECT * FROM pg_catalog.pg_roles WHERE rolname = $2::name
        ),
        direct AS (
            SELECT membership.*
            FROM pg_catalog.pg_auth_members AS membership
            JOIN login ON login.oid = membership.member
            JOIN target ON target.oid = membership.roleid
        )
        SELECT COALESCE((
            SELECT
                current_user = session_user
                AND login.rolcanlogin
                AND NOT login.rolinherit
                AND login.rolvaliduntil IS NOT NULL
                AND login.rolvaliduntil > pg_catalog.statement_timestamp()
                AND login.rolconfig IS NULL
                AND NOT (
                    login.rolsuper OR login.rolcreatedb OR login.rolcreaterole
                    OR login.rolreplication OR login.rolbypassrls
                )
                AND NOT target.rolcanlogin
                AND target.rolinherit
                AND target.rolconnlimit = -1
                AND target.rolvaliduntil IS NULL
                AND target.rolconfig IS NULL
                AND NOT (
                    target.rolsuper OR target.rolcreatedb OR target.rolcreaterole
                    OR target.rolreplication OR target.rolbypassrls
                )
                AND NOT counterpart.rolcanlogin
                AND counterpart.rolinherit
                AND counterpart.rolconnlimit = -1
                AND counterpart.rolvaliduntil IS NULL
                AND counterpart.rolconfig IS NULL
                AND NOT (
                    counterpart.rolsuper OR counterpart.rolcreatedb
                    OR counterpart.rolcreaterole OR counterpart.rolreplication
                    OR counterpart.rolbypassrls
                )
                AND direct.set_option
                AND NOT direct.inherit_option
                AND NOT direct.admin_option
                AND pg_catalog.pg_has_role(login.oid, target.oid, 'MEMBER')
                AND pg_catalog.pg_has_role(login.oid, target.oid, 'SET')
                AND NOT pg_catalog.pg_has_role(login.oid, target.oid, 'USAGE')
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_roles AS other
                    WHERE other.oid <> login.oid
                      AND other.oid <> target.oid
                      AND pg_catalog.pg_has_role(login.oid, other.oid, 'MEMBER')
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_roles AS other
                    WHERE other.oid <> target.oid
                      AND pg_catalog.pg_has_role(target.oid, other.oid, 'MEMBER')
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_roles AS other
                    WHERE other.oid <> counterpart.oid
                      AND pg_catalog.pg_has_role(counterpart.oid, other.oid, 'MEMBER')
                )
            FROM login
            CROSS JOIN target
            CROSS JOIN counterpart
            CROSS JOIN direct
        ), FALSE)
        "#,
    )
    .bind(expected)
    .bind(counterpart)
    .fetch_one(&mut *connection)
    .await?;
    if !admitted {
        return Err(role_protocol_error(
            "database login role failed the exact SET-only membership contract",
        ));
    }

    let selected: String = sqlx::query_scalar("SELECT pg_catalog.set_config('role', $1, false)")
        .bind(expected)
        .fetch_one(&mut *connection)
        .await?;
    if selected != expected {
        return Err(role_protocol_error(
            "database SET ROLE did not select the expected stable role",
        ));
    }

    let search_path: String = sqlx::query_scalar(
        "SELECT pg_catalog.set_config('search_path', 'pg_catalog, public', false)",
    )
    .fetch_one(&mut *connection)
    .await?;
    if search_path != "pg_catalog, public" {
        return Err(role_protocol_error(
            "database connection did not establish the reviewed search_path",
        ));
    }

    let active: bool = sqlx::query_scalar(
        "SELECT current_user = $1::name \
                AND session_user <> current_user \
                AND pg_catalog.current_setting('role') = $1 \
                AND pg_catalog.current_setting('search_path') = 'pg_catalog, public'",
    )
    .bind(expected)
    .fetch_one(&mut *connection)
    .await?;
    if !active {
        return Err(role_protocol_error(
            "database current_user/session_user split identity was not established",
        ));
    }
    Ok(())
}

fn expected_public_table_names() -> BTreeSet<String> {
    APPLICATION_TABLE_POLICIES
        .iter()
        .map(|policy| policy.name.to_owned())
        .chain(std::iter::once("_sqlx_migrations".to_owned()))
        .collect()
}

async fn attest_public_table_inventory(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    let actual: BTreeSet<String> = sqlx::query_scalar(
        "SELECT class.relname::text \
         FROM pg_catalog.pg_class AS class \
         JOIN pg_catalog.pg_namespace AS namespace \
           ON namespace.oid = class.relnamespace \
         WHERE namespace.nspname = 'public' \
           AND class.relkind IN ('r', 'p', 'f') \
         ORDER BY class.relname",
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .collect();
    let expected = expected_public_table_names();
    if expected.len() != APPLICATION_TABLE_POLICIES.len() + 1 {
        return Err(role_protocol_error(
            "application table policy contains a duplicate table name",
        ));
    }
    if actual != expected {
        let missing: Vec<&String> = expected.difference(&actual).collect();
        let unexpected: Vec<&String> = actual.difference(&expected).collect();
        return Err(role_protocol_error(format!(
            "public table inventory differs from the reviewed application policy (missing={missing:?}, unexpected={unexpected:?})"
        )));
    }
    Ok(())
}

async fn attest_application_acl(
    connection: &mut PgConnection,
    application_role: &str,
) -> Result<(), sqlx::Error> {
    attest_public_table_inventory(connection).await?;
    let names: Vec<String> = APPLICATION_TABLE_POLICIES
        .iter()
        .map(|policy| policy.name.to_owned())
        .collect();
    let inserts: Vec<bool> = APPLICATION_TABLE_POLICIES
        .iter()
        .map(|policy| policy.insert)
        .collect();
    let updates: Vec<bool> = APPLICATION_TABLE_POLICIES
        .iter()
        .map(|policy| policy.update)
        .collect();
    let deletes: Vec<bool> = APPLICATION_TABLE_POLICIES
        .iter()
        .map(|policy| policy.delete)
        .collect();
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        login AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user
        ),
        policy AS (
            SELECT *
            FROM unnest($2::text[], $3::boolean[], $4::boolean[], $5::boolean[])
                AS expected(name, can_insert, can_update, can_delete)
        ),
        policy_tables AS (
            SELECT class.oid, policy.*
            FROM policy
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.nspname = 'public'
            JOIN pg_catalog.pg_class AS class
              ON class.relnamespace = namespace.oid
             AND class.relname = policy.name
             AND class.relkind IN ('r', 'p', 'f')
        ),
        ledger AS (
            SELECT class.oid
            FROM pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = class.relnamespace
            WHERE namespace.nspname = 'public'
              AND class.relname = '_sqlx_migrations'
              AND class.relkind IN ('r', 'p')
        )
        SELECT COALESCE((
            SELECT
                (SELECT count(*) FROM policy_tables) =
                    (SELECT count(*) FROM policy)
                AND NOT EXISTS (
                    SELECT 1
                    FROM policy_tables AS table_policy
                    WHERE NOT pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'SELECT'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'SELECT WITH GRANT OPTION'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'INSERT'
                          ) IS DISTINCT FROM table_policy.can_insert
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'UPDATE'
                          ) IS DISTINCT FROM table_policy.can_update
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'DELETE'
                          ) IS DISTINCT FROM table_policy.can_delete
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'INSERT WITH GRANT OPTION'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'UPDATE WITH GRANT OPTION'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'DELETE WITH GRANT OPTION'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'TRUNCATE'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'REFERENCES'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'TRIGGER'
                          )
                       OR pg_catalog.has_table_privilege(
                              app.oid, table_policy.oid, 'MAINTAIN'
                          )
                       OR (
                            NOT table_policy.can_insert
                            AND pg_catalog.has_any_column_privilege(
                                app.oid, table_policy.oid, 'INSERT'
                            )
                          )
                       OR (
                            NOT table_policy.can_update
                            AND pg_catalog.has_any_column_privilege(
                                app.oid, table_policy.oid, 'UPDATE'
                            )
                          )
                       OR pg_catalog.has_any_column_privilege(
                              app.oid, table_policy.oid, 'REFERENCES'
                          )
                )
                AND (SELECT count(*) FROM ledger) = 1
                AND NOT EXISTS (
                    SELECT 1
                    FROM ledger
                    WHERE NOT pg_catalog.has_table_privilege(app.oid, ledger.oid, 'SELECT')
                       OR pg_catalog.has_table_privilege(
                              app.oid, ledger.oid, 'SELECT WITH GRANT OPTION'
                          )
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'INSERT')
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'UPDATE')
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'DELETE')
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'TRUNCATE')
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'REFERENCES')
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'TRIGGER')
                       OR pg_catalog.has_table_privilege(app.oid, ledger.oid, 'MAINTAIN')
                       OR pg_catalog.has_any_column_privilege(app.oid, ledger.oid, 'INSERT')
                       OR pg_catalog.has_any_column_privilege(app.oid, ledger.oid, 'UPDATE')
                       OR pg_catalog.has_any_column_privilege(app.oid, ledger.oid, 'REFERENCES')
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    JOIN pg_catalog.pg_attribute AS attribute
                      ON attribute.attrelid = class.oid
                     AND attribute.attnum > 0
                     AND NOT attribute.attisdropped
                    CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
                    WHERE namespace.nspname = 'public'
                      AND class.relkind IN ('r', 'p', 'f')
                      AND acl.grantee IN (0, app.oid, login.oid)
                )
            FROM app
            CROSS JOIN login
        ), FALSE)
        "#,
    )
    .bind(application_role)
    .bind(&names)
    .bind(&inserts)
    .bind(&updates)
    .bind(&deletes)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "application table privileges differ from the reviewed exact policy",
        ));
    }

    let sequences_are_usage_only: bool = sqlx::query_scalar(
        r#"
        WITH app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        )
        SELECT COALESCE((
            SELECT NOT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_class AS class
                JOIN pg_catalog.pg_namespace AS namespace
                  ON namespace.oid = class.relnamespace
                WHERE namespace.nspname = 'public'
                  AND class.relkind = 'S'
                  AND (
                       NOT pg_catalog.has_sequence_privilege(app.oid, class.oid, 'USAGE')
                       OR pg_catalog.has_sequence_privilege(app.oid, class.oid, 'SELECT')
                       OR pg_catalog.has_sequence_privilege(app.oid, class.oid, 'UPDATE')
                       OR pg_catalog.has_sequence_privilege(
                              app.oid, class.oid, 'USAGE WITH GRANT OPTION'
                          )
                  )
            )
            FROM app
        ), FALSE)
        "#,
    )
    .bind(application_role)
    .fetch_one(&mut *connection)
    .await?;
    if !sequences_are_usage_only {
        return Err(role_protocol_error(
            "application sequence privileges are not USAGE-only",
        ));
    }
    Ok(())
}

/// The runtime may directly invoke exactly two reviewed SECURITY DEFINER entry
/// points. Every trigger, validator, and maintenance routine remains
/// owner/trigger-only; PUBLIC, the ephemeral login, and grant options are
/// denied across the complete public routine inventory.
async fn attest_application_routine_acl(
    connection: &mut PgConnection,
    application_role: &str,
) -> Result<(), sqlx::Error> {
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        login AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user
        ),
        expected(signature) AS (
            VALUES
                ('public.reconcile_noisy_trigger_sites(integer)'::text),
                ('public.append_audit_log(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text)'::text)
        ),
        routines AS (
            SELECT procedure.oid,
                   procedure.proowner,
                   procedure.proacl,
                   procedure.prokind,
                   procedure.prosecdef
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname = 'public'
        ),
        allowed AS (
            SELECT routines.*
            FROM expected
            JOIN routines
              ON routines.oid = pg_catalog.to_regprocedure(expected.signature)::oid
        )
        SELECT COALESCE((
            SELECT
                (SELECT count(*) FROM expected) = 2
                AND (SELECT count(*) FROM allowed) = 2
                AND NOT EXISTS (
                    SELECT 1
                    FROM allowed
                    WHERE allowed.prokind <> 'f'
                       OR NOT allowed.prosecdef
                       OR NOT pg_catalog.has_function_privilege(
                              app.oid, allowed.oid, 'EXECUTE'
                          )
                       OR pg_catalog.has_function_privilege(
                              app.oid, allowed.oid, 'EXECUTE WITH GRANT OPTION'
                          )
                       OR pg_catalog.has_function_privilege(
                              login.oid, allowed.oid, 'EXECUTE'
                          )
                       OR NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.aclexplode(
                                COALESCE(
                                    allowed.proacl,
                                    pg_catalog.acldefault('f', allowed.proowner)
                                )
                            ) AS acl
                            WHERE acl.grantee = app.oid
                              AND acl.privilege_type = 'EXECUTE'
                              AND NOT acl.is_grantable
                        )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM routines AS procedure
                    WHERE (
                        pg_catalog.has_function_privilege(
                            app.oid, procedure.oid, 'EXECUTE'
                        )
                        OR pg_catalog.has_function_privilege(
                            login.oid, procedure.oid, 'EXECUTE'
                        )
                    )
                      AND procedure.oid NOT IN (SELECT oid FROM allowed)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM routines AS procedure
                    CROSS JOIN LATERAL pg_catalog.aclexplode(
                        COALESCE(
                            procedure.proacl,
                            pg_catalog.acldefault('f', procedure.proowner)
                        )
                    ) AS acl
                    WHERE acl.privilege_type = 'EXECUTE'
                      AND (
                           acl.grantee = 0
                           OR acl.grantee = login.oid
                           OR (
                               acl.grantee = app.oid
                               AND (
                                   procedure.oid NOT IN (SELECT oid FROM allowed)
                                   OR acl.is_grantable
                               )
                           )
                      )
                )
            FROM app
            CROSS JOIN login
        ), FALSE)
        "#,
    )
    .bind(application_role)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "application routine privileges differ from the two reviewed entry-point policy",
        ));
    }
    Ok(())
}

async fn attest_application_connection(
    connection: &mut PgConnection,
    contract: &ApplicationRoleContract,
) -> Result<(), sqlx::Error> {
    assume_and_attest_database_role(connection, &contract.expected, &contract.forbidden).await?;
    let safe_boundary: bool = sqlx::query_scalar(
        r#"
        WITH app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        login AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user
        ),
        migration AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $2::name
        ),
        database AS (
            SELECT oid, datdba
            FROM pg_catalog.pg_database
            WHERE datname = pg_catalog.current_database()
        ),
        database_owner AS (
            SELECT owner.*
            FROM pg_catalog.pg_roles AS owner
            JOIN database ON database.datdba = owner.oid
        ),
        public_schema AS (
            SELECT oid, nspowner
            FROM pg_catalog.pg_namespace
            WHERE nspname = 'public'
        )
        SELECT COALESCE((
            SELECT
                public_schema.nspowner = migration.oid
                AND database.datdba <> app.oid
                AND database.datdba <> login.oid
                AND database.datdba <> migration.oid
                AND NOT database_owner.rolcanlogin
                AND database_owner.rolinherit
                AND database_owner.rolconnlimit = -1
                AND database_owner.rolvaliduntil IS NULL
                AND database_owner.rolconfig IS NULL
                AND NOT (
                    database_owner.rolsuper OR database_owner.rolcreatedb
                    OR database_owner.rolcreaterole OR database_owner.rolreplication
                    OR database_owner.rolbypassrls
                )
                AND pg_catalog.has_database_privilege(app.oid, database.oid, 'CONNECT')
                AND pg_catalog.has_database_privilege(login.oid, database.oid, 'CONNECT')
                AND pg_catalog.has_database_privilege(migration.oid, database.oid, 'CONNECT')
                AND NOT pg_catalog.has_database_privilege(app.oid, database.oid, 'CREATE')
                AND NOT pg_catalog.has_database_privilege(login.oid, database.oid, 'CREATE')
                AND NOT pg_catalog.has_database_privilege(migration.oid, database.oid, 'CREATE')
                AND NOT pg_catalog.has_database_privilege(app.oid, database.oid, 'TEMPORARY')
                AND NOT pg_catalog.has_database_privilege(login.oid, database.oid, 'TEMPORARY')
                AND NOT pg_catalog.has_database_privilege(
                    migration.oid, database.oid, 'TEMPORARY'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_database AS other_database
                    WHERE other_database.datdba IN (app.oid, login.oid, migration.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_database AS other_database
                    WHERE other_database.oid <> database.oid
                      AND other_database.datallowconn
                      AND (
                           pg_catalog.has_database_privilege(
                               app.oid, other_database.oid, 'CONNECT'
                           )
                           OR pg_catalog.has_database_privilege(
                               app.oid, other_database.oid, 'CREATE'
                           )
                           OR pg_catalog.has_database_privilege(
                               app.oid, other_database.oid, 'TEMPORARY'
                           )
                           OR pg_catalog.has_database_privilege(
                               login.oid, other_database.oid, 'CONNECT'
                           )
                           OR pg_catalog.has_database_privilege(
                               login.oid, other_database.oid, 'CREATE'
                           )
                           OR pg_catalog.has_database_privilege(
                               login.oid, other_database.oid, 'TEMPORARY'
                           )
                           OR pg_catalog.has_database_privilege(
                               migration.oid, other_database.oid, 'CONNECT'
                           )
                           OR pg_catalog.has_database_privilege(
                               migration.oid, other_database.oid, 'CREATE'
                           )
                           OR pg_catalog.has_database_privilege(
                               migration.oid, other_database.oid, 'TEMPORARY'
                           )
                      )
                )
                AND pg_catalog.has_schema_privilege(app.oid, public_schema.oid, 'USAGE')
                AND NOT pg_catalog.has_schema_privilege(app.oid, public_schema.oid, 'CREATE')
                AND pg_catalog.has_schema_privilege(
                    migration.oid, public_schema.oid, 'USAGE'
                )
                AND pg_catalog.has_schema_privilege(
                    migration.oid, public_schema.oid, 'CREATE'
                )
                AND NOT pg_catalog.has_schema_privilege(login.oid, public_schema.oid, 'USAGE')
                AND NOT pg_catalog.has_schema_privilege(login.oid, public_schema.oid, 'CREATE')
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_namespace AS namespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND namespace.nspname <> 'public'
                      AND (
                           namespace.nspowner IN (app.oid, login.oid, migration.oid)
                           OR pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'USAGE')
                           OR pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'CREATE')
                           OR pg_catalog.has_schema_privilege(login.oid, namespace.oid, 'USAGE')
                           OR pg_catalog.has_schema_privilege(login.oid, namespace.oid, 'CREATE')
                           OR pg_catalog.has_schema_privilege(
                               migration.oid, namespace.oid, 'USAGE'
                           )
                           OR pg_catalog.has_schema_privilege(
                               migration.oid, namespace.oid, 'CREATE'
                           )
                      )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname = 'public'
                      AND class.relowner <> migration.oid
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = procedure.pronamespace
                    WHERE namespace.nspname = 'public'
                      AND procedure.proowner <> migration.oid
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_type AS type
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = type.typnamespace
                    WHERE namespace.nspname = 'public'
                      AND type.typowner <> migration.oid
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND class.relowner IN (app.oid, login.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = procedure.pronamespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND procedure.proowner IN (app.oid, login.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_type AS type
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = type.typnamespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND type.typowner IN (app.oid, login.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname = 'public'
                      AND class.relkind IN ('r', 'p', 'f')
                      AND (
                           pg_catalog.has_table_privilege(login.oid, class.oid, 'SELECT')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'INSERT')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'UPDATE')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'DELETE')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'TRUNCATE')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'REFERENCES')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'TRIGGER')
                           OR pg_catalog.has_table_privilege(login.oid, class.oid, 'MAINTAIN')
                           OR pg_catalog.has_any_column_privilege(
                               login.oid, class.oid, 'SELECT'
                           )
                           OR pg_catalog.has_any_column_privilege(
                               login.oid, class.oid, 'INSERT'
                           )
                           OR pg_catalog.has_any_column_privilege(
                               login.oid, class.oid, 'UPDATE'
                           )
                           OR pg_catalog.has_any_column_privilege(
                               login.oid, class.oid, 'REFERENCES'
                           )
                      )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname = 'public'
                      AND class.relkind = 'S'
                      AND (
                           pg_catalog.has_sequence_privilege(login.oid, class.oid, 'USAGE')
                           OR pg_catalog.has_sequence_privilege(login.oid, class.oid, 'SELECT')
                           OR pg_catalog.has_sequence_privilege(login.oid, class.oid, 'UPDATE')
                      )
                )
            FROM app
            CROSS JOIN login
            CROSS JOIN migration
            CROSS JOIN database
            CROSS JOIN database_owner
            CROSS JOIN public_schema
        ), FALSE)
        "#,
    )
    .bind(&contract.expected)
    .bind(&contract.forbidden)
    .fetch_one(&mut *connection)
    .await?;
    if !safe_boundary {
        return Err(role_protocol_error(
            "application database boundary has unexpected ownership, schema, or cross-database authority",
        ));
    }
    attest_safe_default_privileges(connection, &contract.forbidden).await?;
    attest_application_routine_acl(connection, &contract.expected).await?;
    attest_application_acl(connection, &contract.expected).await
}

async fn attest_migration_connection(
    connection: &mut PgConnection,
    contract: &MigrationRoleContract,
) -> Result<(), sqlx::Error> {
    assume_and_attest_database_role(connection, &contract.expected, &contract.application).await?;
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH migration AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        login AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user
        ),
        app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $2::name
        ),
        database AS (
            SELECT oid, datdba
            FROM pg_catalog.pg_database
            WHERE datname = pg_catalog.current_database()
        ),
        database_owner AS (
            SELECT owner.*
            FROM pg_catalog.pg_roles AS owner
            JOIN database ON database.datdba = owner.oid
        ),
        public_schema AS (
            SELECT oid, nspowner
            FROM pg_catalog.pg_namespace
            WHERE nspname = 'public'
        )
        SELECT COALESCE((
            SELECT
                public_schema.nspowner = migration.oid
                AND database.datdba <> migration.oid
                AND database.datdba <> login.oid
                AND database.datdba <> app.oid
                AND NOT database_owner.rolcanlogin
                AND database_owner.rolinherit
                AND database_owner.rolconnlimit = -1
                AND database_owner.rolvaliduntil IS NULL
                AND database_owner.rolconfig IS NULL
                AND NOT (
                    database_owner.rolsuper OR database_owner.rolcreatedb
                    OR database_owner.rolcreaterole OR database_owner.rolreplication
                    OR database_owner.rolbypassrls
                )
                AND pg_catalog.has_database_privilege(migration.oid, database.oid, 'CONNECT')
                AND pg_catalog.has_database_privilege(login.oid, database.oid, 'CONNECT')
                AND pg_catalog.has_database_privilege(app.oid, database.oid, 'CONNECT')
                AND NOT pg_catalog.has_database_privilege(migration.oid, database.oid, 'CREATE')
                AND NOT pg_catalog.has_database_privilege(login.oid, database.oid, 'CREATE')
                AND NOT pg_catalog.has_database_privilege(app.oid, database.oid, 'CREATE')
                AND NOT pg_catalog.has_database_privilege(migration.oid, database.oid, 'TEMPORARY')
                AND NOT pg_catalog.has_database_privilege(login.oid, database.oid, 'TEMPORARY')
                AND NOT pg_catalog.has_database_privilege(app.oid, database.oid, 'TEMPORARY')
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_database AS other_database
                    WHERE other_database.datdba IN (migration.oid, login.oid, app.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_database AS other_database
                    WHERE other_database.oid <> database.oid
                      AND other_database.datallowconn
                      AND (
                           pg_catalog.has_database_privilege(
                               migration.oid, other_database.oid, 'CONNECT'
                           )
                           OR pg_catalog.has_database_privilege(
                               migration.oid, other_database.oid, 'CREATE'
                           )
                           OR pg_catalog.has_database_privilege(
                               migration.oid, other_database.oid, 'TEMPORARY'
                           )
                           OR pg_catalog.has_database_privilege(
                               login.oid, other_database.oid, 'CONNECT'
                           )
                           OR pg_catalog.has_database_privilege(
                               login.oid, other_database.oid, 'CREATE'
                           )
                           OR pg_catalog.has_database_privilege(
                               login.oid, other_database.oid, 'TEMPORARY'
                           )
                           OR pg_catalog.has_database_privilege(
                               app.oid, other_database.oid, 'CONNECT'
                           )
                           OR pg_catalog.has_database_privilege(
                               app.oid, other_database.oid, 'CREATE'
                           )
                           OR pg_catalog.has_database_privilege(
                               app.oid, other_database.oid, 'TEMPORARY'
                           )
                      )
                )
                AND pg_catalog.has_schema_privilege(migration.oid, public_schema.oid, 'USAGE')
                AND pg_catalog.has_schema_privilege(migration.oid, public_schema.oid, 'CREATE')
                AND pg_catalog.has_schema_privilege(app.oid, public_schema.oid, 'USAGE')
                AND NOT pg_catalog.has_schema_privilege(app.oid, public_schema.oid, 'CREATE')
                AND NOT pg_catalog.has_schema_privilege(login.oid, public_schema.oid, 'USAGE')
                AND NOT pg_catalog.has_schema_privilege(login.oid, public_schema.oid, 'CREATE')
                AND pg_catalog.has_language_privilege(migration.oid, 'sql', 'USAGE')
                AND pg_catalog.has_language_privilege(migration.oid, 'plpgsql', 'USAGE')
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_namespace AS namespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND namespace.nspname <> 'public'
                      AND (
                           namespace.nspowner IN (migration.oid, login.oid, app.oid)
                           OR pg_catalog.has_schema_privilege(
                               migration.oid, namespace.oid, 'USAGE'
                           )
                           OR pg_catalog.has_schema_privilege(
                               migration.oid, namespace.oid, 'CREATE'
                           )
                           OR pg_catalog.has_schema_privilege(
                               login.oid, namespace.oid, 'USAGE'
                           )
                           OR pg_catalog.has_schema_privilege(
                               login.oid, namespace.oid, 'CREATE'
                           )
                           OR pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'USAGE')
                           OR pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'CREATE')
                      )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND namespace.nspname <> 'public'
                      AND class.relowner IN (migration.oid, login.oid, app.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = procedure.pronamespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND namespace.nspname <> 'public'
                      AND procedure.proowner IN (migration.oid, login.oid, app.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_type AS type
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = type.typnamespace
                    WHERE namespace.nspname !~ '^pg_'
                      AND namespace.nspname <> 'information_schema'
                      AND namespace.nspname <> 'public'
                      AND type.typowner IN (migration.oid, login.oid, app.oid)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname = 'public'
                      AND class.relowner <> migration.oid
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = procedure.pronamespace
                    WHERE namespace.nspname = 'public'
                      AND procedure.proowner <> migration.oid
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_type AS type
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = type.typnamespace
                    WHERE namespace.nspname = 'public'
                      AND type.typowner <> migration.oid
                )
            FROM migration
            CROSS JOIN login
            CROSS JOIN app
            CROSS JOIN database
            CROSS JOIN database_owner
            CROSS JOIN public_schema
        ), FALSE)
        "#,
    )
    .bind(&contract.expected)
    .bind(&contract.application)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "migration database boundary has unexpected ownership, schema, or cross-database authority",
        ));
    }
    Ok(())
}

async fn build_application_pool_inner(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
    role_contract: Option<ApplicationRoleContract>,
) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .idle_timeout(Duration::from_secs(idle_timeout_secs))
        .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
        .max_lifetime(Duration::from_secs(max_lifetime_secs))
        // Bound application OLTP independently from offline DDL. Migration
        // processes never use this pool.
        .after_connect(move |conn, _meta| {
            let role_contract = role_contract.clone();
            Box::pin(async move {
                use sqlx::Executor;
                conn.execute("SET statement_timeout = '30s'; SET lock_timeout = '10s'")
                    .await?;
                if let Some(contract) = role_contract.as_ref() {
                    attest_application_connection(conn, contract).await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
}

#[cfg(test)]
async fn build_application_pool(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
) -> Result<PgPool, sqlx::Error> {
    build_application_pool_inner(
        url,
        max_connections,
        min_connections,
        idle_timeout_secs,
        acquire_timeout_secs,
        max_lifetime_secs,
        None,
    )
    .await
}

async fn build_migration_pool_inner(
    url: &str,
    timeouts: MigrationTimeouts,
    role_contract: Option<MigrationRoleContract>,
) -> Result<PgPool, sqlx::Error> {
    let statement_timeout = format!("{}s", timeouts.statement_timeout_secs);
    let lock_timeout = format!("{}s", timeouts.lock_timeout_secs);
    PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(
            MIGRATION_CONNECTION_ACQUIRE_TIMEOUT_SECS,
        ))
        .after_connect(move |connection, _meta| {
            let statement_timeout = statement_timeout.clone();
            let lock_timeout = lock_timeout.clone();
            let role_contract = role_contract.clone();
            Box::pin(async move {
                sqlx::query(
                    "SELECT set_config('statement_timeout', $1, false), \
                            set_config('lock_timeout', $2, false)",
                )
                .bind(statement_timeout)
                .bind(lock_timeout)
                .execute(&mut *connection)
                .await?;
                if let Some(contract) = role_contract.as_ref() {
                    attest_migration_connection(connection, contract).await?;

                    // Keep pg_catalog implicit so PostgreSQL resolves built-ins before
                    // caller-writable schemas while leaving `public` as the creation
                    // target for SQLx's unqualified migration ledger table.
                    let search_path: String = sqlx::query_scalar(
                        "SELECT pg_catalog.set_config('search_path', 'public', false)",
                    )
                    .fetch_one(&mut *connection)
                    .await?;
                    if search_path != "public" {
                        return Err(role_protocol_error(
                            "migration connection did not establish the reviewed search_path",
                        ));
                    }
                }
                Ok(())
            })
        })
        .connect(url)
        .await
}

#[cfg(test)]
async fn build_migration_pool(
    url: &str,
    timeouts: MigrationTimeouts,
) -> Result<PgPool, sqlx::Error> {
    build_migration_pool_inner(url, timeouts, None).await
}

fn quoted_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn qualified_policy_tables(policies: &[TablePolicy]) -> String {
    policies
        .iter()
        .map(|policy| format!("public.{}", quoted_identifier(policy.name)))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn attest_safe_default_privileges(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<(), sqlx::Error> {
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH migration AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        public_schema AS (
            SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = 'public'
        ),
        object_types(objtype) AS (
            VALUES
                (CAST('r' AS pg_catalog."char")),
                (CAST('S' AS pg_catalog."char")),
                (CAST('f' AS pg_catalog."char"))
        ),
        effective_defaults AS (
            SELECT object_types.objtype,
                   COALESCE(
                       default_acl.defaclacl,
                       pg_catalog.acldefault(object_types.objtype, migration.oid)
                   ) AS acl
            FROM migration
            CROSS JOIN public_schema
            CROSS JOIN object_types
            LEFT JOIN pg_catalog.pg_default_acl AS default_acl
              ON default_acl.defaclrole = migration.oid
             AND default_acl.defaclnamespace = 0
             AND default_acl.defaclobjtype = object_types.objtype
        )
        SELECT COALESCE((
            SELECT
                (SELECT count(*) FROM effective_defaults) = 3
                AND NOT EXISTS (
                    SELECT 1
                    FROM effective_defaults
                    CROSS JOIN LATERAL pg_catalog.aclexplode(
                        effective_defaults.acl
                    ) AS acl
                    WHERE acl.grantee <> migration.oid
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_default_acl AS default_acl
                    CROSS JOIN LATERAL pg_catalog.aclexplode(
                        default_acl.defaclacl
                    ) AS acl
                    WHERE default_acl.defaclrole = migration.oid
                      AND acl.grantee <> migration.oid
                )
            FROM migration
        ), FALSE)
        "#,
    )
    .bind(migration_role)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "migration role default privileges are not owner-only and fail-closed",
        ));
    }
    Ok(())
}

async fn reconcile_application_privileges(
    pool: &PgPool,
    contract: &MigrationRoleContract,
) -> Result<(), sqlx::Error> {
    {
        let mut connection = pool.acquire().await?;
        attest_public_table_inventory(&mut connection).await?;
    }

    let app = quoted_identifier(&contract.application);
    let migration = quoted_identifier(&contract.expected);
    let mut groups: BTreeMap<(bool, bool, bool), Vec<TablePolicy>> = BTreeMap::new();
    for policy in APPLICATION_TABLE_POLICIES {
        groups
            .entry((policy.insert, policy.update, policy.delete))
            .or_default()
            .push(*policy);
    }
    let public_routines: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT CASE WHEN procedure.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
               pg_catalog.format(
                   '%I.%I(%s)',
                   namespace.nspname,
                   procedure.proname,
                   pg_catalog.pg_get_function_identity_arguments(procedure.oid)
               )
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'public'
        ORDER BY procedure.oid
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut transaction = pool.begin().await?;
    for statement in [
        format!("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, {app}"),
        format!("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, {app}"),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration} \
             REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, {app}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration} \
             REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, {app}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration} \
             REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, {app}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public \
             REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, {app}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public \
             REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, {app}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public \
             REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, {app}"
        ),
    ] {
        sqlx::query(&statement).execute(&mut *transaction).await?;
    }

    // Trigger and validation functions are invoked by PostgreSQL and do not
    // need caller EXECUTE. Deny every direct public routine call, then add back
    // the two reviewed bounded entry points below.
    for (object_kind, signature) in public_routines {
        let statement =
            format!("REVOKE ALL PRIVILEGES ON {object_kind} {signature} FROM PUBLIC, {app}");
        sqlx::query(&statement).execute(&mut *transaction).await?;
    }

    let column_acl_tables: Vec<(String, Vec<String>)> = sqlx::query_as(
        r#"
        WITH app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        )
        SELECT class.relname::text,
               pg_catalog.array_agg(attribute.attname::text ORDER BY attribute.attnum)
        FROM pg_catalog.pg_class AS class
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = class.relnamespace
        JOIN pg_catalog.pg_attribute AS attribute
          ON attribute.attrelid = class.oid
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped
        WHERE namespace.nspname = 'public'
          AND class.relkind IN ('r', 'p', 'f')
          AND EXISTS (
              SELECT 1
              FROM pg_catalog.aclexplode(attribute.attacl) AS acl
              WHERE acl.grantee IN (0, (SELECT oid FROM app))
          )
        GROUP BY class.oid, class.relname
        ORDER BY class.oid
        "#,
    )
    .bind(&contract.application)
    .fetch_all(&mut *transaction)
    .await?;
    for (table, columns) in column_acl_tables {
        let columns = columns
            .iter()
            .map(|column| quoted_identifier(column))
            .collect::<Vec<_>>()
            .join(", ");
        let statement = format!(
            "REVOKE ALL PRIVILEGES ({columns}) ON TABLE public.{} FROM PUBLIC, {app}",
            quoted_identifier(&table),
        );
        sqlx::query(&statement).execute(&mut *transaction).await?;
    }

    for ((insert, update, delete), policies) in groups {
        let mut privileges = vec!["SELECT"];
        if insert {
            privileges.push("INSERT");
        }
        if update {
            privileges.push("UPDATE");
        }
        if delete {
            privileges.push("DELETE");
        }
        let statement = format!(
            "GRANT {} ON TABLE {} TO {app}",
            privileges.join(", "),
            qualified_policy_tables(&policies),
        );
        sqlx::query(&statement).execute(&mut *transaction).await?;
    }
    sqlx::query(&format!(
        "GRANT SELECT ON TABLE public._sqlx_migrations TO {app}"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(&format!(
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {app}"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION public.reconcile_noisy_trigger_sites(integer) TO {app}"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION \
         public.append_audit_log(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text) \
         TO {app}"
    ))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let mut connection = pool.acquire().await?;
    // `after_connect` already selected the stable migrator role on this
    // physical connection. Re-establish the authenticated login identity
    // before replaying the exact membership attestation; otherwise the
    // intentional `current_user = session_user` precondition fails on a safe
    // pooled connection after migration work.
    sqlx::query("RESET ROLE").execute(&mut *connection).await?;
    attest_migration_connection(&mut connection, contract).await?;
    attest_safe_default_privileges(&mut connection, &contract.expected).await?;
    attest_application_routine_acl(&mut connection, &contract.application).await?;
    attest_application_acl(&mut connection, &contract.application).await
}

/// Apply and immediately read back the exact embedded inventory through one
/// isolated, one-connection pool. The pool is closed before returning, so the
/// migration identity and its longer DDL timeouts cannot leak into serving
/// requests or background jobs.
async fn apply_embedded_migrations_inner(
    url: &str,
    timeouts: MigrationTimeouts,
    role_contract: Option<MigrationRoleContract>,
) -> Result<MigrationInventory, MigrationRunError> {
    let result = async {
        let pool = build_migration_pool_inner(url, timeouts, role_contract.clone())
            .await
            .map_err(MigrationRunError::Connect)?;
        if let Err(error) = EMBEDDED_MIGRATOR.run(&pool).await {
            pool.close().await;
            return Err(MigrationRunError::Apply(error));
        }
        if let Some(contract) = role_contract.as_ref() {
            if let Err(error) = reconcile_application_privileges(&pool, contract).await {
                pool.close().await;
                return Err(MigrationRunError::Privileges(error));
            }
        }
        let verification = verify_embedded_migrations(&pool)
            .await
            .map_err(MigrationRunError::Verify);
        pool.close().await;
        verification
    }
    .await;
    set_migration_status(if result.is_ok() {
        MigrationStatus::Applied
    } else {
        MigrationStatus::Failed
    });
    result
}

pub async fn apply_embedded_migrations(
    url: &str,
    timeouts: MigrationTimeouts,
) -> Result<MigrationInventory, MigrationRunError> {
    apply_embedded_migrations_inner(url, timeouts, None).await
}

pub async fn apply_embedded_migrations_with_role_contract(
    url: &str,
    timeouts: MigrationTimeouts,
    role_contract: MigrationRoleContract,
) -> Result<MigrationInventory, MigrationRunError> {
    apply_embedded_migrations_inner(url, timeouts, Some(role_contract)).await
}

/// Whether a failed database connection is fatal instead of falling back to
/// in-memory stores (RYUKI_DATABASE__REQUIRED / database.required). Loaded
/// directly from configuration on the failure path so this module does not
/// depend on process startup order; only consulted when connecting fails.
fn database_required() -> bool {
    match ryuki_core::config::RyukiConfig::load() {
        Ok(config) => config.database.required,
        // A malformed unrelated env var must not fail this flag open into the
        // silent in-memory fallback it exists to prevent: read the raw env
        // value directly when full config parsing is unavailable.
        Err(_) => std::env::var("RYUKI_DATABASE__REQUIRED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false),
    }
}

async fn try_connect_with_url_inner(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
    role_contract: Option<ApplicationRoleContract>,
) {
    // Production is process-global; tests are runtime/thread-local because each
    // `#[tokio::test]` drops its reactor after the test.
    if get_db().is_some() {
        return;
    }
    let connected = build_application_pool_inner(
        url,
        max_connections,
        min_connections,
        idle_timeout_secs,
        acquire_timeout_secs,
        max_lifetime_secs,
        role_contract,
    )
    .await;

    let pool = match connected {
        Ok(pool) => {
            tracing::info!("database connected");
            Some(pool)
        }
        Err(e) => {
            if database_required() {
                tracing::error!(
                    "database unavailable and database.required is true; refusing in-memory fallback: {e}"
                );
                std::process::exit(1);
            }
            tracing::warn!("database unavailable, falling back to in-memory stores: {e}");
            None
        }
    };
    #[cfg(not(test))]
    POOL.set(pool).ok();
    #[cfg(test)]
    TEST_POOL.with(|slot| {
        *slot.borrow_mut() = pool.map(Box::new);
    });
}

pub async fn try_connect_with_url(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
) {
    try_connect_with_url_inner(
        url,
        max_connections,
        min_connections,
        idle_timeout_secs,
        acquire_timeout_secs,
        max_lifetime_secs,
        None,
    )
    .await;
}

pub async fn try_connect_with_role_contract(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
    role_contract: ApplicationRoleContract,
) {
    try_connect_with_url_inner(
        url,
        max_connections,
        min_connections,
        idle_timeout_secs,
        acquire_timeout_secs,
        max_lifetime_secs,
        Some(role_contract),
    )
    .await;
}

pub async fn migrate_if_connected(
    url: &str,
    timeouts: MigrationTimeouts,
) -> Result<MigrationStatus, MigrationRunError> {
    if get_db().is_none() {
        set_migration_status(MigrationStatus::NotApplied);
        return Ok(MigrationStatus::NotApplied);
    }

    match apply_embedded_migrations(url, timeouts).await {
        Ok(inventory) => {
            tracing::info!(
                embedded_count = inventory.embedded_count,
                latest_version = ?inventory.latest_version,
                "database migrations applied and read back through dedicated runner"
            );
            Ok(MigrationStatus::Applied)
        }
        Err(error) => {
            tracing::error!(%error, "database migration failed in dedicated runner");
            Err(error)
        }
    }
}

#[cfg(test)]
pub fn set_migration_status_for_test(status: MigrationStatus) {
    set_migration_status(status);
}

/// Process-wide serialization guard for DB-touching integration tests. All
/// tests that connect to and query the live Postgres (the migrations check in
/// `main::db_tests` and the lifecycle/logout/token tests in
/// `contracts::db_lifecycle_tests`) acquire this so they run mutually
/// exclusive — otherwise the shared, small connection pools are exhausted and
/// queries `PoolTimedOut` under `cargo test`'s parallel scheduling.
#[cfg(test)]
pub static DB_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::{
        build_application_pool, build_migration_pool, expected_embedded_migrations, get_db,
        live_platform_health, migration_status, set_migration_status_for_test,
        try_connect_with_url, verify_embedded_migrations_on_connection, verify_migration_inventory,
        MigrationStartupMode, MigrationStatus, MigrationTimeouts, MigrationVerificationError,
        DB_TEST_SERIAL,
    };
    use ryuki_engine::health_monitor::{HealthSource, HealthStatus};
    use sqlx::{Connection, PgConnection};

    #[test]
    fn migration_mode_is_explicit_and_rejects_unknown_values() {
        let missing = super::migration_startup_mode_from_value(None).unwrap_err();
        assert!(missing.contains("RYUKI_MIGRATION_MODE is required"));
        assert_eq!("local-auto".parse(), Ok(MigrationStartupMode::LocalAuto));
        assert_eq!("apply-only".parse(), Ok(MigrationStartupMode::ApplyOnly));
        assert_eq!("verify-only".parse(), Ok(MigrationStartupMode::VerifyOnly));
        let error = "auto".parse::<MigrationStartupMode>().unwrap_err();
        assert!(error.contains("local-auto, apply-only, verify-only"));
    }

    #[test]
    fn apply_only_mode_can_never_continue_to_http_serving() {
        assert!(!MigrationStartupMode::ApplyOnly.serves_http());
        assert!(MigrationStartupMode::LocalAuto.serves_http());
        assert!(MigrationStartupMode::VerifyOnly.serves_http());

        for mode in [
            MigrationStartupMode::LocalAuto,
            MigrationStartupMode::ApplyOnly,
            MigrationStartupMode::VerifyOnly,
        ] {
            for status in [
                MigrationStatus::NotApplied,
                MigrationStatus::Applied,
                MigrationStatus::Failed,
            ] {
                for pool_present in [false, true] {
                    let expected = matches!(
                        (mode, status, pool_present),
                        (
                            MigrationStartupMode::LocalAuto,
                            MigrationStatus::NotApplied,
                            false
                        ) | (
                            MigrationStartupMode::LocalAuto,
                            MigrationStatus::Applied,
                            true
                        ) | (
                            MigrationStartupMode::VerifyOnly,
                            MigrationStatus::Applied,
                            true
                        )
                    );
                    assert_eq!(
                        mode.permits_serving_with(status, pool_present),
                        expected,
                        "unexpected startup gate for mode={mode}, status={status:?}, pool_present={pool_present}"
                    );
                }
            }
        }
    }

    #[test]
    fn migration_timeout_parsing_is_bounded_and_keeps_lock_timeout_shorter() {
        assert_eq!(
            MigrationTimeouts::from_values(None, None).unwrap(),
            MigrationTimeouts::default()
        );
        assert_eq!(
            MigrationTimeouts::from_values(Some("3600"), Some("120")).unwrap(),
            MigrationTimeouts {
                statement_timeout_secs: 3_600,
                lock_timeout_secs: 120,
            }
        );
        for (statement, lock) in [
            (Some("59"), Some("1")),
            (Some("7201"), Some("1")),
            (Some("1800"), Some("0")),
            (Some("1800"), Some("301")),
            (Some("60"), Some("60")),
            (Some("not-a-number"), Some("1")),
        ] {
            assert!(MigrationTimeouts::from_values(statement, lock).is_err());
        }
    }

    #[test]
    fn production_role_names_and_protected_table_policies_fail_closed() {
        assert!(super::ApplicationRoleContract::from_values(
            "ryuki_app_runtime".into(),
            "ryuki_schema_migrator".into(),
        )
        .is_ok());
        for invalid in ["", "Ryuki_app", "app-role", "9app", "app role"] {
            assert!(super::canonical_database_role_name("TEST_ROLE", invalid.into()).is_err());
        }
        assert!(super::ApplicationRoleContract::from_values(
            "ryuki_app_runtime".into(),
            "ryuki_app_runtime".into(),
        )
        .is_err());

        let policies: std::collections::BTreeMap<_, _> = super::APPLICATION_TABLE_POLICIES
            .iter()
            .map(|policy| (policy.name, (policy.insert, policy.update, policy.delete)))
            .collect();
        assert_eq!(policies.len(), super::APPLICATION_TABLE_POLICIES.len());
        for name in [
            "ad_computers",
            "gmsa_accounts",
            "container_requests",
            "k8s_namespaces",
        ] {
            assert_eq!(policies.get(name), Some(&(true, true, false)));
        }
        assert_eq!(
            policies.get("gmsa_host_assignments"),
            Some(&(true, true, true))
        );
        for name in [
            "audit_log",
            "certificate_site_authority_quarantine",
            "k8s_cluster_registry",
            "k8s_cluster_environment_scopes",
            "noisy_trigger_site_authority",
            "scheduler_protocol_versions",
        ] {
            assert_eq!(policies.get(name), Some(&(false, false, false)));
        }
    }

    #[test]
    fn verify_only_inventory_rejects_missing_dirty_modified_and_unexpected_rows() {
        let expected = expected_embedded_migrations();
        assert!(
            !expected.is_empty(),
            "the embedded inventory must not be empty"
        );
        let mut applied: Vec<(i64, Vec<u8>)> = expected
            .iter()
            .map(|(version, checksum)| (*version, checksum.to_vec()))
            .collect();
        let latest = *expected.keys().next_back().unwrap();
        let complete = verify_migration_inventory(&applied, None).unwrap();
        assert_eq!(complete.embedded_count, expected.len());
        assert_eq!(complete.latest_version, Some(latest));

        applied.pop();
        assert!(matches!(
            verify_migration_inventory(&applied, None),
            Err(MigrationVerificationError::Missing(versions)) if versions == vec![latest]
        ));

        let mut complete_rows: Vec<(i64, Vec<u8>)> = expected
            .iter()
            .map(|(version, checksum)| (*version, checksum.to_vec()))
            .collect();
        assert!(matches!(
            verify_migration_inventory(&complete_rows, Some(latest)),
            Err(MigrationVerificationError::Dirty(version)) if version == latest
        ));

        complete_rows[0].1[0] ^= 0xff;
        assert!(matches!(
            verify_migration_inventory(&complete_rows, None),
            Err(MigrationVerificationError::ChecksumMismatch(_))
        ));

        let mut unexpected: Vec<(i64, Vec<u8>)> = expected
            .iter()
            .map(|(version, checksum)| (*version, checksum.to_vec()))
            .collect();
        unexpected.push((i64::MAX, vec![0; 48]));
        assert!(matches!(
            verify_migration_inventory(&unexpected, None),
            Err(MigrationVerificationError::UnexpectedApplied(i64::MAX))
        ));
    }

    /// #12: every pooled connection must carry the per-statement timeout set in
    /// `after_connect`, so a runaway query aborts at the DB instead of pinning a
    /// connection until the request timeout fires.
    #[tokio::test]
    async fn statement_timeout_is_set_on_pool_connections() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        try_connect_with_url(&url, 2, 1, 300, 30, 1800).await;
        let pool = get_db().expect("pool must be connected");
        let stmt: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(pool)
            .await
            .expect("SHOW statement_timeout");
        assert_eq!(
            stmt, "30s",
            "every pooled connection must carry the 30s statement_timeout from after_connect"
        );
        let lock: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(pool)
            .await
            .expect("SHOW lock_timeout");
        assert_eq!(
            lock, "10s",
            "every pooled connection must carry the 10s lock_timeout from after_connect"
        );
    }

    #[tokio::test]
    async fn migration_pool_timeouts_are_isolated_from_application_connections() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let application = build_application_pool(&url, 1, 0, 300, 30, 1_800)
            .await
            .expect("application pool");
        let migration = build_migration_pool(&url, MigrationTimeouts::default())
            .await
            .expect("migration pool");

        for (pool, statement_secs, lock_secs) in [
            (&application, 30_i64, 10_i64),
            (
                &migration,
                MigrationTimeouts::default().statement_timeout_secs as i64,
                MigrationTimeouts::default().lock_timeout_secs as i64,
            ),
        ] {
            let observed: (i64, i64) = sqlx::query_as(
                "SELECT \
                    EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval)::bigint, \
                    EXTRACT(EPOCH FROM current_setting('lock_timeout')::interval)::bigint",
            )
            .fetch_one(pool)
            .await
            .expect("read connection timeouts");
            assert_eq!(
                observed,
                (statement_secs, lock_secs),
                "pool carries the wrong timeout class"
            );
        }

        application.close().await;
        migration.close().await;
    }

    /// Integration fixture for a disposable PostgreSQL 18 database that has
    /// already received the CNPG-equivalent stable-role/bootstrap handoff and
    /// two short-lived SET-only login credentials. The test deliberately does
    /// not create or alter cluster roles, so it can never broaden a developer's
    /// ordinary local database principal. It skips unless both dedicated URLs
    /// are supplied by an isolated CI fixture.
    #[tokio::test]
    async fn strict_role_postflight_denies_schema_ledger_sequence_and_internal_definer_paths() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(migration_url) = std::env::var("RYUKI_DISPOSABLE_STRICT_MIGRATION_DATABASE_URL")
        else {
            eprintln!("SKIP: disposable strict migration database URL not set");
            return;
        };
        let Ok(application_url) = std::env::var("RYUKI_DISPOSABLE_STRICT_APPLICATION_DATABASE_URL")
        else {
            eprintln!("SKIP: disposable strict application database URL not set");
            return;
        };

        let migration_contract = super::MigrationRoleContract::from_values(
            "ryuki_schema_migrator".into(),
            "ryuki_app_runtime".into(),
        )
        .expect("valid migration role fixture");
        super::apply_embedded_migrations_with_role_contract(
            &migration_url,
            MigrationTimeouts::default(),
            migration_contract,
        )
        .await
        .expect("strict migration postflight must reconcile and attest privileges");

        let application_contract = super::ApplicationRoleContract::from_values(
            "ryuki_app_runtime".into(),
            "ryuki_schema_migrator".into(),
        )
        .expect("valid application role fixture");
        let pool = super::build_application_pool_inner(
            &application_url,
            1,
            1,
            60,
            30,
            300,
            Some(application_contract),
        )
        .await
        .expect("every strict application connection must pass post-connect attestation");

        let identity: (String, String) =
            sqlx::query_as("SELECT current_user::text, session_user::text")
                .fetch_one(&pool)
                .await
                .expect("read strict split identity");
        assert_eq!(identity.0, "ryuki_app_runtime");
        assert_ne!(identity.0, identity.1);

        let callable_public_routines: Vec<String> = sqlx::query_scalar(
            "SELECT procedure.proname::text \
             FROM pg_catalog.pg_proc AS procedure \
             JOIN pg_catalog.pg_namespace AS namespace \
               ON namespace.oid = procedure.pronamespace \
             WHERE namespace.nspname = 'public' \
               AND pg_catalog.has_function_privilege( \
                   current_user, procedure.oid, 'EXECUTE' \
               ) \
             ORDER BY procedure.proname",
        )
        .fetch_all(&pool)
        .await
        .expect("read exact callable routine surface");
        assert_eq!(
            callable_public_routines,
            vec![
                "append_audit_log".to_owned(),
                "reconcile_noisy_trigger_sites".to_owned(),
            ]
        );

        for forbidden_sql in [
            "UPDATE public._sqlx_migrations SET success = success WHERE false",
            "UPDATE public.noisy_trigger_site_authority SET updated_at = updated_at WHERE false",
            "CREATE TABLE public.__ryuki_runtime_ddl_must_fail (id integer)",
            "SELECT public.queue_noisy_trigger_site_reconciliation()",
            "SELECT pg_catalog.set_config('role', 'ryuki_schema_migrator', false)",
        ] {
            assert!(
                sqlx::query(forbidden_sql).execute(&pool).await.is_err(),
                "strict runtime unexpectedly executed {forbidden_sql}"
            );
        }

        let sequence: String = sqlx::query_scalar(
            "SELECT pg_catalog.format('%I.%I', namespace.nspname, class.relname) \
             FROM pg_catalog.pg_class AS class \
             JOIN pg_catalog.pg_namespace AS namespace \
               ON namespace.oid = class.relnamespace \
             WHERE namespace.nspname = 'public' AND class.relkind = 'S' \
             ORDER BY class.oid LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("embedded inventory must contain a sequence");
        assert!(
            sqlx::query("SELECT pg_catalog.setval($1::pg_catalog.regclass, 1, false)")
                .bind(sequence)
                .execute(&pool)
                .await
                .is_err(),
            "USAGE-only sequence policy must deny setval"
        );

        let repaired: i32 = sqlx::query_scalar("SELECT public.reconcile_noisy_trigger_sites(1)")
            .fetch_one(&pool)
            .await
            .expect("the sole reviewed SECURITY DEFINER routine must remain executable");
        assert!((0..=1).contains(&repaired));
        pool.close().await;
    }

    #[tokio::test]
    async fn verify_only_reader_ignores_a_temporary_shadow_ledger() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let mut connection = PgConnection::connect(&url)
            .await
            .expect("connect migration verification test");
        super::EMBEDDED_MIGRATOR
            .run(&mut connection)
            .await
            .expect("apply public migration inventory");
        // A hostile temp ledger must never shadow the schema-qualified public
        // ledger used by the verify-only reader.
        sqlx::query(
            "CREATE TEMP TABLE _sqlx_migrations (\
                version BIGINT PRIMARY KEY, \
                success BOOLEAN NOT NULL, \
                checksum BYTEA NOT NULL\
             )",
        )
        .execute(&mut connection)
        .await
        .expect("create isolated migration ledger");

        let expected = expected_embedded_migrations();
        let latest = *expected.keys().next_back().expect("embedded migrations");
        sqlx::query(
            "INSERT INTO _sqlx_migrations(version, success, checksum) VALUES ($1, false, $2)",
        )
        .bind(latest)
        .bind(
            expected
                .get(&latest)
                .copied()
                .expect("latest embedded checksum"),
        )
        .execute(&mut connection)
        .await
        .expect("seed dirty migration row");
        let inventory = verify_embedded_migrations_on_connection(&mut connection)
            .await
            .expect("temporary ledger must not shadow public._sqlx_migrations");
        assert_eq!(inventory.embedded_count, expected.len());
        assert_eq!(inventory.latest_version, Some(latest));
        sqlx::query("DROP TABLE _sqlx_migrations")
            .execute(&mut connection)
            .await
            .expect("drop isolated migration ledger");
    }

    #[test]
    fn handler_pool_reconnects_on_each_short_lived_test_thread() {
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let lock_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build DB-test serialization runtime");
        let serial = lock_runtime.block_on(DB_TEST_SERIAL.lock());

        for sequence in 1..=2 {
            let url = url.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build short-lived test runtime");
                runtime.block_on(async {
                    try_connect_with_url(&url, 2, 1, 300, 30, 1800).await;
                    let one: i32 = sqlx::query_scalar("SELECT 1")
                        .fetch_one(get_db().expect("thread-local handler pool connected"))
                        .await
                        .unwrap_or_else(|error| panic!("query on test thread {sequence}: {error}"));
                    assert_eq!(one, 1);
                });
            })
            .join()
            .unwrap_or_else(|_| panic!("test thread {sequence} panicked"));
        }
        drop(serial);
    }

    #[test]
    fn migration_status_tracks_updates() {
        set_migration_status_for_test(MigrationStatus::NotApplied);
        assert_eq!(migration_status(), MigrationStatus::NotApplied);

        set_migration_status_for_test(MigrationStatus::Applied);
        assert_eq!(migration_status(), MigrationStatus::Applied);

        set_migration_status_for_test(MigrationStatus::Failed);
        assert_eq!(migration_status(), MigrationStatus::Failed);
    }

    #[tokio::test]
    async fn live_platform_health_leaves_db_simulated_without_a_pool() {
        // No pool configured => a deliberate dry-run deployment. The board must
        // NOT be flipped to a database outage: the db component stays the
        // simulated placeholder, so we never page on an intentionally-absent DB.
        // (Skips if some other test in this binary already initialized the pool.)
        if get_db().is_some() {
            eprintln!("SKIP: a database pool is configured in this test binary");
            return;
        }
        let health = live_platform_health().await;
        let db = health
            .checks
            .iter()
            .find(|c| c.component == "platform-db")
            .expect("platform-db check present");
        assert_eq!(db.source, HealthSource::Simulated);
        assert_eq!(db.status, HealthStatus::Healthy);
    }
}
