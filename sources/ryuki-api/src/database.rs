use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::env::VarError;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[cfg(not(test))]
static POOL: OnceLock<Option<Arc<PgPool>>> = OnceLock::new();
static MIGRATION_STATUS: AtomicU8 = AtomicU8::new(MigrationStatus::NotApplied as u8);
static PRODUCTION_DATABASE_CONSTRUCTION_CLAIMED: AtomicBool = AtomicBool::new(false);

const REQUIRED_PRODUCTION_POSTGRESQL_MAJOR_VERSION: u16 = 18;

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

/// Receipt-derived stable roles required by the production PostgreSQL
/// boundary. The constructor accepts already authenticated, typed expectation
/// fields; production observation never discovers role authority from ambient
/// environment variables.
#[derive(Clone, PartialEq, Eq)]
pub struct ProductionDatabaseRoles {
    application_role: String,
    migration_role: String,
}

impl fmt::Debug for ProductionDatabaseRoles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionDatabaseRoles")
            .field("application_role_present", &true)
            .field("migration_role_present", &true)
            .finish()
    }
}

impl ProductionDatabaseRoles {
    pub fn new(application_role: String, migration_role: String) -> Result<Self, String> {
        let application_role = canonical_database_role_name("application_role", application_role)?;
        let migration_role = canonical_database_role_name("migration_role", migration_role)?;
        if application_role == "postgres" || migration_role == "postgres" {
            return Err("production database roles must not select the postgres superuser".into());
        }
        if application_role == migration_role {
            return Err("production application_role and migration_role must differ".into());
        }
        Ok(Self {
            application_role,
            migration_role,
        })
    }

    pub fn application_role(&self) -> &str {
        &self.application_role
    }

    pub fn migration_role(&self) -> &str {
        &self.migration_role
    }

    fn application_contract(&self) -> ApplicationRoleContract {
        ApplicationRoleContract {
            expected: self.application_role.clone(),
            forbidden: self.migration_role.clone(),
        }
    }
}

/// Bounded application-pool construction values retained by the unpublished
/// production database seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationPoolSettings {
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
}

impl ApplicationPoolSettings {
    pub fn new(
        max_connections: u32,
        min_connections: u32,
        idle_timeout_secs: u64,
        acquire_timeout_secs: u64,
        max_lifetime_secs: u64,
    ) -> Result<Self, String> {
        if max_connections == 0 {
            return Err("production database max_connections must be greater than zero".into());
        }
        if min_connections > max_connections {
            return Err(
                "production database min_connections must not exceed max_connections".into(),
            );
        }
        for (label, value) in [
            ("idle_timeout_secs", idle_timeout_secs),
            ("acquire_timeout_secs", acquire_timeout_secs),
            ("max_lifetime_secs", max_lifetime_secs),
        ] {
            if value == 0 {
                return Err(format!(
                    "production database {label} must be greater than zero"
                ));
            }
        }
        Ok(Self {
            max_connections,
            min_connections,
            idle_timeout_secs,
            acquire_timeout_secs,
            max_lifetime_secs,
        })
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
    TablePolicy::new("first_owner_closure_records", false, false, false),
    TablePolicy::new(
        "first_owner_privileged_domain_assignments",
        false,
        false,
        false,
    ),
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
    // Request identity and its monotonic resource_version are permanent. The
    // runtime can conclude a request, but cannot delete and later reuse its id.
    TablePolicy::new("requests", true, true, false),
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

/// Exact successful row retained from `public._sqlx_migrations`. Installation
/// timestamps and execution duration are operational metadata; the normative
/// inventory is the strictly ordered version/checksum set embedded in the
/// running image.
#[derive(Debug, PartialEq, Eq)]
pub struct PostgresqlMigrationLedgerRow {
    version: i64,
    checksum: Box<[u8]>,
}

impl PostgresqlMigrationLedgerRow {
    pub fn version(&self) -> i64 {
        self.version
    }

    pub fn checksum(&self) -> &[u8] {
        &self.checksum
    }
}

/// Negotiated TLS facts for the exact PostgreSQL backend session used to
/// measure the runtime. Certificate-chain authority is deployment evidence and
/// is intentionally not inferred from these local SQL-visible facts.
#[derive(PartialEq, Eq)]
pub struct PostgresqlTlsObservation {
    protocol: String,
    cipher: String,
    bits: u16,
    client_distinguished_name: Option<String>,
    issuer_distinguished_name: Option<String>,
}

impl fmt::Debug for PostgresqlTlsObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresqlTlsObservation")
            .field("tls_enabled", &true)
            .finish_non_exhaustive()
    }
}

impl PostgresqlTlsObservation {
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn cipher(&self) -> &str {
        &self.cipher
    }

    pub fn bits(&self) -> u16 {
        self.bits
    }

    pub fn client_distinguished_name(&self) -> Option<&str> {
        self.client_distinguished_name.as_deref()
    }

    pub fn issuer_distinguished_name(&self) -> Option<&str> {
        self.issuer_distinguished_name.as_deref()
    }
}

/// Independently measured, non-secret PostgreSQL facts retained by the local
/// half of the DurablePostgresql witness. This deliberately omits the external
/// durable-storage/provider attestation required to complete that guard. The
/// cluster system identifier belongs to that signed infrastructure evidence:
/// the least-privilege application role must not receive `pg_monitor` or
/// `pg_control_system()` execution authority merely to inspect it locally.
#[derive(PartialEq, Eq)]
pub struct PostgresqlRuntimeObservation {
    server_version_num: u32,
    server_version: String,
    server_major_version: u16,
    database_name: String,
    database_oid: u32,
    server_address: IpAddr,
    server_port: u16,
    primary: bool,
    transaction_writable: bool,
    default_transaction_writable: bool,
    application_role: String,
    migration_role: String,
    session_login_role: String,
    tls: PostgresqlTlsObservation,
    migration_ledger: Box<[PostgresqlMigrationLedgerRow]>,
}

impl fmt::Debug for PostgresqlRuntimeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresqlRuntimeObservation")
            .field("contract", &"local-postgresql-runtime-observation-v1")
            .field("server_major_version", &self.server_major_version)
            .field("primary", &self.primary)
            .field("transaction_writable", &self.transaction_writable)
            .field(
                "default_transaction_writable",
                &self.default_transaction_writable,
            )
            .field("tls_enabled", &true)
            .field("migration_count", &self.migration_ledger.len())
            .finish_non_exhaustive()
    }
}

impl PostgresqlRuntimeObservation {
    pub fn server_version_num(&self) -> u32 {
        self.server_version_num
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn server_major_version(&self) -> u16 {
        self.server_major_version
    }

    pub fn database_name(&self) -> &str {
        &self.database_name
    }

    pub fn database_oid(&self) -> u32 {
        self.database_oid
    }

    pub fn server_address(&self) -> IpAddr {
        self.server_address
    }

    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    pub fn is_primary(&self) -> bool {
        self.primary
    }

    pub fn is_transaction_writable(&self) -> bool {
        self.transaction_writable
    }

    pub fn is_default_transaction_writable(&self) -> bool {
        self.default_transaction_writable
    }

    pub fn application_role(&self) -> &str {
        &self.application_role
    }

    pub fn migration_role(&self) -> &str {
        &self.migration_role
    }

    pub fn session_login_role(&self) -> &str {
        &self.session_login_role
    }

    pub fn tls(&self) -> &PostgresqlTlsObservation {
        &self.tls
    }

    pub fn migration_ledger(&self) -> &[PostgresqlMigrationLedgerRow] {
        &self.migration_ledger
    }
}

struct ProductionDatabaseConnectionBinding {
    roles: Arc<ProductionDatabaseRoles>,
    baseline: OnceLock<PostgresqlRuntimeObservation>,
}

impl ProductionDatabaseConnectionBinding {
    fn new(roles: Arc<ProductionDatabaseRoles>) -> Self {
        Self {
            roles,
            baseline: OnceLock::new(),
        }
    }

    fn bind_or_compare(
        &self,
        observation: PostgresqlRuntimeObservation,
    ) -> Result<(), sqlx::Error> {
        if let Some(baseline) = self.baseline.get() {
            return if baseline == &observation {
                Ok(())
            } else {
                Err(role_protocol_error(
                    "pooled PostgreSQL connection differs from the sealed production identity",
                ))
            };
        }
        match self.baseline.set(observation) {
            Ok(()) => Ok(()),
            Err(observation) => {
                if self
                    .baseline
                    .get()
                    .is_some_and(|baseline| baseline == &observation)
                {
                    Ok(())
                } else {
                    Err(role_protocol_error(
                        "concurrent PostgreSQL connections resolved to different production identities",
                    ))
                }
            }
        }
    }

    fn require_match(
        &self,
        observation: &PostgresqlRuntimeObservation,
    ) -> Result<(), PostgresqlRuntimeObservationError> {
        if self
            .baseline
            .get()
            .is_some_and(|baseline| baseline == observation)
        {
            Ok(())
        } else {
            Err(observation_contract_error(
                "measured PostgreSQL observation does not match every pooled connection binding",
            ))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PostgresqlRuntimeObservationError {
    #[error("PostgreSQL runtime observation failed: {0}")]
    Database(#[source] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] MigrationVerificationError),
    #[error("PostgreSQL runtime contract was not proven: {0}")]
    Contract(String),
}

#[derive(Debug, thiserror::Error)]
pub enum PostgresqlRuntimePublicationError {
    #[error("a database publication decision was already made for this process")]
    AlreadyPublished,
    #[error("database publication did not receive the exact admission-retained runtime handle")]
    AdmissionHandleMismatch,
    #[error("the globally published database is not the measured retained pool")]
    PublishedPoolMismatch,
}

/// Cloneable only through its retained `Arc` allocations; guard authority is
/// supplied by the separate non-cloneable nominal runtime witness.
#[derive(Clone)]
pub struct RetainedPostgresqlRuntime {
    pool: Arc<PgPool>,
    observation: Arc<PostgresqlRuntimeObservation>,
    roles: Arc<ProductionDatabaseRoles>,
    connection_binding: Arc<ProductionDatabaseConnectionBinding>,
}

impl fmt::Debug for RetainedPostgresqlRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedPostgresqlRuntime")
            .field("contract", &"retained-postgresql-runtime-v1")
            .field(
                "server_major_version",
                &self.observation.server_major_version,
            )
            .field("primary", &self.observation.primary)
            .field(
                "transaction_writable",
                &self.observation.transaction_writable,
            )
            .field("tls_enabled", &true)
            .field("migration_count", &self.observation.migration_ledger.len())
            .finish_non_exhaustive()
    }
}

impl RetainedPostgresqlRuntime {
    pub fn pool(&self) -> &Arc<PgPool> {
        &self.pool
    }

    pub fn observation(&self) -> &Arc<PostgresqlRuntimeObservation> {
        &self.observation
    }

    pub fn pool_ptr_eq(&self, candidate: &Arc<PgPool>) -> bool {
        Arc::ptr_eq(&self.pool, candidate)
    }

    pub fn observation_ptr_eq(&self, candidate: &Arc<PostgresqlRuntimeObservation>) -> bool {
        Arc::ptr_eq(&self.observation, candidate)
    }

    pub fn same_runtime(&self, candidate: &Self) -> bool {
        Arc::ptr_eq(&self.pool, &candidate.pool)
            && Arc::ptr_eq(&self.observation, &candidate.observation)
            && Arc::ptr_eq(&self.roles, &candidate.roles)
            && Arc::ptr_eq(&self.connection_binding, &candidate.connection_binding)
    }

    pub fn is_exact_published_pool(&self) -> bool {
        published_pool_ptr_eq(&self.pool)
    }

    /// Repeat every local SQL observation through the exact retained pool and
    /// require value equality with the initially sealed observation.
    pub async fn remeasure_exact(&self) -> Result<(), PostgresqlRuntimeObservationError> {
        let current = observe_postgresql_runtime(&self.pool, &self.roles).await?;
        self.connection_binding.require_match(&current)?;
        if current != *self.observation {
            return Err(PostgresqlRuntimeObservationError::Contract(
                "live PostgreSQL facts changed after the retained observation was sealed".into(),
            ));
        }
        Ok(())
    }
}

/// Owns a connected and measured pool that is not yet reachable through
/// `get_db()`. Production startup may clone only the retained handle for guard
/// construction; publication consumes this wrapper after all admission gates
/// have sealed.
pub struct UnpublishedPostgresqlRuntime {
    retained: RetainedPostgresqlRuntime,
}

impl fmt::Debug for UnpublishedPostgresqlRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UnpublishedPostgresqlRuntime")
            .field(&self.retained)
            .finish()
    }
}

impl UnpublishedPostgresqlRuntime {
    pub fn retained_handle(&self) -> RetainedPostgresqlRuntime {
        self.retained.clone()
    }

    pub fn is_unpublished(&self) -> bool {
        !database_publication_decided()
    }

    pub fn publish_after_admission(
        self,
        admitted_runtime: &RetainedPostgresqlRuntime,
    ) -> Result<RetainedPostgresqlRuntime, PostgresqlRuntimePublicationError> {
        if !self.retained.same_runtime(admitted_runtime) {
            return Err(PostgresqlRuntimePublicationError::AdmissionHandleMismatch);
        }
        publish_production_pool(self.retained.pool.clone())?;
        if !self.retained.is_exact_published_pool() {
            return Err(PostgresqlRuntimePublicationError::PublishedPoolMismatch);
        }
        Ok(self.retained)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationVerificationError {
    #[error("migration metadata could not be read: {0}")]
    Metadata(#[source] sqlx::Error),
    #[error("migration {0} is partially applied")]
    Dirty(i64),
    #[error("applied migration {0} is duplicated")]
    DuplicateApplied(i64),
    #[error("applied migration versions are not strictly ordered ({previous} before {current})")]
    NotStrictlyOrdered { previous: i64, current: i64 },
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
    static TEST_POOL: std::cell::RefCell<Option<Arc<PgPool>>> = const {
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
    POOL.get().and_then(|pool| pool.as_deref())
}

#[cfg(test)]
pub fn get_db() -> Option<&'static PgPool> {
    TEST_POOL.with(|slot| {
        let borrowed = slot.borrow();
        let pointer = Arc::as_ptr(borrowed.as_ref()?);
        drop(borrowed);
        // SAFETY: TEST_POOL owns an Arc to this stable allocation until the
        // current Rust test thread exits. API tests use current-thread Tokio
        // runtimes; references are consumed within that test. Detached work
        // clones PgPool before spawning, so it does not retain this borrow.
        Some(unsafe { &*pointer })
    })
}

#[cfg(not(test))]
fn published_pool_ptr_eq(candidate: &Arc<PgPool>) -> bool {
    POOL.get()
        .and_then(Option::as_ref)
        .is_some_and(|published| Arc::ptr_eq(published, candidate))
}

#[cfg(not(test))]
fn database_publication_decided() -> bool {
    POOL.get().is_some()
}

#[cfg(test)]
fn published_pool_ptr_eq(candidate: &Arc<PgPool>) -> bool {
    TEST_POOL.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|published| Arc::ptr_eq(published, candidate))
    })
}

#[cfg(test)]
fn database_publication_decided() -> bool {
    TEST_POOL.with(|slot| slot.borrow().is_some())
}

#[cfg(not(test))]
fn publish_production_pool(pool: Arc<PgPool>) -> Result<(), PostgresqlRuntimePublicationError> {
    POOL.set(Some(pool))
        .map_err(|_| PostgresqlRuntimePublicationError::AlreadyPublished)
}

#[cfg(test)]
fn publish_production_pool(pool: Arc<PgPool>) -> Result<(), PostgresqlRuntimePublicationError> {
    TEST_POOL.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(PostgresqlRuntimePublicationError::AlreadyPublished);
        }
        *slot = Some(pool);
        Ok(())
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
    let mut previous = None;
    for (version, checksum) in applied {
        if let Some(previous) = previous {
            if *version < previous {
                return Err(MigrationVerificationError::NotStrictlyOrdered {
                    previous,
                    current: *version,
                });
            }
            if *version == previous {
                return Err(MigrationVerificationError::DuplicateApplied(*version));
            }
        }
        let Some(expected_checksum) = expected.get(version) else {
            return Err(MigrationVerificationError::UnexpectedApplied(*version));
        };
        if checksum.as_slice() != *expected_checksum {
            return Err(MigrationVerificationError::ChecksumMismatch(*version));
        }
        if !seen.insert(*version) {
            return Err(MigrationVerificationError::DuplicateApplied(*version));
        }
        previous = Some(*version);
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

struct RawPostgresqlRuntimeFacts {
    server_version_num: i32,
    server_version: String,
    database_name: String,
    database_oid: i64,
    server_address: Option<String>,
    server_port: Option<i32>,
    primary: bool,
    transaction_writable: bool,
    default_transaction_writable: bool,
    current_role: String,
    session_login_role: String,
    selected_role: String,
    tls_enabled: Option<bool>,
    tls_protocol: Option<String>,
    tls_cipher: Option<String>,
    tls_bits: Option<i32>,
    client_distinguished_name: Option<String>,
    issuer_distinguished_name: Option<String>,
}

fn observation_contract_error(message: impl Into<String>) -> PostgresqlRuntimeObservationError {
    PostgresqlRuntimeObservationError::Contract(message.into())
}

fn validate_optional_distinguished_name(
    label: &str,
    value: Option<String>,
) -> Result<Option<String>, PostgresqlRuntimeObservationError> {
    match value {
        Some(value)
            if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) =>
        {
            Err(observation_contract_error(format!(
                "TLS {label} is empty, oversized, or contains control characters"
            )))
        }
        value => Ok(value),
    }
}

fn validate_postgresql_runtime_facts(
    raw: RawPostgresqlRuntimeFacts,
    roles: &ProductionDatabaseRoles,
    migration_ledger: Box<[PostgresqlMigrationLedgerRow]>,
) -> Result<PostgresqlRuntimeObservation, PostgresqlRuntimeObservationError> {
    let server_version_num = u32::try_from(raw.server_version_num)
        .map_err(|_| observation_contract_error("server_version_num is not positive"))?;
    let server_major_version = u16::try_from(server_version_num / 10_000)
        .map_err(|_| observation_contract_error("server major version is out of range"))?;
    if server_major_version != REQUIRED_PRODUCTION_POSTGRESQL_MAJOR_VERSION {
        return Err(observation_contract_error(format!(
            "PostgreSQL major version must equal {REQUIRED_PRODUCTION_POSTGRESQL_MAJOR_VERSION}, observed {server_major_version}"
        )));
    }
    if raw.server_version.is_empty()
        || raw.server_version.len() > 256
        || raw.server_version.chars().any(char::is_control)
    {
        return Err(observation_contract_error(
            "server_version is empty, oversized, or contains control characters",
        ));
    }
    if raw.database_name.is_empty()
        || raw.database_name.len() > 63
        || raw.database_name.chars().any(char::is_control)
    {
        return Err(observation_contract_error(
            "current database name is empty, oversized, or contains control characters",
        ));
    }
    let database_oid = u32::try_from(raw.database_oid)
        .ok()
        .filter(|oid| *oid != 0)
        .ok_or_else(|| observation_contract_error("current database OID is invalid"))?;
    let server_address = raw
        .server_address
        .as_deref()
        .ok_or_else(|| observation_contract_error("TLS database session has no server address"))?
        .parse::<IpAddr>()
        .map_err(|_| observation_contract_error("database server address is not a canonical IP"))?;
    let server_port = raw
        .server_port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| observation_contract_error("database server port is invalid"))?;
    if !raw.primary || !raw.transaction_writable || !raw.default_transaction_writable {
        return Err(observation_contract_error(
            "database must be a primary with current and default transactions writable",
        ));
    }
    if raw.current_role != roles.application_role
        || raw.selected_role != roles.application_role
        || raw.session_login_role == roles.application_role
        || raw.session_login_role == roles.migration_role
        || raw.session_login_role == "postgres"
    {
        return Err(observation_contract_error(
            "live current/session/selected roles do not match the SET-only application role contract",
        ));
    }
    canonical_database_role_name("session_login_role", raw.session_login_role.clone())
        .map_err(observation_contract_error)?;
    if raw.tls_enabled != Some(true) {
        return Err(observation_contract_error(
            "database transport is not an observed PostgreSQL TLS session",
        ));
    }
    let protocol = raw
        .tls_protocol
        .filter(|protocol| matches!(protocol.as_str(), "TLSv1.2" | "TLSv1.3"))
        .ok_or_else(|| observation_contract_error("database TLS protocol must be 1.2 or 1.3"))?;
    let cipher = raw
        .tls_cipher
        .filter(|cipher| {
            !cipher.is_empty() && cipher.len() <= 256 && !cipher.chars().any(char::is_control)
        })
        .ok_or_else(|| observation_contract_error("database TLS cipher is missing or invalid"))?;
    let bits = raw
        .tls_bits
        .and_then(|bits| u16::try_from(bits).ok())
        .filter(|bits| *bits >= 128)
        .ok_or_else(|| {
            observation_contract_error("database TLS cipher strength is below 128 bits")
        })?;
    let tls = PostgresqlTlsObservation {
        protocol,
        cipher,
        bits,
        client_distinguished_name: validate_optional_distinguished_name(
            "client distinguished name",
            raw.client_distinguished_name,
        )?,
        issuer_distinguished_name: validate_optional_distinguished_name(
            "issuer distinguished name",
            raw.issuer_distinguished_name,
        )?,
    };

    Ok(PostgresqlRuntimeObservation {
        server_version_num,
        server_version: raw.server_version,
        server_major_version,
        database_name: raw.database_name,
        database_oid,
        server_address,
        server_port,
        primary: raw.primary,
        transaction_writable: raw.transaction_writable,
        default_transaction_writable: raw.default_transaction_writable,
        application_role: roles.application_role.clone(),
        migration_role: roles.migration_role.clone(),
        session_login_role: raw.session_login_role,
        tls,
        migration_ledger,
    })
}

fn validate_observed_migration_ledger(
    rows: Vec<(i64, Vec<u8>, bool)>,
) -> Result<Box<[PostgresqlMigrationLedgerRow]>, MigrationVerificationError> {
    let dirty_version = rows
        .iter()
        .find_map(|(version, _, success)| (!success).then_some(*version));
    let applied = rows
        .iter()
        .filter(|(_, _, success)| *success)
        .map(|(version, checksum, _)| (*version, checksum.clone()))
        .collect::<Vec<_>>();
    verify_migration_inventory(&applied, dirty_version)?;
    Ok(applied
        .into_iter()
        .map(|(version, checksum)| PostgresqlMigrationLedgerRow {
            version,
            checksum: checksum.into_boxed_slice(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

async fn read_postgresql_runtime_facts(
    connection: &mut PgConnection,
) -> Result<RawPostgresqlRuntimeFacts, sqlx::Error> {
    let row = sqlx::query(
        r#"
            SELECT
                pg_catalog.current_setting('server_version_num')::integer
                    AS server_version_num,
                pg_catalog.current_setting('server_version') AS server_version,
                pg_catalog.current_database()::text AS database_name,
                database.oid::bigint AS database_oid,
                pg_catalog.inet_server_addr()::text AS server_address,
                pg_catalog.inet_server_port() AS server_port,
                NOT pg_catalog.pg_is_in_recovery() AS is_primary,
                NOT pg_catalog.current_setting('transaction_read_only')::boolean
                    AS transaction_writable,
                NOT pg_catalog.current_setting('default_transaction_read_only')::boolean
                    AS default_transaction_writable,
                current_user::text AS current_role,
                session_user::text AS session_login_role,
                pg_catalog.current_setting('role') AS selected_role,
                tls.ssl AS tls_enabled,
                tls.version AS tls_protocol,
                tls.cipher AS tls_cipher,
                tls.bits AS tls_bits,
                tls.client_dn AS client_distinguished_name,
                tls.issuer_dn AS issuer_distinguished_name
            FROM pg_catalog.pg_database AS database
            LEFT JOIN pg_catalog.pg_stat_ssl AS tls
              ON tls.pid = pg_catalog.pg_backend_pid()
            WHERE database.datname = pg_catalog.current_database()
            "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    Ok(RawPostgresqlRuntimeFacts {
        server_version_num: row.try_get("server_version_num")?,
        server_version: row.try_get("server_version")?,
        database_name: row.try_get("database_name")?,
        database_oid: row.try_get("database_oid")?,
        server_address: row.try_get("server_address")?,
        server_port: row.try_get("server_port")?,
        primary: row.try_get("is_primary")?,
        transaction_writable: row.try_get("transaction_writable")?,
        default_transaction_writable: row.try_get("default_transaction_writable")?,
        current_role: row.try_get("current_role")?,
        session_login_role: row.try_get("session_login_role")?,
        selected_role: row.try_get("selected_role")?,
        tls_enabled: row.try_get("tls_enabled")?,
        tls_protocol: row.try_get("tls_protocol")?,
        tls_cipher: row.try_get("tls_cipher")?,
        tls_bits: row.try_get("tls_bits")?,
        client_distinguished_name: row.try_get("client_distinguished_name")?,
        issuer_distinguished_name: row.try_get("issuer_distinguished_name")?,
    })
}

async fn observe_postgresql_runtime(
    pool: &PgPool,
    roles: &ProductionDatabaseRoles,
) -> Result<PostgresqlRuntimeObservation, PostgresqlRuntimeObservationError> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(PostgresqlRuntimeObservationError::Database)?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(PostgresqlRuntimeObservationError::Database)?;

    let result = async {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ WRITE")
            .execute(&mut *transaction)
            .await
            .map_err(PostgresqlRuntimeObservationError::Database)?;
        // RESET ROLE is deliberately inside the transaction. Any failure or
        // cancellation rolls the pooled session back to its already-attested
        // application role instead of returning a login-role session.
        sqlx::query("RESET ROLE")
            .execute(&mut *transaction)
            .await
            .map_err(PostgresqlRuntimeObservationError::Database)?;
        // Run the complete role/ACL proof and decisive identity/ledger reads in
        // one repeatable-read transaction so catalog changes cannot splice a
        // passing observation from different authority states.
        attest_application_connection(&mut transaction, &roles.application_contract())
            .await
            .map_err(PostgresqlRuntimeObservationError::Database)?;
        let raw = read_postgresql_runtime_facts(&mut transaction)
            .await
            .map_err(PostgresqlRuntimeObservationError::Database)?;
        let ledger_rows: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version, checksum, success FROM public._sqlx_migrations ORDER BY version",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| {
            PostgresqlRuntimeObservationError::Migration(MigrationVerificationError::Metadata(
                error,
            ))
        })?;
        let migration_ledger = validate_observed_migration_ledger(ledger_rows)?;
        validate_postgresql_runtime_facts(raw, roles, migration_ledger)
    }
    .await;

    match result {
        Ok(observation) => {
            transaction
                .commit()
                .await
                .map_err(PostgresqlRuntimeObservationError::Database)?;
            Ok(observation)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
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

/// Prove that the four request resource-version invariants still target the
/// reviewed trigger functions and fire even in replica sessions. This is a
/// startup schema attestation, not just a privilege check: disabling a trigger,
/// changing its event/column scope, or replacing a function body must fail the
/// application connection before it can serve traffic.
async fn attest_request_resource_version_triggers(
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH request_table AS (
            SELECT class.oid,
                   resource_version.attnum AS resource_version_attnum
            FROM pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = class.relnamespace
            JOIN pg_catalog.pg_attribute AS resource_version
              ON resource_version.attrelid = class.oid
             AND resource_version.attname = 'resource_version'
             AND resource_version.attnum > 0
             AND NOT resource_version.attisdropped
            WHERE namespace.nspname = 'public'
              AND class.relname = 'requests'
              AND class.relkind = 'r'
        ),
        expected(
            trigger_name,
            function_signature,
            trigger_type,
            column_specific,
            function_source_sha256
        ) AS (
            VALUES
                (
                    'trg_requests_resource_version_owned'::text,
                    'public.reject_caller_managed_request_resource_version()'::text,
                    19::smallint,
                    true,
                    '8398ad738d888fbe104696423676e61ea3fd579222ad775830c1a0ae056531cd'::text
                ),
                (
                    'trg_requests_zz_resource_version'::text,
                    'public.advance_request_resource_version()'::text,
                    23::smallint,
                    false,
                    '275aec932a2e02510bbc9dc6fb17bb392412dcb592d7fe33d30904472efeb8fe'::text
                ),
                (
                    'trg_requests_resource_version_no_delete'::text,
                    'public.reject_runtime_request_resource_deletion()'::text,
                    11::smallint,
                    false,
                    '42ca6bd64968c7bf9cd303a32fc2b2e33d4b14d8427cf8664c177947b0800fe4'::text
                ),
                (
                    'trg_requests_resource_version_no_truncate'::text,
                    'public.reject_runtime_request_resource_deletion()'::text,
                    34::smallint,
                    false,
                    '42ca6bd64968c7bf9cd303a32fc2b2e33d4b14d8427cf8664c177947b0800fe4'::text
                )
        ),
        matching AS (
            SELECT expected.trigger_name
            FROM expected
            CROSS JOIN request_table
            JOIN pg_catalog.pg_trigger AS trigger
              ON trigger.tgrelid = request_table.oid
             AND trigger.tgname = expected.trigger_name
            JOIN pg_catalog.pg_proc AS procedure
              ON procedure.oid = trigger.tgfoid
            JOIN pg_catalog.pg_language AS language
              ON language.oid = procedure.prolang
            WHERE trigger.tgfoid =
                      pg_catalog.to_regprocedure(expected.function_signature)
              AND trigger.tgtype = expected.trigger_type
              AND trigger.tgenabled = 'A'
              AND NOT trigger.tgisinternal
              AND trigger.tgparentid = 0
              AND trigger.tgconstraint = 0
              AND trigger.tgconstrrelid = 0
              AND trigger.tgconstrindid = 0
              AND NOT trigger.tgdeferrable
              AND NOT trigger.tginitdeferred
              AND trigger.tgnargs = 0
              AND pg_catalog.octet_length(trigger.tgargs) = 0
              AND trigger.tgqual IS NULL
              AND trigger.tgoldtable IS NULL
              AND trigger.tgnewtable IS NULL
              AND (
                   (
                       expected.column_specific
                       AND trigger.tgattr::text =
                           request_table.resource_version_attnum::text
                   )
                   OR (
                       NOT expected.column_specific
                       AND trigger.tgattr::text = ''
                   )
              )
              AND procedure.prokind = 'f'
              AND procedure.prorettype = 'pg_catalog.trigger'::regtype
              AND procedure.pronargs = 0
              AND NOT procedure.prosecdef
              AND NOT procedure.proleakproof
              AND procedure.provolatile = 'v'
              AND procedure.proparallel = 'u'
              AND procedure.proconfig IS NULL
              AND language.lanname = 'plpgsql'
              AND pg_catalog.encode(
                      pg_catalog.sha256(
                          pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                      ),
                      'hex'
                  ) = expected.function_source_sha256
        )
        SELECT (SELECT COUNT(*) FROM request_table) = 1
           AND (SELECT COUNT(*) FROM matching) = 4
           AND NOT EXISTS (
               SELECT 1
               FROM expected
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM matching
                   WHERE matching.trigger_name = expected.trigger_name
               )
           )
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "request resource-version trigger definitions are not canonical and always enabled",
        ));
    }
    Ok(())
}

/// Prove that approval evidence and dispatched agent work remain bound to the
/// exact request authority version selected by migration 196. These guards are
/// part of the startup schema contract: changing a target table, trigger event
/// or column set, execution mode, or function body must prevent the application
/// connection from serving traffic.
async fn attest_request_authority_version_binding_triggers(
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH target_tables AS (
            SELECT class.oid,
                   class.relname::text AS table_name
            FROM pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = class.relnamespace
            WHERE namespace.nspname = 'public'
              AND class.relname IN (
                    'request_approval_decisions',
                    'agent_jobs'
                  )
              AND class.relkind = 'r'
        ),
        expected(
            table_name,
            trigger_name,
            function_signature,
            trigger_type,
            column_names,
            function_source_sha256
        ) AS (
            VALUES
                (
                    'request_approval_decisions'::text,
                    'trg_request_approval_decision_basis_version'::text,
                    'public.bind_request_approval_basis_resource_version()'::text,
                    7::smallint,
                    ARRAY[]::text[],
                    'e2579634b52772f8523057618254b0c000db9ad99026c7fd6f5ff1bd670b4822'::text
                ),
                (
                    'request_approval_decisions'::text,
                    'trg_request_approval_decision_basis_version_owned'::text,
                    'public.reject_request_approval_basis_version_update()'::text,
                    19::smallint,
                    ARRAY['approval_basis_resource_version']::text[],
                    '7b412cf35870cd0ebc625e44758d279745553ae4783bc7920761a6c22522fe3f'::text
                ),
                (
                    'agent_jobs'::text,
                    'trg_agent_jobs_request_resource_version'::text,
                    'public.bind_agent_job_request_resource_version()'::text,
                    7::smallint,
                    ARRAY[]::text[],
                    'd26216065dfbd4f9fcdc00a5a9cfd1d0422499863109a05fc4690c5413d59d58'::text
                ),
                (
                    'agent_jobs'::text,
                    'trg_agent_jobs_request_resource_version_owned'::text,
                    'public.reject_agent_job_request_binding_update()'::text,
                    19::smallint,
                    ARRAY[
                        'id',
                        'request_id',
                        'platform',
                        'spec',
                        'mode',
                        'live_context',
                        'origin',
                        'step_scoped',
                        'request_resource_version'
                    ]::text[],
                    '5b6979234abd8ad135cd5f7d4125c6e2b0444139ddf88a560951d2581376db19'::text
                )
        ),
        resolved_expected AS (
            SELECT expected.*,
                   target_tables.oid AS table_oid,
                   resolved_columns.resolved_count,
                   resolved_columns.trigger_columns
            FROM expected
            JOIN target_tables
              ON target_tables.table_name = expected.table_name
            CROSS JOIN LATERAL (
                SELECT COUNT(attribute.attnum)::integer AS resolved_count,
                       COALESCE(
                           pg_catalog.string_agg(
                               attribute.attnum::text,
                               ' ' ORDER BY column_name.ordinality
                           ),
                           ''
                       ) AS trigger_columns
                FROM pg_catalog.unnest(expected.column_names)
                     WITH ORDINALITY AS column_name(name, ordinality)
                JOIN pg_catalog.pg_attribute AS attribute
                  ON attribute.attrelid = target_tables.oid
                 AND attribute.attname = column_name.name
                 AND attribute.attnum > 0
                 AND NOT attribute.attisdropped
            ) AS resolved_columns
        ),
        matching AS (
            SELECT expected.trigger_name
            FROM resolved_expected AS expected
            JOIN pg_catalog.pg_trigger AS trigger
              ON trigger.tgrelid = expected.table_oid
             AND trigger.tgname = expected.trigger_name
            JOIN pg_catalog.pg_proc AS procedure
              ON procedure.oid = trigger.tgfoid
            JOIN pg_catalog.pg_language AS language
              ON language.oid = procedure.prolang
            WHERE expected.resolved_count =
                      pg_catalog.cardinality(expected.column_names)
              AND trigger.tgfoid =
                      pg_catalog.to_regprocedure(expected.function_signature)
              AND trigger.tgtype = expected.trigger_type
              AND trigger.tgattr::text = expected.trigger_columns
              AND trigger.tgenabled = 'A'
              AND NOT trigger.tgisinternal
              AND trigger.tgparentid = 0
              AND trigger.tgconstraint = 0
              AND trigger.tgconstrrelid = 0
              AND trigger.tgconstrindid = 0
              AND NOT trigger.tgdeferrable
              AND NOT trigger.tginitdeferred
              AND trigger.tgnargs = 0
              AND pg_catalog.octet_length(trigger.tgargs) = 0
              AND trigger.tgqual IS NULL
              AND trigger.tgoldtable IS NULL
              AND trigger.tgnewtable IS NULL
              AND procedure.prokind = 'f'
              AND procedure.prorettype = 'pg_catalog.trigger'::regtype
              AND procedure.pronargs = 0
              AND NOT procedure.prosecdef
              AND NOT procedure.proleakproof
              AND procedure.provolatile = 'v'
              AND procedure.proparallel = 'u'
              AND procedure.proconfig IS NULL
              AND language.lanname = 'plpgsql'
              AND pg_catalog.encode(
                      pg_catalog.sha256(
                          pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                      ),
                      'hex'
                  ) = expected.function_source_sha256
        )
        SELECT (SELECT COUNT(*) FROM target_tables) = 2
           AND (SELECT COUNT(*) FROM resolved_expected) = 4
           AND (SELECT COUNT(*) FROM matching) = 4
           AND NOT EXISTS (
               SELECT 1
               FROM expected
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM matching
                   WHERE matching.trigger_name = expected.trigger_name
               )
           )
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "request authority-version binding trigger definitions are not canonical and always enabled",
        ));
    }
    Ok(())
}

async fn attest_application_connection(
    connection: &mut PgConnection,
    contract: &ApplicationRoleContract,
) -> Result<(), sqlx::Error> {
    assume_and_attest_database_role(connection, &contract.expected, &contract.forbidden).await?;
    let trigger_enforcement_is_fixed: bool = sqlx::query_scalar(
        r#"
        WITH app AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        login AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user
        )
        SELECT pg_catalog.current_setting('session_replication_role') = 'origin'
           AND NOT EXISTS (
               SELECT 1
               FROM pg_catalog.pg_parameter_acl AS parameter_acl
               CROSS JOIN LATERAL pg_catalog.aclexplode(parameter_acl.paracl) AS acl
               CROSS JOIN app
               CROSS JOIN login
               WHERE parameter_acl.parname = 'session_replication_role'
                 AND acl.grantee IN (0, app.oid, login.oid)
                 AND acl.privilege_type IN ('SET', 'ALTER SYSTEM')
           )
        "#,
    )
    .bind(&contract.expected)
    .fetch_one(&mut *connection)
    .await?;
    if !trigger_enforcement_is_fixed {
        return Err(role_protocol_error(
            "application or login role can disable database trigger enforcement",
        ));
    }
    attest_request_resource_version_triggers(connection).await?;
    attest_request_authority_version_binding_triggers(connection).await?;
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

async fn attest_and_bind_production_connection(
    connection: &mut PgConnection,
    binding: &ProductionDatabaseConnectionBinding,
) -> Result<(), sqlx::Error> {
    sqlx::query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ WRITE")
        .execute(&mut *connection)
        .await?;
    let result = async {
        attest_application_connection(connection, &binding.roles.application_contract()).await?;
        let raw = read_postgresql_runtime_facts(connection).await?;
        let ledger_rows: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version, checksum, success FROM public._sqlx_migrations ORDER BY version",
        )
        .fetch_all(&mut *connection)
        .await?;
        let migration_ledger = validate_observed_migration_ledger(ledger_rows).map_err(|_| {
            role_protocol_error(
                "pooled connection migration ledger differs from the embedded inventory",
            )
        })?;
        let observation = validate_postgresql_runtime_facts(raw, &binding.roles, migration_ledger)
            .map_err(|_| {
                role_protocol_error(
                    "pooled connection failed the production PostgreSQL fact contract",
                )
            })?;
        binding.bind_or_compare(observation)
    }
    .await;
    match result {
        Ok(()) => {
            sqlx::query("COMMIT").execute(&mut *connection).await?;
            Ok(())
        }
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            Err(error)
        }
    }
}

async fn build_application_pool_inner(
    url: &str,
    settings: ApplicationPoolSettings,
    role_contract: Option<ApplicationRoleContract>,
    production_connection_binding: Option<Arc<ProductionDatabaseConnectionBinding>>,
) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .idle_timeout(Duration::from_secs(settings.idle_timeout_secs))
        .acquire_timeout(Duration::from_secs(settings.acquire_timeout_secs))
        .max_lifetime(Duration::from_secs(settings.max_lifetime_secs))
        // Bound application OLTP independently from offline DDL. Migration
        // processes never use this pool.
        .after_connect(move |conn, _meta| {
            let role_contract = role_contract.clone();
            let production_connection_binding = production_connection_binding.clone();
            Box::pin(async move {
                use sqlx::Executor;
                conn.execute("SET statement_timeout = '30s'; SET lock_timeout = '10s'")
                    .await?;
                if let Some(binding) = production_connection_binding.as_ref() {
                    attest_and_bind_production_connection(conn, binding).await?;
                } else if let Some(contract) = role_contract.as_ref() {
                    attest_application_connection(conn, contract).await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
}

/// Connect, attest, and measure a production PostgreSQL pool without making it
/// visible to request handlers, repositories, workers, or `get_db()`. The
/// returned wrapper must remain unpublished until the complete production
/// runtime admission has consumed a retained handle for this exact allocation.
pub async fn construct_unpublished_production_database(
    url: &str,
    settings: ApplicationPoolSettings,
    roles: ProductionDatabaseRoles,
) -> Result<UnpublishedPostgresqlRuntime, PostgresqlRuntimeObservationError> {
    if database_publication_decided() {
        return Err(observation_contract_error(
            "a database publication decision already exists before production observation",
        ));
    }
    if PRODUCTION_DATABASE_CONSTRUCTION_CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(observation_contract_error(
            "production database construction was already claimed for this process",
        ));
    }
    let roles = Arc::new(roles);
    let connection_binding = Arc::new(ProductionDatabaseConnectionBinding::new(roles.clone()));
    let pool = Arc::new(
        build_application_pool_inner(url, settings, None, Some(connection_binding.clone()))
            .await
            .map_err(PostgresqlRuntimeObservationError::Database)?,
    );
    let observation = match observe_postgresql_runtime(&pool, &roles).await {
        Ok(observation) => observation,
        Err(error) => {
            pool.close().await;
            set_migration_status(MigrationStatus::Failed);
            return Err(error);
        }
    };
    if let Err(error) = connection_binding.require_match(&observation) {
        pool.close().await;
        set_migration_status(MigrationStatus::Failed);
        return Err(error);
    }
    set_migration_status(MigrationStatus::Applied);
    let retained = RetainedPostgresqlRuntime {
        pool,
        observation: Arc::new(observation),
        roles,
        connection_binding,
    };
    if !database_publication_decided() {
        Ok(UnpublishedPostgresqlRuntime { retained })
    } else {
        retained.pool.close().await;
        Err(observation_contract_error(
            "a database publication decision raced production observation",
        ))
    }
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
        ApplicationPoolSettings {
            max_connections,
            min_connections,
            idle_timeout_secs,
            acquire_timeout_secs,
            max_lifetime_secs,
        },
        None,
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
        ApplicationPoolSettings {
            max_connections,
            min_connections,
            idle_timeout_secs,
            acquire_timeout_secs,
            max_lifetime_secs,
        },
        role_contract,
        None,
    )
    .await;

    let pool = match connected {
        Ok(pool) => {
            tracing::info!("database connected");
            Some(Arc::new(pool))
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
        *slot.borrow_mut() = pool;
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
        assert!(super::ProductionDatabaseRoles::new(
            "ryuki_app_runtime".into(),
            "ryuki_schema_migrator".into(),
        )
        .is_ok());
        assert!(super::ProductionDatabaseRoles::new(
            "postgres".into(),
            "ryuki_schema_migrator".into(),
        )
        .is_err());
        assert!(super::ProductionDatabaseRoles::new(
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
            "first_owner_closure_records",
            "first_owner_privileged_domain_assignments",
            "k8s_cluster_registry",
            "k8s_cluster_environment_scopes",
            "noisy_trigger_site_authority",
            "scheduler_protocol_versions",
        ] {
            assert_eq!(policies.get(name), Some(&(false, false, false)));
        }
    }

    #[test]
    fn production_pool_settings_are_bounded_before_connect() {
        assert!(super::ApplicationPoolSettings::new(20, 2, 300, 30, 1_800).is_ok());
        for settings in [
            (0, 0, 300, 30, 1_800),
            (2, 3, 300, 30, 1_800),
            (2, 1, 0, 30, 1_800),
            (2, 1, 300, 0, 1_800),
            (2, 1, 300, 30, 0),
        ] {
            assert!(super::ApplicationPoolSettings::new(
                settings.0, settings.1, settings.2, settings.3, settings.4,
            )
            .is_err());
        }
    }

    #[test]
    fn local_postgresql_fact_validation_fails_closed_without_live_io() {
        fn valid_raw() -> super::RawPostgresqlRuntimeFacts {
            super::RawPostgresqlRuntimeFacts {
                server_version_num: 180_002,
                server_version: "18.2".into(),
                database_name: "ryuki".into(),
                database_oid: 16_384,
                server_address: Some("192.0.2.10".into()),
                server_port: Some(5432),
                primary: true,
                transaction_writable: true,
                default_transaction_writable: true,
                current_role: "ryuki_app_runtime".into(),
                session_login_role: "ryuki_login_20260719".into(),
                selected_role: "ryuki_app_runtime".into(),
                tls_enabled: Some(true),
                tls_protocol: Some("TLSv1.3".into()),
                tls_cipher: Some("TLS_AES_256_GCM_SHA384".into()),
                tls_bits: Some(256),
                client_distinguished_name: None,
                issuer_distinguished_name: None,
            }
        }

        let roles = super::ProductionDatabaseRoles::new(
            "ryuki_app_runtime".into(),
            "ryuki_schema_migrator".into(),
        )
        .unwrap();
        assert!(super::validate_postgresql_runtime_facts(
            valid_raw(),
            &roles,
            Vec::new().into_boxed_slice(),
        )
        .is_ok());

        let mut wrong_major = valid_raw();
        wrong_major.server_version_num = 170_009;
        assert!(super::validate_postgresql_runtime_facts(
            wrong_major,
            &roles,
            Vec::new().into_boxed_slice(),
        )
        .is_err());

        let mut standby = valid_raw();
        standby.primary = false;
        assert!(super::validate_postgresql_runtime_facts(
            standby,
            &roles,
            Vec::new().into_boxed_slice(),
        )
        .is_err());

        let mut read_only = valid_raw();
        read_only.transaction_writable = false;
        assert!(super::validate_postgresql_runtime_facts(
            read_only,
            &roles,
            Vec::new().into_boxed_slice(),
        )
        .is_err());

        let mut plaintext = valid_raw();
        plaintext.tls_enabled = Some(false);
        assert!(super::validate_postgresql_runtime_facts(
            plaintext,
            &roles,
            Vec::new().into_boxed_slice(),
        )
        .is_err());

        let mut wrong_role = valid_raw();
        wrong_role.current_role = "ryuki_schema_migrator".into();
        assert!(super::validate_postgresql_runtime_facts(
            wrong_role,
            &roles,
            Vec::new().into_boxed_slice(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn retained_postgresql_debug_is_value_free() {
        let roles = super::ProductionDatabaseRoles::new(
            "ryuki_app_runtime".into(),
            "ryuki_schema_migrator".into(),
        )
        .unwrap();
        let observation = std::sync::Arc::new(super::PostgresqlRuntimeObservation {
            server_version_num: 180_002,
            server_version: "18.2 sensitive-build-label".into(),
            server_major_version: 18,
            database_name: "sensitive_database".into(),
            database_oid: 42_424,
            server_address: "192.0.2.77".parse().unwrap(),
            server_port: 5432,
            primary: true,
            transaction_writable: true,
            default_transaction_writable: true,
            application_role: roles.application_role.clone(),
            migration_role: roles.migration_role.clone(),
            session_login_role: "sensitive_ephemeral_login".into(),
            tls: super::PostgresqlTlsObservation {
                protocol: "TLSv1.3".into(),
                cipher: "sensitive_cipher".into(),
                bits: 256,
                client_distinguished_name: Some("CN=sensitive-client".into()),
                issuer_distinguished_name: Some("CN=sensitive-issuer".into()),
            },
            migration_ledger: Vec::new().into_boxed_slice(),
        });
        let pool = std::sync::Arc::new(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgresql://placeholder@example.invalid/debug-db")
                .unwrap(),
        );
        let retained = super::RetainedPostgresqlRuntime {
            pool,
            observation: observation.clone(),
            roles: std::sync::Arc::new(roles.clone()),
            connection_binding: std::sync::Arc::new(
                super::ProductionDatabaseConnectionBinding::new(std::sync::Arc::new(roles.clone())),
            ),
        };
        assert!(retained.same_runtime(&retained.clone()));
        let foreign_pool = std::sync::Arc::new(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgresql://foreign@example.invalid/debug-db")
                .unwrap(),
        );
        let foreign = super::RetainedPostgresqlRuntime {
            pool: foreign_pool,
            observation: observation.clone(),
            roles: retained.roles.clone(),
            connection_binding: retained.connection_binding.clone(),
        };
        assert!(!retained.same_runtime(&foreign));
        let debug = format!("{roles:?} {observation:?} {retained:?}");
        for forbidden in [
            "ryuki_app_runtime",
            "ryuki_schema_migrator",
            "sensitive_database",
            "42424",
            "192.0.2.77",
            "sensitive_ephemeral_login",
            "sensitive_cipher",
            "sensitive-client",
            "sensitive-issuer",
            "placeholder",
        ] {
            assert!(
                !debug.contains(forbidden),
                "debug output leaked {forbidden}: {debug}"
            );
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

        let mut duplicated: Vec<(i64, Vec<u8>)> = expected
            .iter()
            .map(|(version, checksum)| (*version, checksum.to_vec()))
            .collect();
        duplicated.insert(1, duplicated[0].clone());
        assert!(matches!(
            verify_migration_inventory(&duplicated, None),
            Err(MigrationVerificationError::DuplicateApplied(_))
        ));

        let mut out_of_order: Vec<(i64, Vec<u8>)> = expected
            .iter()
            .map(|(version, checksum)| (*version, checksum.to_vec()))
            .collect();
        out_of_order.swap(0, 1);
        assert!(matches!(
            verify_migration_inventory(&out_of_order, None),
            Err(MigrationVerificationError::NotStrictlyOrdered { .. })
        ));
    }

    #[tokio::test]
    async fn request_resource_version_triggers_are_attested_and_fire_in_replica_mode() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let mut connection = PgConnection::connect(&url)
            .await
            .expect("connect request resource-version trigger test");
        super::EMBEDDED_MIGRATOR
            .run(&mut connection)
            .await
            .expect("apply request resource-version migrations");

        super::attest_request_resource_version_triggers(&mut connection)
            .await
            .expect("canonical request resource-version triggers");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin trigger drift fixture");
        sqlx::query(
            "ALTER TABLE public.requests DISABLE TRIGGER \
             trg_requests_resource_version_owned",
        )
        .execute(&mut connection)
        .await
        .expect("disable one invariant trigger inside rollback-only fixture");
        let drift_error = super::attest_request_resource_version_triggers(&mut connection)
            .await
            .expect_err("disabled invariant trigger must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("trigger definitions are not canonical and always enabled"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical trigger state");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin replica-mode trigger fixture");
        sqlx::query("SET LOCAL session_replication_role = 'replica'")
            .execute(&mut connection)
            .await
            .expect("fixture role may enter replica mode");

        let (request_id, inserted_version): (uuid::Uuid, i64) = sqlx::query_as(
            "INSERT INTO public.requests (\
                 request_type, status, stage, site, environment, name, \
                 cpu, memory_gb, resource_version\
             ) VALUES (\
                 'server-deployment', 'intake', 'intake', \
                 'resource-version-test', 'test', 'replica insert', 1, 1, 41\
             ) RETURNING id, resource_version",
        )
        .fetch_one(&mut connection)
        .await
        .expect("insert request while origin triggers are suppressed");
        assert_eq!(
            inserted_version, 1,
            "the ALWAYS insert trigger must normalize a caller-supplied version"
        );

        let updated_version: i64 = sqlx::query_scalar(
            "UPDATE public.requests \
             SET name = 'replica update' \
             WHERE id = $1 \
             RETURNING resource_version",
        )
        .bind(request_id)
        .fetch_one(&mut connection)
        .await
        .expect("update request in replica mode");
        assert_eq!(
            updated_version, 2,
            "the ALWAYS update trigger must advance the resource version"
        );

        sqlx::query("SAVEPOINT caller_managed_version")
            .execute(&mut connection)
            .await
            .expect("save caller-managed version fixture");
        let assignment_error =
            sqlx::query("UPDATE public.requests SET resource_version = 1 WHERE id = $1")
                .bind(request_id)
                .execute(&mut connection)
                .await
                .expect_err("replica mode must not bypass caller-assignment rejection");
        assert_eq!(
            assignment_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55000")
        );
        sqlx::query("ROLLBACK TO SAVEPOINT caller_managed_version")
            .execute(&mut connection)
            .await
            .expect("recover caller-managed version fixture");

        sqlx::query("SET LOCAL ryuki.force_request_runtime_contract = 'runtime-v1'")
            .execute(&mut connection)
            .await
            .expect("force runtime deletion policy in owner-backed fixture");
        sqlx::query("SAVEPOINT request_delete")
            .execute(&mut connection)
            .await
            .expect("save request deletion fixture");
        let deletion_error = sqlx::query("DELETE FROM public.requests WHERE id = $1")
            .bind(request_id)
            .execute(&mut connection)
            .await
            .expect_err("replica mode must not bypass request deletion rejection");
        assert_eq!(
            deletion_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55000")
        );
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("discard replica-mode trigger fixture");
    }

    #[tokio::test]
    async fn request_authority_version_binding_triggers_are_attested_and_must_stay_enabled() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let mut connection = PgConnection::connect(&url)
            .await
            .expect("connect request authority-version binding trigger test");
        super::EMBEDDED_MIGRATOR
            .run(&mut connection)
            .await
            .expect("apply request authority-version binding migrations");

        super::attest_request_authority_version_binding_triggers(&mut connection)
            .await
            .expect("canonical request authority-version binding triggers");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin binding trigger drift fixture");
        sqlx::query(
            "ALTER TABLE public.agent_jobs DISABLE TRIGGER \
             trg_agent_jobs_request_resource_version_owned",
        )
        .execute(&mut connection)
        .await
        .expect("disable one request authority-version binding trigger");
        let drift_error = super::attest_request_authority_version_binding_triggers(&mut connection)
            .await
            .expect_err("disabled binding trigger must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("binding trigger definitions are not canonical and always enabled"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical request authority-version binding trigger state");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin request authority-version binding fixture");
        sqlx::query("SET LOCAL session_replication_role = 'replica'")
            .execute(&mut connection)
            .await
            .expect("fixture role may enter replica mode");

        let (request_id, request_resource_version): (uuid::Uuid, i64) = sqlx::query_as(
            "INSERT INTO public.requests (\
                 request_type, status, stage, site, environment, name, \
                 cpu, memory_gb, resource_version\
             ) VALUES (\
                 'server-deployment', 'intake', 'intake', \
                 'authority-version-test', 'test', 'binding fixture', 1, 1, 41\
             ) RETURNING id, resource_version",
        )
        .fetch_one(&mut connection)
        .await
        .expect("insert request for authority-version binding fixture");
        assert_eq!(
            request_resource_version, 1,
            "the request ALWAYS trigger must establish the canonical initial version"
        );

        let job_id: uuid::Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO public.agent_jobs (
                request_id,
                request_resource_version,
                platform,
                spec,
                mode,
                live_context,
                origin,
                step_scoped
            ) VALUES (
                $1,
                $2,
                'authority-version-test',
                jsonb_build_object(
                    'request_id', $1::uuid::text,
                    'request_resource_version', $2::bigint,
                    'offering_id', '00000000-0000-0000-0000-000000000196',
                    'iac_ref', 'authority-version-test@v7',
                    'iac_digest', repeat('0', 64),
                    'vars', '{}'::jsonb,
                    'state_key', 'authority-version-test',
                    'mode', 'offline_dry_run'
                ),
                'OfflineDryRun',
                NULL,
                NULL,
                FALSE
            )
            RETURNING id
            "#,
        )
        .bind(request_id)
        .bind(request_resource_version)
        .fetch_one(&mut connection)
        .await
        .expect("insert canonical protocol-v7 job bound to the current request version");

        for (column, statement) in [
            (
                "id",
                "UPDATE public.agent_jobs SET id = gen_random_uuid() WHERE id = $1",
            ),
            (
                "request_id",
                "UPDATE public.agent_jobs SET request_id = gen_random_uuid() WHERE id = $1",
            ),
            (
                "platform",
                "UPDATE public.agent_jobs SET platform = platform || '-tampered' WHERE id = $1",
            ),
            (
                "spec",
                "UPDATE public.agent_jobs \
                 SET spec = jsonb_set(spec, '{iac_ref}', '\"tampered\"'::jsonb) \
                 WHERE id = $1",
            ),
            (
                "mode",
                "UPDATE public.agent_jobs SET mode = 'LivePlan' WHERE id = $1",
            ),
            (
                "live_context",
                "UPDATE public.agent_jobs SET live_context = '{}'::jsonb WHERE id = $1",
            ),
            (
                "origin",
                "UPDATE public.agent_jobs SET origin = 'drift_recheck' WHERE id = $1",
            ),
            (
                "step_scoped",
                "UPDATE public.agent_jobs SET step_scoped = NOT step_scoped WHERE id = $1",
            ),
            (
                "request_resource_version",
                "UPDATE public.agent_jobs \
                 SET request_resource_version = request_resource_version + 1 \
                 WHERE id = $1",
            ),
        ] {
            sqlx::query("SAVEPOINT authority_update")
                .execute(&mut connection)
                .await
                .expect("save immutable authority update fixture");
            let update_result = sqlx::query(statement)
                .bind(job_id)
                .execute(&mut connection)
                .await;
            let update_error = match update_result {
                Ok(_) => {
                    panic!("replica mode must not permit an agent_jobs.{column} authority update")
                }
                Err(error) => error,
            };
            assert_eq!(
                update_error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref(),
                Some("55000"),
                "agent_jobs.{column} authority update returned the wrong SQLSTATE"
            );
            sqlx::query("ROLLBACK TO SAVEPOINT authority_update")
                .execute(&mut connection)
                .await
                .expect("recover immutable authority update fixture");
            sqlx::query("RELEASE SAVEPOINT authority_update")
                .execute(&mut connection)
                .await
                .expect("release immutable authority update fixture");
        }

        sqlx::query("SAVEPOINT row_spec_mode_mismatch")
            .execute(&mut connection)
            .await
            .expect("save row/spec mode mismatch fixture");
        let mismatch_error = sqlx::query(
            r#"
            INSERT INTO public.agent_jobs (
                request_id,
                request_resource_version,
                platform,
                spec,
                mode
            ) VALUES (
                $1,
                $2,
                'authority-version-test',
                jsonb_build_object(
                    'request_id', $1::uuid::text,
                    'request_resource_version', $2::bigint,
                    'offering_id', '00000000-0000-0000-0000-000000000196',
                    'iac_ref', 'authority-version-test@v7',
                    'iac_digest', repeat('0', 64),
                    'vars', '{}'::jsonb,
                    'state_key', 'authority-version-test',
                    'mode', 'offline_dry_run'
                ),
                'LivePlan'
            )
            "#,
        )
        .bind(request_id)
        .bind(request_resource_version)
        .execute(&mut connection)
        .await
        .expect_err("replica mode must reject a row/spec mode mismatch");
        assert_eq!(
            mismatch_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        sqlx::query("ROLLBACK TO SAVEPOINT row_spec_mode_mismatch")
            .execute(&mut connection)
            .await
            .expect("recover row/spec mode mismatch fixture");
        sqlx::query("RELEASE SAVEPOINT row_spec_mode_mismatch")
            .execute(&mut connection)
            .await
            .expect("release row/spec mode mismatch fixture");

        for missing_field in ["request_id", "request_resource_version", "mode"] {
            sqlx::query("SAVEPOINT missing_authority_field")
                .execute(&mut connection)
                .await
                .expect("save missing authority field fixture");
            let missing_error = sqlx::query(
                r#"
                INSERT INTO public.agent_jobs (
                    request_id,
                    request_resource_version,
                    platform,
                    spec,
                    mode
                ) VALUES (
                    $1,
                    $2,
                    'authority-version-test',
                    jsonb_build_object(
                        'request_id', $1::uuid::text,
                        'request_resource_version', $2::bigint,
                        'offering_id', '00000000-0000-0000-0000-000000000196',
                        'iac_ref', 'authority-version-test@v7',
                        'iac_digest', repeat('0', 64),
                        'vars', '{}'::jsonb,
                        'state_key', 'authority-version-test',
                        'mode', 'offline_dry_run'
                    ) - $3::text,
                    'OfflineDryRun'
                )
                "#,
            )
            .bind(request_id)
            .bind(request_resource_version)
            .bind(missing_field)
            .execute(&mut connection)
            .await
            .expect_err("replica mode must reject a missing spec authority field");
            assert_eq!(
                missing_error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref(),
                Some("23514"),
                "missing spec authority field {missing_field} returned the wrong SQLSTATE"
            );
            sqlx::query("ROLLBACK TO SAVEPOINT missing_authority_field")
                .execute(&mut connection)
                .await
                .expect("recover missing authority field fixture");
            sqlx::query("RELEASE SAVEPOINT missing_authority_field")
                .execute(&mut connection)
                .await
                .expect("release missing authority field fixture");
        }

        sqlx::query("SET LOCAL session_replication_role = 'origin'")
            .execute(&mut connection)
            .await
            .expect("restore origin trigger mode before fixture rollback");
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("discard request authority-version binding fixture");
        let replication_role: String = sqlx::query_scalar("SHOW session_replication_role")
            .fetch_one(&mut connection)
            .await
            .expect("read restored session replication role");
        assert_eq!(replication_role, "origin");
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
            super::ApplicationPoolSettings {
                max_connections: 1,
                min_connections: 1,
                idle_timeout_secs: 60,
                acquire_timeout_secs: 30,
                max_lifetime_secs: 300,
            },
            Some(application_contract),
            None,
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
