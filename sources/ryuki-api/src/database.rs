use chrono::{DateTime, Utc};
use ryuki_core::postgresql_infrastructure::{
    postgresql_session_binding_digest, PostgresqlSessionBinding, PostgresqlTlsChannelBinding,
    VerifiedPostgresqlInfrastructureAttestation,
};
use ryuki_core::security_profile::{
    postgresql_database_identity_digest, postgresql_migration_inventory_digest,
    postgresql_storage_binding_digest, PostgresqlDatabaseIdentity, PostgresqlMigrationInventoryRow,
    PostgresqlStorageBinding, ProductionDatabaseProvider, RuntimeGuardDigestError,
    RuntimeGuardExpectedValue,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::env::VarError;
use std::fmt;
use std::net::IpAddr;
use std::path::{Component, Path};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use url::{Host, Url};

use crate::postgresql_tls_channel::ProductionPostgresqlTarget;

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
const REVIEWED_PRODUCTION_MIGRATION_STATEMENT_TIMEOUT_SECS: u64 = 180;
const REVIEWED_PRODUCTION_MIGRATION_LOCK_TIMEOUT_SECS: u64 = 30;

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

    /// Construct the migration-session role contract from the authenticated
    /// DurablePostgresql runtime-guard expectation. Production callers must
    /// use this seam instead of granting ambient role-name environment values
    /// authority over the migration session.
    pub(crate) fn from_receipt_bound_roles(
        migration_role: &str,
        application_role: &str,
    ) -> Result<Self, String> {
        Self::from_values(migration_role.to_owned(), application_role.to_owned())
    }

    /// Environment role names are deployment wiring only. When supplied for
    /// compatibility with an existing manifest they must agree exactly with
    /// the receipt-bound roles; a partial or conflicting pair fails closed.
    pub(crate) fn validate_optional_environment_consistency(&self) -> Result<(), String> {
        let migration = std::env::var("RYUKI_MIGRATION_EXPECTED_ROLE").ok();
        let application = std::env::var("RYUKI_APPLICATION_DATABASE_ROLE").ok();
        match (migration, application) {
            (None, None) => Ok(()),
            (Some(migration), Some(application)) => {
                let configured = Self::from_values(migration, application)?;
                if configured == *self {
                    Ok(())
                } else {
                    Err(
                        "migration role environment wiring differs from the receipt-bound production roles"
                            .into(),
                    )
                }
            }
            _ => Err(
                "production migration role environment wiring must supply both role names or neither"
                    .into(),
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn matches_receipt_bound_roles(
        &self,
        migration_role: &str,
        application_role: &str,
    ) -> bool {
        self.expected == migration_role && self.application == application_role
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
    // Completion witnesses are written only by the one-shot migration role.
    // The serving role may inspect them for operations, but can never create,
    // mutate, or delete a witness.
    TablePolicy::new("production_migration_operations", false, false, false),
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
    TablePolicy::new("site_status", true, true, false),
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

/// Parse the production migration target without accepting libpq-style target
/// overrides. The signed infrastructure exchange proves the live target, but
/// the connection bootstrap must independently exclude Unix sockets, literal
/// IP targets, opportunistic TLS, and implicit database selection before any
/// network connection is attempted.
fn percent_decode_url_component(raw: &str, label: &str) -> Result<String, String> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(format!(
                "production migration URL {label} has invalid percent encoding"
            ));
        }
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = hex(bytes[index + 1]).ok_or_else(|| {
            format!("production migration URL {label} has invalid percent encoding")
        })?;
        let low = hex(bytes[index + 2]).ok_or_else(|| {
            format!("production migration URL {label} has invalid percent encoding")
        })?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    let decoded = String::from_utf8(decoded)
        .map_err(|_| format!("production migration URL {label} is not UTF-8"))?;
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        return Err(format!(
            "production migration URL {label} is empty or contains control characters"
        ));
    }
    Ok(decoded)
}

fn canonical_absolute_certificate_path(raw: &str) -> bool {
    let path = Path::new(raw);
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && components.clone().next().is_some()
        && components.all(|component| matches!(component, Component::Normal(_)))
}

fn production_migration_target(raw_url: &str) -> Result<ProductionPostgresqlTarget, String> {
    if raw_url.is_empty()
        || raw_url.len() > 8192
        || raw_url != raw_url.trim()
        || raw_url.chars().any(char::is_control)
    {
        return Err(
            "production migration database URL is empty, oversized, or noncanonical".into(),
        );
    }
    let parsed = Url::parse(raw_url)
        .map_err(|_| "production migration database URL could not be parsed".to_owned())?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.cannot_be_a_base()
        || parsed.fragment().is_some()
    {
        return Err(
            "production migration database URL must be a hierarchical PostgreSQL URL without a fragment"
                .into(),
        );
    }

    let hostname = match parsed.host() {
        Some(Host::Domain(hostname)) => hostname,
        _ => {
            return Err(
                "production migration database URL must use a TCP DNS hostname, not an IP literal or Unix socket"
                    .into(),
            )
        }
    };
    let hostname_is_canonical = hostname.parse::<IpAddr>().is_err()
        && !hostname.is_empty()
        && hostname.len() <= 253
        && !hostname.ends_with('.')
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if !hostname_is_canonical {
        return Err("production migration database hostname is not canonical DNS".into());
    }
    let username = canonical_database_role_name(
        "production migration URL username",
        percent_decode_url_component(parsed.username(), "username")?,
    )?;
    let password = /* secret-scan-allow: reviewed runtime URL credential */ percent_decode_url_component(
        parsed.password().ok_or_else(|| {
            "production migration database URL must carry an explicit password".to_owned()
        })?,
        "password",
    )?;
    if password.len() > 4096 {
        return Err("production migration database URL password is oversized".into());
    }
    let port = parsed.port().filter(|port| *port != 0).ok_or_else(|| {
        "production migration database URL must carry an explicit nonzero TCP port".to_owned()
    })?;
    let database_segments = parsed
        .path_segments()
        .ok_or_else(|| {
            "production migration database URL must name an explicit database".to_owned()
        })?
        .collect::<Vec<_>>();
    if database_segments.len() != 1 || database_segments[0].is_empty() {
        return Err(
            "production migration database URL must contain one explicit canonical database path segment"
                .into(),
        );
    }
    let database = canonical_database_role_name(
        "production migration URL database",
        percent_decode_url_component(database_segments[0], "database")?,
    )?;
    if database == "postgres" {
        return Err("the postgres maintenance database is not a migration target".into());
    }

    let mut ssl_mode = None;
    let mut ssl_root_cert = None;
    let mut seen = BTreeSet::new();
    for (key, value) in parsed.query_pairs() {
        if !seen.insert(key.to_string()) {
            return Err("production migration database URL repeats a parameter".into());
        }
        match key.as_ref() {
            "sslmode" => ssl_mode = Some(value.into_owned()),
            "sslrootcert" => ssl_root_cert = Some(value.into_owned()),
            _ => {
                return Err(
                    "production migration database URL contains a parameter that is not permitted"
                        .into(),
                );
            }
        }
    }
    if ssl_mode.as_deref() != Some("verify-full") {
        return Err("production migration database URL must set sslmode=verify-full".into());
    }
    let ssl_root_cert = ssl_root_cert.ok_or_else(|| {
        "production migration database URL must set an explicit sslrootcert".to_owned()
    })?;
    if !canonical_absolute_certificate_path(&ssl_root_cert)
        || ssl_root_cert.len() > 4096
        || ssl_root_cert.chars().any(char::is_control)
    {
        return Err(
            "production migration database sslrootcert must be a canonical absolute path".into(),
        );
    }

    // The app-owned TLS channel ignores libpq target variables entirely. The
    // remaining variables could otherwise imply a client certificate or
    // server-side option outside the closed direct-session profile.
    for ambient in ["PGOPTIONS", "PGSSLCERT", "PGSSLKEY"] {
        if std::env::var_os(ambient).is_some() {
            return Err(
                "ambient PostgreSQL options or client-certificate variables are prohibited for production migrations"
                    .into(),
            );
        }
    }
    ProductionPostgresqlTarget::new(
        hostname.to_owned(),
        port,
        username,
        password,
        database,
        Path::new(&ssl_root_cert).to_path_buf(),
    )
    .map_err(|error| error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationInventory {
    pub embedded_count: usize,
    pub latest_version: Option<i64>,
    /// Canonical `ryuki-postgresql-migration-inventory-v1` digest of the
    /// exact ordered version/checksum rows read back after verification.
    pub content_digest: String,
    pub(crate) production_attestation:
        Option<crate::security_contracts::ProductionMigrationCompletionEvidence>,
    pub(crate) production_operation: Option<ProductionMigrationOperationReceipt>,
}

/// Non-secret operation projection returned only after a confirmed commit or
/// an independently attested readback of a previously committed marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionMigrationOperationReceipt {
    operation_id: String,
    reconciled_after_prior_attempt: bool,
}

impl ProductionMigrationOperationReceipt {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn reconciled_after_prior_attempt(&self) -> bool {
        self.reconciled_after_prior_attempt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProductionMigrationOperationMarker {
    operation_id: String,
    release_binding_digest: String,
    target_binding_digest: String,
    migration_inventory_digest: String,
    attestation_response_digest: String,
    session_binding_digest: String,
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

/// Independently authenticated infrastructure evidence needed by the local
/// half of the `DurablePostgresql` guard.
///
/// There is deliberately no data-only implementation or constructor in this
/// module. An implementation must retain the exact signed/provider-attested
/// authority from which these fields were obtained and revalidate that
/// authority in `verify_integrity`. Copying values out of the runtime-guard
/// expectation is not an observation and must never implement this contract.
/// The database verifier supplies every SQL-observable identity field itself;
/// this seam supplies only facts that the least-privilege application role
/// cannot safely observe.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait VerifiedPostgresqlInfrastructureEvidence: Send + Sync {
    fn verify_integrity(&self) -> Result<(), String>;
    fn deployment_id(&self) -> &str;
    fn trust_domain_id(&self) -> &str;
    fn database_provider(&self) -> ProductionDatabaseProvider;
    fn attestation_profile_id(&self) -> &str;
    fn attestation_profile_version(&self) -> u64;
    fn attestation_profile_digest(&self) -> &str;
    fn provider_route_binding_digest(&self) -> &str;
    fn cluster_system_identifier(&self) -> &str;
    fn storage_bindings(&self) -> &[PostgresqlStorageBinding];
}

impl VerifiedPostgresqlInfrastructureEvidence for VerifiedPostgresqlInfrastructureAttestation {
    fn verify_integrity(&self) -> Result<(), String> {
        VerifiedPostgresqlInfrastructureAttestation::verify_integrity(self)
            .map_err(|error| error.to_string())
    }

    fn deployment_id(&self) -> &str {
        VerifiedPostgresqlInfrastructureAttestation::deployment_id(self)
    }

    fn trust_domain_id(&self) -> &str {
        VerifiedPostgresqlInfrastructureAttestation::trust_domain_id(self)
    }

    fn database_provider(&self) -> ProductionDatabaseProvider {
        VerifiedPostgresqlInfrastructureAttestation::database_provider(self)
    }

    fn attestation_profile_id(&self) -> &str {
        VerifiedPostgresqlInfrastructureAttestation::attestation_profile_id(self)
    }

    fn attestation_profile_version(&self) -> u64 {
        VerifiedPostgresqlInfrastructureAttestation::attestation_profile_version(self)
    }

    fn attestation_profile_digest(&self) -> &str {
        VerifiedPostgresqlInfrastructureAttestation::attestation_profile_digest(self)
    }

    fn provider_route_binding_digest(&self) -> &str {
        VerifiedPostgresqlInfrastructureAttestation::provider_route_binding_digest(self)
    }

    fn cluster_system_identifier(&self) -> &str {
        &VerifiedPostgresqlInfrastructureAttestation::database_identity(self)
            .cluster_system_identifier
    }

    fn storage_bindings(&self) -> &[PostgresqlStorageBinding] {
        VerifiedPostgresqlInfrastructureAttestation::storage_bindings(self)
    }
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum DurablePostgresqlRuntimeVerificationError {
    #[error("DurablePostgresql verification requires an unpublished database runtime")]
    RuntimeAlreadyPublished,
    #[error("DurablePostgresql verification received the wrong runtime-guard expectation kind")]
    ExpectedGuardKind,
    #[error("authenticated PostgreSQL infrastructure evidence failed integrity verification")]
    InfrastructureEvidenceInvalid,
    #[error("the local PostgreSQL migration inventory contains an invalid version")]
    InvalidMigrationVersion,
    #[error("the measured DurablePostgresql value does not equal the receipt-bound expectation")]
    ExpectedValueMismatch,
    #[error(transparent)]
    DigestProjection(#[from] RuntimeGuardDigestError),
    #[error(transparent)]
    RuntimeObservation(#[from] PostgresqlRuntimeObservationError),
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

/// The verified local half of the `DurablePostgresql` runtime guard.
///
/// This handle retains the exact unpublished pool, its connection-binding
/// authority, and the independently authenticated infrastructure evidence used
/// for the comparison. It is intentionally not `Clone`: the runtime-guard
/// witness should own this nominal proof while callers use `runtime()` only to
/// prove that publication consumes the same retained allocation.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct VerifiedLocalDurablePostgresqlRuntime {
    runtime: RetainedPostgresqlRuntime,
    infrastructure_evidence: Arc<dyn VerifiedPostgresqlInfrastructureEvidence>,
    observed_value: RuntimeGuardExpectedValue,
}

impl fmt::Debug for VerifiedLocalDurablePostgresqlRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLocalDurablePostgresqlRuntime")
            .field("contract", &"verified-local-durable-postgresql-v1")
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl VerifiedLocalDurablePostgresqlRuntime {
    pub(crate) fn runtime(&self) -> &RetainedPostgresqlRuntime {
        &self.runtime
    }

    pub(crate) fn observed_value(&self) -> &RuntimeGuardExpectedValue {
        &self.observed_value
    }

    fn recheck_retained_projection(&self) -> Result<(), DurablePostgresqlRuntimeVerificationError> {
        if self.infrastructure_evidence.verify_integrity().is_err() {
            return Err(DurablePostgresqlRuntimeVerificationError::InfrastructureEvidenceInvalid);
        }
        let current = measured_durable_postgresql_value(
            &self.runtime,
            self.infrastructure_evidence.as_ref(),
        )?;
        if current != self.observed_value {
            return Err(DurablePostgresqlRuntimeVerificationError::ExpectedValueMismatch);
        }
        // An evidence implementation may re-hash retained bytes here. Check it
        // on both sides of the projection so mutable or replaced authority
        // cannot splice one comparison from two evidence states.
        if self.infrastructure_evidence.verify_integrity().is_err() {
            return Err(DurablePostgresqlRuntimeVerificationError::InfrastructureEvidenceInvalid);
        }
        Ok(())
    }

    /// Remeasure every SQL-visible fact through the exact retained pool, then
    /// revalidate the retained infrastructure authority and all three digest
    /// projections against the value sealed during initial verification.
    pub(crate) async fn remeasure_exact(
        &self,
    ) -> Result<(), DurablePostgresqlRuntimeVerificationError> {
        self.runtime.remeasure_exact().await?;
        self.recheck_retained_projection()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn measured_postgresql_migration_inventory(
    observation: &PostgresqlRuntimeObservation,
) -> Result<Box<[PostgresqlMigrationInventoryRow]>, DurablePostgresqlRuntimeVerificationError> {
    observation
        .migration_ledger()
        .iter()
        .map(|row| {
            let version = u64::try_from(row.version())
                .ok()
                .filter(|version| *version != 0)
                .ok_or(DurablePostgresqlRuntimeVerificationError::InvalidMigrationVersion)?;
            Ok(PostgresqlMigrationInventoryRow {
                version,
                checksum_digest: format!("sha256:{:x}", Sha256::digest(row.checksum())),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

#[cfg_attr(not(test), allow(dead_code))]
fn measured_durable_postgresql_value(
    runtime: &RetainedPostgresqlRuntime,
    infrastructure_evidence: &dyn VerifiedPostgresqlInfrastructureEvidence,
) -> Result<RuntimeGuardExpectedValue, DurablePostgresqlRuntimeVerificationError> {
    let observation = runtime.observation();
    let identity = PostgresqlDatabaseIdentity {
        deployment_id: infrastructure_evidence.deployment_id().to_owned(),
        trust_domain_id: infrastructure_evidence.trust_domain_id().to_owned(),
        database_provider: infrastructure_evidence.database_provider(),
        database_name: observation.database_name().to_owned(),
        database_oid: observation.database_oid(),
        cluster_system_identifier: infrastructure_evidence
            .cluster_system_identifier()
            .to_owned(),
        server_address: observation.server_address().to_string(),
        server_port: observation.server_port(),
        tls_enabled: true,
        // PostgreSQL reports the standard protocol and cipher spellings in
        // uppercase. The core digest contracts deliberately use canonical
        // lowercase runtime identifiers, so normalize only that spelling.
        tls_protocol: observation.tls().protocol().to_ascii_lowercase(),
        tls_cipher_suite: observation.tls().cipher().to_ascii_lowercase(),
        tls_cipher_bits: observation.tls().bits(),
        server_major_version: observation.server_major_version(),
        primary: observation.is_primary(),
        writable: observation.is_transaction_writable()
            && observation.is_default_transaction_writable(),
    };
    let migrations = measured_postgresql_migration_inventory(observation)?;
    Ok(RuntimeGuardExpectedValue::DurablePostgresql {
        database_provider: infrastructure_evidence.database_provider(),
        server_major_version: observation.server_major_version(),
        attestation_profile_id: infrastructure_evidence.attestation_profile_id().to_owned(),
        attestation_profile_version: infrastructure_evidence.attestation_profile_version(),
        attestation_profile_digest: infrastructure_evidence
            .attestation_profile_digest()
            .to_owned(),
        provider_route_binding_digest: infrastructure_evidence
            .provider_route_binding_digest()
            .to_owned(),
        database_identity_digest: postgresql_database_identity_digest(&identity)?,
        storage_binding_digest: postgresql_storage_binding_digest(
            infrastructure_evidence.storage_bindings(),
        )?,
        migration_inventory_digest: postgresql_migration_inventory_digest(&migrations)?,
        application_role: observation.application_role().to_owned(),
        migration_role: observation.migration_role().to_owned(),
    })
}

/// Verify the exact local PostgreSQL observation against one closed receipt
/// expectation without deriving any observed field from that expectation.
///
/// The caller must supply a provider-attested evidence object and the still
/// unpublished runtime. The returned nominal handle owns both authorities and
/// is suitable for retention by the higher-level runtime-guard witness.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_local_durable_postgresql_runtime(
    unpublished: &UnpublishedPostgresqlRuntime,
    infrastructure_evidence: Arc<dyn VerifiedPostgresqlInfrastructureEvidence>,
    expected_value: &RuntimeGuardExpectedValue,
) -> Result<VerifiedLocalDurablePostgresqlRuntime, DurablePostgresqlRuntimeVerificationError> {
    if !unpublished.is_unpublished() {
        return Err(DurablePostgresqlRuntimeVerificationError::RuntimeAlreadyPublished);
    }
    if !matches!(
        expected_value,
        RuntimeGuardExpectedValue::DurablePostgresql { .. }
    ) {
        return Err(DurablePostgresqlRuntimeVerificationError::ExpectedGuardKind);
    }
    if infrastructure_evidence.verify_integrity().is_err() {
        return Err(DurablePostgresqlRuntimeVerificationError::InfrastructureEvidenceInvalid);
    }
    let runtime = unpublished.retained_handle();
    let observed_value =
        measured_durable_postgresql_value(&runtime, infrastructure_evidence.as_ref())?;
    if &observed_value != expected_value {
        return Err(DurablePostgresqlRuntimeVerificationError::ExpectedValueMismatch);
    }
    if infrastructure_evidence.verify_integrity().is_err() {
        return Err(DurablePostgresqlRuntimeVerificationError::InfrastructureEvidenceInvalid);
    }
    let verified = VerifiedLocalDurablePostgresqlRuntime {
        runtime,
        infrastructure_evidence,
        observed_value,
    };
    verified.recheck_retained_projection()?;
    Ok(verified)
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
    #[error("applied migration {0} is not a contiguous embedded migration prefix")]
    NonPrefixApplied(i64),
    #[error("embedded migrations are not applied: {0:?}")]
    Missing(Vec<i64>),
    #[error("migration inventory digest projection is invalid: {0}")]
    Digest(#[from] RuntimeGuardDigestError),
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationRunError {
    #[error("migration admission was rejected: {0}")]
    Admission(String),
    #[error("production migration target was rejected before connection: {0}")]
    Target(String),
    #[error("production migration pre-DDL verification failed: {0}")]
    Preflight(String),
    #[error("dedicated migration database connection failed: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("embedded migration execution failed: {0}")]
    Apply(#[source] sqlx::migrate::MigrateError),
    #[error("atomic production migration {version} failed: {source}")]
    AtomicApply {
        version: i64,
        #[source]
        source: sqlx::Error,
    },
    #[error("application database privileges could not be reconciled: {0}")]
    Privileges(#[source] sqlx::Error),
    #[error(
        "production migration COMMIT outcome is unknown for operation {operation_id} ({reason}); do not retry DDL blindly -- a fresh independently attested run must reconcile the exact durable operation marker and final inventory"
    )]
    CommitOutcomeUnknown {
        operation_id: String,
        reason: &'static str,
        #[source]
        source: Option<sqlx::Error>,
    },
    #[error(transparent)]
    Verify(#[from] MigrationVerificationError),
}

impl MigrationRunError {
    fn commit_outcome_unknown(&self) -> bool {
        matches!(self, Self::CommitOutcomeUnknown { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionMigrationFailureBoundary {
    BeforeCommitDispatch,
    CommitDispatched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionMigrationFailureDisposition {
    RollbackExpected,
    OutcomeUnknown,
}

const fn classify_production_migration_failure(
    boundary: ProductionMigrationFailureBoundary,
) -> ProductionMigrationFailureDisposition {
    match boundary {
        ProductionMigrationFailureBoundary::BeforeCommitDispatch => {
            ProductionMigrationFailureDisposition::RollbackExpected
        }
        ProductionMigrationFailureBoundary::CommitDispatched => {
            ProductionMigrationFailureDisposition::OutcomeUnknown
        }
    }
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

fn migration_inventory_content_digest(
    rows: &[(i64, Vec<u8>)],
) -> Result<String, MigrationVerificationError> {
    let projection = rows
        .iter()
        .map(|(version, checksum)| {
            let version = u64::try_from(*version)
                .ok()
                .filter(|version| *version != 0)
                .ok_or(RuntimeGuardDigestError::InvalidProjection(
                    "postgresql migration inventory",
                ))?;
            Ok(PostgresqlMigrationInventoryRow {
                version,
                checksum_digest: format!("sha256:{:x}", Sha256::digest(checksum)),
            })
        })
        .collect::<Result<Vec<_>, RuntimeGuardDigestError>>()?;
    postgresql_migration_inventory_digest(&projection).map_err(Into::into)
}

pub(crate) fn embedded_migration_inventory_digest() -> Result<String, MigrationVerificationError> {
    let rows = expected_embedded_migrations()
        .into_iter()
        .map(|(version, checksum)| (version, checksum.to_vec()))
        .collect::<Vec<_>>();
    migration_inventory_content_digest(&rows)
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
        content_digest: migration_inventory_content_digest(applied)?,
        production_attestation: None,
        production_operation: None,
    })
}

/// Validate the ledger before production DDL. A fresh database may have no
/// ledger yet, and a previously migrated database may contain any contiguous
/// prefix of the exact embedded inventory. Dirty, unknown, reordered, skipped,
/// or checksum-substituted rows all fail before the atomic embedded migrator
/// can create or alter an object.
fn verify_preflight_migration_inventory(
    rows: &[(i64, Vec<u8>, bool)],
) -> Result<(), MigrationVerificationError> {
    if let Some((version, _, _)) = rows.iter().find(|(_, _, success)| !success) {
        return Err(MigrationVerificationError::Dirty(*version));
    }
    let expected = expected_embedded_migrations();
    let mut expected_rows = expected.iter();
    let mut previous = None;
    for (version, checksum, _) in rows {
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
        let Some((expected_version, expected_checksum)) = expected_rows.next() else {
            return Err(MigrationVerificationError::UnexpectedApplied(*version));
        };
        if version != expected_version {
            return if expected.contains_key(version) {
                Err(MigrationVerificationError::NonPrefixApplied(*version))
            } else {
                Err(MigrationVerificationError::UnexpectedApplied(*version))
            };
        }
        if checksum.as_slice() != *expected_checksum {
            return Err(MigrationVerificationError::ChecksumMismatch(*version));
        }
        previous = Some(*version);
    }
    Ok(())
}

async fn read_preflight_migration_ledger(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<Vec<(i64, Vec<u8>, bool)>, MigrationVerificationError> {
    let ledger_exists: bool =
        sqlx::query_scalar("SELECT pg_catalog.to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await
            .map_err(MigrationVerificationError::Metadata)?;
    if !ledger_exists {
        return Ok(Vec::new());
    }
    attest_sqlx_migrations_table(connection, migration_role).await?;
    sqlx::query_as(
        "SELECT version, checksum, success FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(MigrationVerificationError::Metadata)
}

async fn attest_sqlx_migrations_table(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<(), MigrationVerificationError> {
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH migration AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        ledger AS (
            SELECT class.*
            FROM pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = class.relnamespace
            WHERE namespace.nspname = 'public'
              AND class.relname = '_sqlx_migrations'
        ),
        expected_columns(name, type_name, not_null, default_expression) AS (
            VALUES
                ('version'::text, 'bigint'::text, TRUE, NULL::text),
                ('description'::text, 'text'::text, TRUE, NULL::text),
                ('installed_on'::text, 'timestamp with time zone'::text, TRUE, 'now()'::text),
                ('success'::text, 'boolean'::text, TRUE, NULL::text),
                ('checksum'::text, 'bytea'::text, TRUE, NULL::text),
                ('execution_time'::text, 'bigint'::text, TRUE, NULL::text)
        ),
        actual_columns AS (
            SELECT attribute.attname::text AS name,
                   pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                       AS type_name,
                   attribute.attnotnull AS not_null,
                   pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid)
                       AS default_expression,
                   attribute.attidentity,
                   attribute.attgenerated
            FROM ledger
            JOIN pg_catalog.pg_attribute AS attribute
              ON attribute.attrelid = ledger.oid
             AND attribute.attnum > 0
             AND NOT attribute.attisdropped
            LEFT JOIN pg_catalog.pg_attrdef AS default_value
              ON default_value.adrelid = attribute.attrelid
             AND default_value.adnum = attribute.attnum
        ),
        primary_key AS (
            SELECT constraint.*
            FROM ledger
            JOIN pg_catalog.pg_constraint AS constraint
              ON constraint.conrelid = ledger.oid
             AND constraint.contype = 'p'
        )
        SELECT COALESCE((
            SELECT ledger.relkind = 'r'
               AND ledger.relpersistence = 'p'
               AND NOT ledger.relispartition
               AND NOT ledger.relrowsecurity
               AND NOT ledger.relforcerowsecurity
               AND ledger.relreplident = 'd'
               AND ledger.relowner = migration.oid
               AND ledger.relam = (
                    SELECT access_method.oid
                    FROM pg_catalog.pg_am AS access_method
                    WHERE access_method.amname = 'heap'
               )
               AND (SELECT count(*) FROM actual_columns) = 6
               AND NOT EXISTS (
                    SELECT 1
                    FROM expected_columns
                    FULL JOIN actual_columns USING (name)
                    WHERE expected_columns.name IS NULL
                       OR actual_columns.name IS NULL
                       OR expected_columns.type_name <> actual_columns.type_name
                       OR expected_columns.not_null <> actual_columns.not_null
                       OR expected_columns.default_expression
                            IS DISTINCT FROM actual_columns.default_expression
                       OR actual_columns.attidentity <> ''
                       OR actual_columns.attgenerated <> ''
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_attribute AS attribute
                    WHERE attribute.attrelid = ledger.oid
                      AND attribute.attnum > 0
                      AND attribute.attisdropped
               )
               AND (SELECT count(*) FROM primary_key) = 1
               AND (SELECT conkey FROM primary_key) = ARRAY[
                    (
                        SELECT attribute.attnum
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = ledger.oid
                          AND attribute.attname = 'version'
                    )
               ]::smallint[]
               AND NOT (SELECT condeferrable FROM primary_key)
               AND NOT (SELECT condeferred FROM primary_key)
               AND (SELECT convalidated FROM primary_key)
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_constraint AS constraint
                    WHERE constraint.conrelid = ledger.oid
                      AND constraint.contype <> 'p'
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_trigger AS trigger
                    WHERE trigger.tgrelid = ledger.oid
                      AND NOT trigger.tgisinternal
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_policy AS policy
                    WHERE policy.polrelid = ledger.oid
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_inherits AS inheritance
                    WHERE inheritance.inhrelid = ledger.oid
                       OR inheritance.inhparent = ledger.oid
               )
            FROM ledger
            CROSS JOIN migration
        ), FALSE)
        "#,
    )
    .bind(migration_role)
    .fetch_one(&mut *connection)
    .await
    .map_err(MigrationVerificationError::Metadata)?;
    if !exact {
        return Err(MigrationVerificationError::Metadata(role_protocol_error(
            "public._sqlx_migrations is not the exact owned SQLx ledger table",
        )));
    }
    Ok(())
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

/// SQL-visible identity of the exact, direct migration backend. Every field is
/// read from one joined catalog row for `pg_backend_pid()`, then projected into
/// the closed core preimage that the independent infrastructure authority must
/// sign. The raw form keeps fallible PostgreSQL integer/NULL values out of the
/// trusted type until local validation succeeds.
struct RawPostgresqlMigrationSessionBinding {
    server_version_num: i32,
    database_name: String,
    database_oid: i64,
    datid: Option<i64>,
    server_address: Option<String>,
    server_port: Option<i32>,
    primary: bool,
    transaction_writable: bool,
    default_transaction_writable: bool,
    client_address: Option<String>,
    client_port: Option<i32>,
    backend_process_id: i32,
    backend_start: DateTime<Utc>,
    backend_type: String,
    application_name: String,
    session_login_role: String,
    session_user_oid: Option<i64>,
    current_role: String,
    selected_role: String,
    tls_enabled: Option<bool>,
    tls_protocol: Option<String>,
    tls_cipher: Option<String>,
    tls_bits: Option<i32>,
    client_distinguished_name: Option<String>,
    issuer_distinguished_name: Option<String>,
}

fn migration_session_contract_error(message: impl Into<String>) -> String {
    format!(
        "production migration session contract was not proven: {}",
        message.into()
    )
}

fn validate_migration_optional_distinguished_name(
    label: &str,
    value: Option<String>,
) -> Result<Option<String>, String> {
    match value {
        Some(value)
            if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) =>
        {
            Err(migration_session_contract_error(format!(
                "TLS {label} is empty, oversized, or contains control characters"
            )))
        }
        value => Ok(value),
    }
}

fn validate_postgresql_migration_session_binding(
    raw: RawPostgresqlMigrationSessionBinding,
    application_name: &str,
    contract: &MigrationRoleContract,
    tls_channel_binding: &PostgresqlTlsChannelBinding,
) -> Result<PostgresqlSessionBinding, String> {
    let server_version_num = u32::try_from(raw.server_version_num).map_err(|_| {
        migration_session_contract_error("server_version_num is not a positive integer")
    })?;
    let server_major_version = u16::try_from(server_version_num / 10_000)
        .map_err(|_| migration_session_contract_error("server major version is out of range"))?;
    if server_major_version != REQUIRED_PRODUCTION_POSTGRESQL_MAJOR_VERSION {
        return Err(migration_session_contract_error(format!(
            "PostgreSQL major version must equal {REQUIRED_PRODUCTION_POSTGRESQL_MAJOR_VERSION}"
        )));
    }
    canonical_database_role_name("database_name", raw.database_name.clone())
        .map_err(migration_session_contract_error)?;
    if raw.database_name == "postgres" {
        return Err(migration_session_contract_error(
            "the administrative postgres database is not a production migration target",
        ));
    }
    let database_oid = u32::try_from(raw.database_oid)
        .ok()
        .filter(|oid| *oid != 0)
        .ok_or_else(|| migration_session_contract_error("current database OID is invalid"))?;
    let datid = raw
        .datid
        .and_then(|oid| u32::try_from(oid).ok())
        .filter(|oid| *oid != 0)
        .ok_or_else(|| migration_session_contract_error("backend datid is invalid"))?;
    if datid != database_oid {
        return Err(migration_session_contract_error(
            "backend datid does not equal the current database OID",
        ));
    }
    let server_address = raw
        .server_address
        .ok_or_else(|| migration_session_contract_error("TCP session has no server address"))?
        .parse::<IpAddr>()
        .map_err(|_| migration_session_contract_error("server address is not a canonical IP"))?;
    let server_address = server_address.to_string();
    let server_port = raw
        .server_port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| migration_session_contract_error("server port is invalid"))?;
    let client_address = raw
        .client_address
        .ok_or_else(|| migration_session_contract_error("TCP session has no client address"))?
        .parse::<IpAddr>()
        .map_err(|_| migration_session_contract_error("client address is not a canonical IP"))?;
    let client_address = client_address.to_string();
    let client_port = raw
        .client_port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| migration_session_contract_error("client port is invalid"))?;
    let backend_process_id = u32::try_from(raw.backend_process_id)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| migration_session_contract_error("backend process ID is invalid"))?;
    if raw.backend_type != "client backend" {
        return Err(migration_session_contract_error(
            "backend_type is not client backend",
        ));
    }
    if raw.application_name != application_name {
        return Err(migration_session_contract_error(
            "live application_name does not equal the nonce-derived request tag",
        ));
    }
    if raw.current_role != contract.expected || raw.selected_role != contract.expected {
        return Err(migration_session_contract_error(
            "current and selected roles do not equal the receipt-bound migration role",
        ));
    }
    canonical_database_role_name("session_login_role", raw.session_login_role.clone())
        .map_err(migration_session_contract_error)?;
    if raw.session_login_role == contract.expected
        || raw.session_login_role == contract.application
        || raw.session_login_role == "postgres"
    {
        return Err(migration_session_contract_error(
            "session login role is not distinct from stable production roles",
        ));
    }
    let session_user_oid = raw
        .session_user_oid
        .and_then(|oid| u32::try_from(oid).ok())
        .filter(|oid| *oid != 0)
        .ok_or_else(|| migration_session_contract_error("backend usesysid is invalid"))?;
    if !raw.primary || !raw.transaction_writable || !raw.default_transaction_writable {
        return Err(migration_session_contract_error(
            "database must be a primary with current and default transactions writable",
        ));
    }
    if raw.tls_enabled != Some(true) {
        return Err(migration_session_contract_error(
            "database transport is not an observed TLS session",
        ));
    }
    let tls_protocol = raw
        .tls_protocol
        .filter(|protocol| matches!(protocol.as_str(), "TLSv1.2" | "TLSv1.3"))
        .ok_or_else(|| migration_session_contract_error("TLS protocol must be 1.2 or 1.3"))?
        .to_ascii_lowercase();
    let tls_cipher_suite = raw
        .tls_cipher
        .filter(|cipher| {
            !cipher.is_empty() && cipher.len() <= 256 && !cipher.chars().any(char::is_control)
        })
        .ok_or_else(|| migration_session_contract_error("TLS cipher is missing or invalid"))?
        .to_ascii_lowercase();
    let tls_cipher_bits = raw
        .tls_bits
        .and_then(|bits| u16::try_from(bits).ok())
        .filter(|bits| *bits >= 128)
        .ok_or_else(|| migration_session_contract_error("TLS cipher strength is below 128 bits"))?;
    // Kubernetes Services and reviewed provider load balancers legitimately
    // expose an entry address that differs from PostgreSQL's backend address.
    // Both addresses are retained in the signed session/channel preimage; the
    // authority's endpoint-derived exporter proves they belong to this exact
    // TLS session. Requiring IP equality would reject ordinary DNAT while
    // adding no cryptographic binding.
    if tls_protocol != tls_channel_binding.tls_protocol
        || tls_cipher_suite != tls_channel_binding.tls_cipher_suite
        || tls_cipher_bits != tls_channel_binding.tls_cipher_bits
    {
        return Err(migration_session_contract_error(
            "SQL-visible TLS endpoint or cipher differs from the caller-observed direct channel",
        ));
    }

    Ok(PostgresqlSessionBinding {
        application_name: raw.application_name,
        database_name: raw.database_name,
        database_oid,
        datid,
        server_address,
        server_port,
        server_major_version,
        primary: raw.primary,
        transaction_writable: raw.transaction_writable,
        default_transaction_writable: raw.default_transaction_writable,
        client_address,
        client_port,
        backend_process_id,
        backend_start: raw.backend_start,
        backend_type: raw.backend_type,
        session_login_role: raw.session_login_role,
        session_user_oid,
        current_role: raw.current_role,
        selected_role: raw.selected_role,
        tls_enabled: true,
        tls_protocol,
        tls_cipher_suite,
        tls_cipher_bits,
        client_distinguished_name: validate_migration_optional_distinguished_name(
            "client distinguished name",
            raw.client_distinguished_name,
        )?,
        issuer_distinguished_name: validate_migration_optional_distinguished_name(
            "issuer distinguished name",
            raw.issuer_distinguished_name,
        )?,
        tls_channel_binding: tls_channel_binding.clone(),
    })
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

async fn read_postgresql_migration_session_binding(
    connection: &mut PgConnection,
    application_name: &str,
    contract: &MigrationRoleContract,
    tls_channel_binding: &PostgresqlTlsChannelBinding,
) -> Result<PostgresqlSessionBinding, String> {
    let row = sqlx::query(
        r#"
            SELECT
                pg_catalog.current_setting('server_version_num')::integer
                    AS server_version_num,
                pg_catalog.current_database()::text AS database_name,
                database.oid::bigint AS database_oid,
                activity.datid::bigint AS datid,
                pg_catalog.inet_server_addr()::text AS server_address,
                pg_catalog.inet_server_port() AS server_port,
                NOT pg_catalog.pg_is_in_recovery() AS is_primary,
                NOT pg_catalog.current_setting('transaction_read_only')::boolean
                    AS transaction_writable,
                NOT pg_catalog.current_setting('default_transaction_read_only')::boolean
                    AS default_transaction_writable,
                activity.client_addr::text AS client_address,
                activity.client_port AS client_port,
                activity.pid AS backend_process_id,
                activity.backend_start AS backend_start,
                activity.backend_type AS backend_type,
                activity.application_name AS application_name,
                session_user::text AS session_login_role,
                activity.usesysid::bigint AS session_user_oid,
                current_user::text AS current_role,
                pg_catalog.current_setting('role') AS selected_role,
                tls.ssl AS tls_enabled,
                tls.version AS tls_protocol,
                tls.cipher AS tls_cipher,
                tls.bits AS tls_bits,
                tls.client_dn AS client_distinguished_name,
                tls.issuer_dn AS issuer_distinguished_name
            FROM pg_catalog.pg_database AS database
            JOIN pg_catalog.pg_stat_activity AS activity
              ON activity.pid = pg_catalog.pg_backend_pid()
             AND activity.datid = database.oid
            LEFT JOIN pg_catalog.pg_stat_ssl AS tls
              ON tls.pid = activity.pid
            WHERE database.datname = pg_catalog.current_database()
              AND activity.usesysid = (
                    SELECT role.oid
                    FROM pg_catalog.pg_roles AS role
                    WHERE role.rolname = session_user
              )
            "#,
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| {
        migration_session_contract_error(
            "exact pg_stat_activity/pg_stat_ssl backend row could not be read",
        )
    })?;
    let raw = RawPostgresqlMigrationSessionBinding {
        server_version_num: row
            .try_get("server_version_num")
            .map_err(|_| migration_session_contract_error("server_version_num is invalid"))?,
        database_name: row
            .try_get("database_name")
            .map_err(|_| migration_session_contract_error("database_name is invalid"))?,
        database_oid: row
            .try_get("database_oid")
            .map_err(|_| migration_session_contract_error("database_oid is invalid"))?,
        datid: row
            .try_get("datid")
            .map_err(|_| migration_session_contract_error("backend datid is invalid"))?,
        server_address: row
            .try_get("server_address")
            .map_err(|_| migration_session_contract_error("server_address is invalid"))?,
        server_port: row
            .try_get("server_port")
            .map_err(|_| migration_session_contract_error("server_port is invalid"))?,
        primary: row
            .try_get("is_primary")
            .map_err(|_| migration_session_contract_error("primary state is invalid"))?,
        transaction_writable: row
            .try_get("transaction_writable")
            .map_err(|_| migration_session_contract_error("transaction writability is invalid"))?,
        default_transaction_writable: row.try_get("default_transaction_writable").map_err(
            |_| migration_session_contract_error("default transaction writability is invalid"),
        )?,
        client_address: row
            .try_get("client_address")
            .map_err(|_| migration_session_contract_error("client_address is invalid"))?,
        client_port: row
            .try_get("client_port")
            .map_err(|_| migration_session_contract_error("client_port is invalid"))?,
        backend_process_id: row
            .try_get("backend_process_id")
            .map_err(|_| migration_session_contract_error("backend process ID is invalid"))?,
        backend_start: row
            .try_get("backend_start")
            .map_err(|_| migration_session_contract_error("backend start time is invalid"))?,
        backend_type: row
            .try_get("backend_type")
            .map_err(|_| migration_session_contract_error("backend_type is invalid"))?,
        application_name: row
            .try_get("application_name")
            .map_err(|_| migration_session_contract_error("application_name is invalid"))?,
        session_login_role: row
            .try_get("session_login_role")
            .map_err(|_| migration_session_contract_error("session login role is invalid"))?,
        session_user_oid: row
            .try_get("session_user_oid")
            .map_err(|_| migration_session_contract_error("session user OID is invalid"))?,
        current_role: row
            .try_get("current_role")
            .map_err(|_| migration_session_contract_error("current role is invalid"))?,
        selected_role: row
            .try_get("selected_role")
            .map_err(|_| migration_session_contract_error("selected role is invalid"))?,
        tls_enabled: row
            .try_get("tls_enabled")
            .map_err(|_| migration_session_contract_error("TLS state is invalid"))?,
        tls_protocol: row
            .try_get("tls_protocol")
            .map_err(|_| migration_session_contract_error("TLS protocol is invalid"))?,
        tls_cipher: row
            .try_get("tls_cipher")
            .map_err(|_| migration_session_contract_error("TLS cipher is invalid"))?,
        tls_bits: row
            .try_get("tls_bits")
            .map_err(|_| migration_session_contract_error("TLS cipher bits are invalid"))?,
        client_distinguished_name: row
            .try_get("client_distinguished_name")
            .map_err(|_| migration_session_contract_error("TLS client DN is invalid"))?,
        issuer_distinguished_name: row
            .try_get("issuer_distinguished_name")
            .map_err(|_| migration_session_contract_error("TLS issuer DN is invalid"))?,
    };
    validate_postgresql_migration_session_binding(
        raw,
        application_name,
        contract,
        tls_channel_binding,
    )
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

/// The runtime may directly invoke exactly three reviewed SECURITY DEFINER entry
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
                ('public.append_audit_log(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text)'::text),
                ('public.ryuki_acquire_live_site_execution_epoch(text)'::text)
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
                (SELECT count(*) FROM expected) = 3
                AND (SELECT count(*) FROM allowed) = 3
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
            "application routine privileges differ from the three reviewed entry-point policy",
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
/// exact request authority version selected by migration 196 and the live-site
/// epoch added by migration 198. These guards are part of the startup schema
/// contract: changing a target table, trigger event or column set, execution
/// mode, or function body must prevent the application connection from serving.
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
            function_source_sha256,
            security_definer,
            function_config
        ) AS (
            VALUES
                (
                    'request_approval_decisions'::text,
                    'trg_request_approval_decision_basis_version'::text,
                    'public.bind_request_approval_basis_resource_version()'::text,
                    7::smallint,
                    ARRAY[]::text[],
                    'e2579634b52772f8523057618254b0c000db9ad99026c7fd6f5ff1bd670b4822'::text,
                    FALSE,
                    NULL::text[]
                ),
                (
                    'request_approval_decisions'::text,
                    'trg_request_approval_decision_basis_version_owned'::text,
                    'public.reject_request_approval_basis_version_update()'::text,
                    19::smallint,
                    ARRAY['approval_basis_resource_version']::text[],
                    '7b412cf35870cd0ebc625e44758d279745553ae4783bc7920761a6c22522fe3f'::text,
                    FALSE,
                    NULL::text[]
                ),
                (
                    'agent_jobs'::text,
                    'trg_agent_jobs_request_resource_version'::text,
                    'public.bind_agent_job_request_resource_version()'::text,
                    7::smallint,
                    ARRAY[]::text[],
                    'd26216065dfbd4f9fcdc00a5a9cfd1d0422499863109a05fc4690c5413d59d58'::text,
                    FALSE,
                    NULL::text[]
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
                        'site_status_authority_epoch',
                        'origin',
                        'step_scoped',
                        'request_resource_version'
                    ]::text[],
                    '5b6979234abd8ad135cd5f7d4125c6e2b0444139ddf88a560951d2581376db19'::text,
                    FALSE,
                    NULL::text[]
                ),
                (
                    'agent_jobs'::text,
                    'trg_agent_jobs_live_site_fence_persistence'::text,
                    'public.ryuki_enforce_agent_job_live_site_fence_persistence()'::text,
                    23::smallint,
                    ARRAY['status']::text[],
                    'afee5fbdf388c235ffa652d9a5fd20b3bc83c0fa806e28763463094b35e6ae54'::text,
                    TRUE,
                    ARRAY['search_path=pg_catalog, public, pg_temp']::text[]
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
              AND procedure.prosecdef = expected.security_definer
              AND NOT procedure.proleakproof
              AND procedure.provolatile = 'v'
              AND procedure.proparallel = 'u'
              AND procedure.proconfig IS NOT DISTINCT FROM expected.function_config
              AND language.lanname = 'plpgsql'
              AND pg_catalog.encode(
                      pg_catalog.sha256(
                          pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                      ),
                      'hex'
                  ) = expected.function_source_sha256
        )
        SELECT (SELECT COUNT(*) FROM target_tables) = 2
           AND (SELECT COUNT(*) FROM resolved_expected) = 5
           AND (SELECT COUNT(*) FROM matching) = 5
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

/// Prove that the transaction-bound live-site authority fence still consumes
/// the exact registered freshness limit, retains its load-bearing columns and
/// constraints, and keeps every upstream observation, epoch-bump, and removal
/// guard attached to its canonical table as an ALWAYS trigger. The agent-job
/// persistence trigger is attested separately as part of the request
/// authority-version binding contract above.
async fn attest_live_site_execution_authority_chain(
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
                    'site_status',
                    'site_registry',
                    'component_status',
                    'agent_jobs'
                  )
              AND class.relkind = 'r'
        ),
        expected_authority_columns(
            table_name,
            column_name,
            type_name,
            not_null,
            default_expression
        ) AS (
            VALUES
                (
                    'site_status'::text,
                    'authority_epoch'::text,
                    'bigint'::text,
                    TRUE,
                    '1'::text
                ),
                (
                    'agent_jobs'::text,
                    'site_status_authority_epoch'::text,
                    'bigint'::text,
                    FALSE,
                    NULL::text
                )
        ),
        matching_authority_columns AS (
            SELECT expected.table_name,
                   expected.column_name
            FROM expected_authority_columns AS expected
            JOIN target_tables
              ON target_tables.table_name = expected.table_name
            JOIN pg_catalog.pg_attribute AS attribute
              ON attribute.attrelid = target_tables.oid
             AND attribute.attname = expected.column_name
             AND attribute.attnum > 0
             AND NOT attribute.attisdropped
            LEFT JOIN pg_catalog.pg_attrdef AS default_value
              ON default_value.adrelid = attribute.attrelid
             AND default_value.adnum = attribute.attnum
            WHERE pg_catalog.format_type(
                      attribute.atttypid,
                      attribute.atttypmod
                  ) = expected.type_name
              AND attribute.attnotnull = expected.not_null
              AND attribute.attidentity = ''
              AND attribute.attgenerated = ''
              AND LOWER(
                      pg_catalog.regexp_replace(
                          pg_catalog.regexp_replace(
                              pg_catalog.pg_get_expr(
                                  default_value.adbin,
                                  default_value.adrelid
                              ),
                              '::bigint',
                              '',
                              'g'
                          ),
                          '[[:space:]()]',
                          '',
                          'g'
                      )
                  ) IS NOT DISTINCT FROM expected.default_expression
        ),
        expected_checks(
            table_name,
            constraint_name,
            column_names,
            normalized_expression
        ) AS (
            VALUES
                (
                    'site_status'::text,
                    'site_status_authority_epoch_positive'::text,
                    ARRAY['authority_epoch']::text[],
                    'authority_epoch>0'::text
                ),
                (
                    'agent_jobs'::text,
                    'agent_jobs_site_status_authority_epoch_positive'::text,
                    ARRAY['site_status_authority_epoch']::text[],
                    'site_status_authority_epochISNULLORsite_status_authority_epoch>0'::text
                ),
                (
                    'agent_jobs'::text,
                    'agent_jobs_open_live_site_fence_required'::text,
                    ARRAY['mode', 'status', 'site_status_authority_epoch']::text[],
                    'mode<>ALLARRAY[''LiveApply'',''LiveDestroy'']ORstatus<>ALLARRAY[''Pending'',''Leased'',''Running'']ORsite_status_authority_epochISNOTNULL'::text
                )
        ),
        resolved_expected_checks AS (
            SELECT expected.*,
                   target_tables.oid AS table_oid,
                   resolved_columns.resolved_count,
                   resolved_columns.constraint_columns
            FROM expected_checks AS expected
            JOIN target_tables
              ON target_tables.table_name = expected.table_name
            CROSS JOIN LATERAL (
                SELECT COUNT(attribute.attnum)::integer AS resolved_count,
                       COALESCE(
                           pg_catalog.array_agg(
                               attribute.attnum::smallint
                               ORDER BY column_name.ordinality
                           ),
                           ARRAY[]::smallint[]
                       ) AS constraint_columns
                FROM pg_catalog.unnest(expected.column_names)
                     WITH ORDINALITY AS column_name(name, ordinality)
                JOIN pg_catalog.pg_attribute AS attribute
                  ON attribute.attrelid = target_tables.oid
                 AND attribute.attname = column_name.name
                 AND attribute.attnum > 0
                 AND NOT attribute.attisdropped
            ) AS resolved_columns
        ),
        matching_checks AS (
            SELECT expected.constraint_name
            FROM resolved_expected_checks AS expected
            JOIN pg_catalog.pg_constraint AS constraint_catalog
              ON constraint_catalog.conrelid = expected.table_oid
             AND constraint_catalog.conname = expected.constraint_name
            WHERE expected.resolved_count =
                      pg_catalog.cardinality(expected.column_names)
              AND constraint_catalog.contype = 'c'
              AND constraint_catalog.conkey = expected.constraint_columns
              AND constraint_catalog.conenforced
              AND constraint_catalog.convalidated
              AND NOT constraint_catalog.condeferrable
              AND NOT constraint_catalog.condeferred
              AND NOT constraint_catalog.connoinherit
              AND pg_catalog.regexp_replace(
                      pg_catalog.regexp_replace(
                          pg_catalog.pg_get_expr(
                              constraint_catalog.conbin,
                              constraint_catalog.conrelid
                          ),
                          '::(text|bigint)',
                          '',
                          'g'
                      ),
                      '[[:space:]()]',
                      '',
                      'g'
                  ) = expected.normalized_expression
        ),
        matching_site_registry_foreign_key AS (
            SELECT constraint_catalog.oid
            FROM target_tables AS site_status_table
            JOIN pg_catalog.pg_constraint AS constraint_catalog
              ON constraint_catalog.conrelid = site_status_table.oid
             AND constraint_catalog.conname = 'site_status_canonical_site_fk'
            JOIN target_tables AS site_registry_table
              ON site_registry_table.table_name = 'site_registry'
            WHERE site_status_table.table_name = 'site_status'
              AND constraint_catalog.contype = 'f'
              AND constraint_catalog.confrelid = site_registry_table.oid
              AND constraint_catalog.conkey = ARRAY[
                    (
                        SELECT attribute.attnum
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = site_status_table.oid
                          AND attribute.attname = 'site'
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                    )
                  ]::smallint[]
              AND constraint_catalog.confkey = ARRAY[
                    (
                        SELECT attribute.attnum
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = site_registry_table.oid
                          AND attribute.attname = 'unlocode'
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                    )
                  ]::smallint[]
              AND constraint_catalog.confmatchtype = 's'
              AND constraint_catalog.confupdtype = 'r'
              AND constraint_catalog.confdeltype = 'r'
              AND constraint_catalog.conenforced
              AND constraint_catalog.convalidated
              AND NOT constraint_catalog.condeferrable
              AND NOT constraint_catalog.condeferred
        ),
        matching_component_unique AS (
            SELECT constraint_catalog.oid
            FROM target_tables AS component_table
            JOIN pg_catalog.pg_constraint AS constraint_catalog
              ON constraint_catalog.conrelid = component_table.oid
             AND constraint_catalog.conname =
                    'component_status_one_adapter_per_site'
            JOIN pg_catalog.pg_index AS index_catalog
              ON index_catalog.indexrelid = constraint_catalog.conindid
             AND index_catalog.indrelid = component_table.oid
            WHERE component_table.table_name = 'component_status'
              AND constraint_catalog.contype = 'u'
              AND constraint_catalog.conkey = ARRAY[
                    (
                        SELECT attribute.attnum
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = component_table.oid
                          AND attribute.attname = 'site'
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                    ),
                    (
                        SELECT attribute.attnum
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = component_table.oid
                          AND attribute.attname = 'adapter_name'
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                    )
                  ]::smallint[]
              AND constraint_catalog.conenforced
              AND constraint_catalog.convalidated
              AND NOT constraint_catalog.condeferrable
              AND NOT constraint_catalog.condeferred
              AND index_catalog.indisunique
              AND index_catalog.indisvalid
              AND index_catalog.indisready
              AND index_catalog.indimmediate
              AND index_catalog.indnkeyatts = 2
              AND index_catalog.indnatts = 2
              AND index_catalog.indpred IS NULL
              AND index_catalog.indexprs IS NULL
        ),
        expected_routines(
            function_signature,
            return_type,
            argument_names,
            function_source_sha256,
            security_definer,
            volatility,
            parallel_safety,
            function_config,
            language_name
        ) AS (
            VALUES
                (
                    'public.ryuki_live_site_status_max_age_seconds()'::text,
                    'pg_catalog.int8'::regtype,
                    NULL::text[],
                    '7a92fb390bc256bd2ba2c1e6fcee26e424a41ab8f752e9f16e7f545054a67a5b'::text,
                    FALSE,
                    'i'::"char",
                    's'::"char",
                    ARRAY['search_path=pg_catalog, public']::text[],
                    'sql'::text
                ),
                (
                    'public.ryuki_acquire_live_site_execution_epoch(text)'::text,
                    'pg_catalog.int8'::regtype,
                    ARRAY['requested_site']::text[],
                    '4eebe323182eb2f0184f7823a3efa7a8ecb5c5150b8059270e1ab707e2a327cd'::text,
                    TRUE,
                    'v'::"char",
                    'u'::"char",
                    ARRAY['search_path=pg_catalog, public, pg_temp']::text[],
                    'plpgsql'::text
                )
        ),
        matching_routines AS (
            SELECT expected.function_signature
            FROM expected_routines AS expected
            JOIN pg_catalog.pg_proc AS procedure
              ON procedure.oid =
                    pg_catalog.to_regprocedure(expected.function_signature)
            JOIN pg_catalog.pg_language AS language
              ON language.oid = procedure.prolang
            WHERE procedure.prokind = 'f'
              AND procedure.prorettype = expected.return_type
              AND NOT procedure.proretset
              AND procedure.pronargdefaults = 0
              AND procedure.provariadic = 0
              AND procedure.proargnames IS NOT DISTINCT FROM expected.argument_names
              AND procedure.proargmodes IS NULL
              AND procedure.proallargtypes IS NULL
              AND procedure.prosecdef = expected.security_definer
              AND NOT procedure.proleakproof
              AND NOT procedure.proisstrict
              AND procedure.provolatile = expected.volatility
              AND procedure.proparallel = expected.parallel_safety
              AND procedure.proconfig IS NOT DISTINCT FROM expected.function_config
              AND language.lanname = expected.language_name
              AND pg_catalog.encode(
                      pg_catalog.sha256(
                          pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                      ),
                      'hex'
                  ) = expected.function_source_sha256
        ),
        expected_triggers(
            table_name,
            trigger_name,
            function_signature,
            trigger_type,
            column_names,
            function_source_sha256,
            security_definer,
            function_config
        ) AS (
            VALUES
                (
                    'site_status'::text,
                    'trg_site_status_authority_epoch'::text,
                    'public.ryuki_guard_site_status_authority_epoch()'::text,
                    23::smallint,
                    ARRAY[]::text[],
                    '00c094ed2565000ddc77467f231f4724afc08ae3836d85701851497a9287c3d2'::text,
                    TRUE,
                    ARRAY['search_path=pg_catalog, public, pg_temp']::text[]
                ),
                (
                    'site_registry'::text,
                    'trg_site_registry_live_execution_epoch'::text,
                    'public.ryuki_bump_site_epoch_after_registry_change()'::text,
                    17::smallint,
                    ARRAY['active']::text[],
                    'b24cdaccfbc411386aabcf98a0fde718444e35b1ec4f4e7293dea6d279f21544'::text,
                    TRUE,
                    ARRAY['search_path=pg_catalog, public, pg_temp']::text[]
                ),
                (
                    'component_status'::text,
                    'trg_component_status_observation'::text,
                    'public.ryuki_guard_component_status_observation()'::text,
                    23::smallint,
                    ARRAY[]::text[],
                    '0a8c6fab39b74ba4808fbd33d84b77395118880a0c2bd0b972c1e6376b23a637'::text,
                    FALSE,
                    ARRAY['search_path=pg_catalog, public']::text[]
                ),
                (
                    'component_status'::text,
                    'trg_component_status_live_execution_epoch'::text,
                    'public.ryuki_bump_site_epoch_after_component_change()'::text,
                    29::smallint,
                    ARRAY[]::text[],
                    '05cdd0352c513af3c0c02b3f3ba234fc7e04ccf143dfaf083d32e4ca8965b096'::text,
                    TRUE,
                    ARRAY['search_path=pg_catalog, public, pg_temp']::text[]
                ),
                (
                    'component_status'::text,
                    'trg_component_status_no_truncate'::text,
                    'public.ryuki_reject_component_status_truncate()'::text,
                    34::smallint,
                    ARRAY[]::text[],
                    '829c3fba4e5affb87b304862cafdd02c58ad82221c5db90b100dc3de57231f42'::text,
                    FALSE,
                    ARRAY['search_path=pg_catalog, public']::text[]
                ),
                (
                    'site_status'::text,
                    'trg_site_status_no_delete'::text,
                    'public.ryuki_reject_site_status_removal()'::text,
                    11::smallint,
                    ARRAY[]::text[],
                    '70e637f52019c6f9b562043b6a5b10f7b8ed118af2b680973ef8e4fd14e2fb11'::text,
                    FALSE,
                    ARRAY['search_path=pg_catalog, public']::text[]
                ),
                (
                    'site_status'::text,
                    'trg_site_status_no_truncate'::text,
                    'public.ryuki_reject_site_status_removal()'::text,
                    34::smallint,
                    ARRAY[]::text[],
                    '70e637f52019c6f9b562043b6a5b10f7b8ed118af2b680973ef8e4fd14e2fb11'::text,
                    FALSE,
                    ARRAY['search_path=pg_catalog, public']::text[]
                )
        ),
        resolved_expected_triggers AS (
            SELECT expected.*,
                   target_tables.oid AS table_oid,
                   resolved_columns.resolved_count,
                   resolved_columns.trigger_columns
            FROM expected_triggers AS expected
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
        matching_triggers AS (
            SELECT expected.trigger_name
            FROM resolved_expected_triggers AS expected
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
              AND procedure.proargnames IS NULL
              AND procedure.proargmodes IS NULL
              AND procedure.proallargtypes IS NULL
              AND procedure.prosecdef = expected.security_definer
              AND NOT procedure.proleakproof
              AND NOT procedure.proisstrict
              AND procedure.provolatile = 'v'
              AND procedure.proparallel = 'u'
              AND procedure.proconfig IS NOT DISTINCT FROM expected.function_config
              AND language.lanname = 'plpgsql'
              AND pg_catalog.encode(
                      pg_catalog.sha256(
                          pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                      ),
                      'hex'
                  ) = expected.function_source_sha256
        )
        SELECT (SELECT COUNT(*) FROM target_tables) = 4
           AND (SELECT COUNT(*) FROM matching_authority_columns) = 2
           AND NOT EXISTS (
               SELECT 1
               FROM expected_authority_columns
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM matching_authority_columns
                   WHERE matching_authority_columns.table_name =
                         expected_authority_columns.table_name
                     AND matching_authority_columns.column_name =
                         expected_authority_columns.column_name
               )
           )
           AND (SELECT COUNT(*) FROM resolved_expected_checks) = 3
           AND (SELECT COUNT(*) FROM matching_checks) = 3
           AND NOT EXISTS (
               SELECT 1
               FROM expected_checks
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM matching_checks
                   WHERE matching_checks.constraint_name =
                         expected_checks.constraint_name
               )
           )
           AND (SELECT COUNT(*) FROM matching_site_registry_foreign_key) = 1
           AND (SELECT COUNT(*) FROM matching_component_unique) = 1
           AND (SELECT COUNT(*) FROM matching_routines) = 2
           AND NOT EXISTS (
               SELECT 1
               FROM expected_routines
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM matching_routines
                   WHERE matching_routines.function_signature =
                         expected_routines.function_signature
               )
           )
           AND (SELECT COUNT(*) FROM resolved_expected_triggers) = 7
           AND (SELECT COUNT(*) FROM matching_triggers) = 7
           AND NOT EXISTS (
               SELECT 1
               FROM expected_triggers
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM matching_triggers
                   WHERE matching_triggers.trigger_name =
                         expected_triggers.trigger_name
               )
           )
        "#,
    )
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "live-site execution authority definitions are not canonical and always enabled",
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
    attest_live_site_execution_authority_chain(connection).await?;
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

async fn reconcile_application_privileges_in_transaction(
    connection: &mut PgConnection,
    contract: &MigrationRoleContract,
) -> Result<(), sqlx::Error> {
    attest_public_table_inventory(connection).await?;

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
    .fetch_all(&mut *connection)
    .await?;

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
        sqlx::query(&statement).execute(&mut *connection).await?;
    }

    // Trigger and validation functions are invoked by PostgreSQL and do not
    // need caller EXECUTE. Deny every direct public routine call, then add back
    // the three reviewed bounded entry points below.
    for (object_kind, signature) in public_routines {
        let statement =
            format!("REVOKE ALL PRIVILEGES ON {object_kind} {signature} FROM PUBLIC, {app}");
        sqlx::query(&statement).execute(&mut *connection).await?;
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
    .fetch_all(&mut *connection)
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
        sqlx::query(&statement).execute(&mut *connection).await?;
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
        sqlx::query(&statement).execute(&mut *connection).await?;
    }
    sqlx::query(&format!(
        "GRANT SELECT ON TABLE public._sqlx_migrations TO {app}"
    ))
    .execute(&mut *connection)
    .await?;
    sqlx::query(&format!(
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {app}"
    ))
    .execute(&mut *connection)
    .await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION public.reconcile_noisy_trigger_sites(integer) TO {app}"
    ))
    .execute(&mut *connection)
    .await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION \
         public.append_audit_log(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text) \
         TO {app}"
    ))
    .execute(&mut *connection)
    .await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION \
         public.ryuki_acquire_live_site_execution_epoch(text) TO {app}"
    ))
    .execute(&mut *connection)
    .await?;

    // The migration bootstrap already selected the stable migrator role on
    // this physical connection. Re-establish the authenticated login identity
    // before replaying the exact membership attestation; otherwise the
    // intentional `current_user = session_user` precondition fails after
    // migration work on either the local pool or production direct path.
    sqlx::query("RESET ROLE").execute(&mut *connection).await?;
    attest_migration_connection(connection, contract).await?;
    attest_safe_default_privileges(connection, &contract.expected).await?;
    attest_application_routine_acl(connection, &contract.application).await?;
    attest_application_acl(connection, &contract.application).await
}

async fn reconcile_application_privileges(
    pool: &PgPool,
    contract: &MigrationRoleContract,
) -> Result<(), sqlx::Error> {
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    let result = reconcile_application_privileges_in_transaction(&mut transaction, contract).await;
    match result {
        Ok(()) => transaction.commit().await,
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

const PRODUCTION_MIGRATION_PROOF_SAFETY_MARGIN_SECS: i64 = 30;
const PRODUCTION_MIGRATION_PREFLIGHT_TIMEOUT_MILLIS: u64 = 30_000;
const PRODUCTION_MIGRATION_COMMIT_ACK_TIMEOUT_SECS: u64 = 30;
const PRODUCTION_MIGRATION_SESSION_LOCK_ID: i64 = 0x7279_756b_695f_6d67;
const PRODUCTION_MIGRATION_RELEASE_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-production-migration-release-binding-v1";
const PRODUCTION_MIGRATION_TARGET_BINDING_DIGEST_CONTRACT: &str =
    "ryuki-production-migration-target-binding-v1";
const PRODUCTION_MIGRATION_OPERATION_ID_CONTRACT: &str =
    "ryuki-production-migration-operation-id-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProductionMigrationWaveLimits {
    deadline_at: DateTime<Utc>,
    whole_wave_timeout: Duration,
    statement_timeout_millis: u64,
    lock_timeout_millis: u64,
}

fn canonical_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn framed_migration_digest(contract: &str, fields: &[(&str, &str)]) -> String {
    let mut digest = Sha256::new();
    for bytes in std::iter::once(contract.as_bytes()).chain(
        fields
            .iter()
            .flat_map(|(label, value)| [label.as_bytes(), value.as_bytes()]),
    ) {
        digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(bytes);
    }
    format!("sha256:{:x}", digest.finalize())
}

fn production_database_provider_id(provider: ProductionDatabaseProvider) -> &'static str {
    match provider {
        ProductionDatabaseProvider::CloudNativePg => "cloudnativepg",
        ProductionDatabaseProvider::AwsRds => "aws-rds",
        ProductionDatabaseProvider::AzurePostgresql => "azure-postgresql",
        ProductionDatabaseProvider::GcpCloudSql => "gcp-cloud-sql",
    }
}

fn production_migration_target_binding_digest(
    database_provider: ProductionDatabaseProvider,
    provider_route_binding_digest: &str,
    server_major_version: u16,
    database_identity_digest: &str,
    storage_binding_digest: &str,
    application_role: &str,
    migration_role: &str,
) -> String {
    let server_major_version = server_major_version.to_string();
    framed_migration_digest(
        PRODUCTION_MIGRATION_TARGET_BINDING_DIGEST_CONTRACT,
        &[
            (
                "database_provider",
                production_database_provider_id(database_provider),
            ),
            (
                "provider_route_binding_digest",
                provider_route_binding_digest,
            ),
            ("server_major_version", &server_major_version),
            ("database_identity_digest", database_identity_digest),
            ("storage_binding_digest", storage_binding_digest),
            ("application_role", application_role),
            ("migration_role", migration_role),
        ],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionMigrationSnapshotState {
    Connected,
    SessionLocked,
    RepeatableReadStarted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionMigrationSnapshotEvent {
    SessionLockAcquired,
    RepeatableReadStarted,
}

fn advance_production_migration_snapshot_state(
    state: ProductionMigrationSnapshotState,
    event: ProductionMigrationSnapshotEvent,
) -> Result<ProductionMigrationSnapshotState, String> {
    match (state, event) {
        (
            ProductionMigrationSnapshotState::Connected,
            ProductionMigrationSnapshotEvent::SessionLockAcquired,
        ) => Ok(ProductionMigrationSnapshotState::SessionLocked),
        (
            ProductionMigrationSnapshotState::SessionLocked,
            ProductionMigrationSnapshotEvent::RepeatableReadStarted,
        ) => Ok(ProductionMigrationSnapshotState::RepeatableReadStarted),
        _ => Err(
            "production migration repeatable-read snapshot requires the pre-BEGIN session lock"
                .into(),
        ),
    }
}

fn production_migration_operation_marker(
    execution: &crate::security_contracts::VerifiedProductionMigrationExecution,
) -> ProductionMigrationOperationMarker {
    let proof = execution.verified_infrastructure();
    let profile_version = proof.attestation_profile_version().to_string();
    // Workload-instance and authority-key identity are intentionally excluded:
    // a new one-shot pod and a rotated authority must be able to reconcile the
    // same release operation after a lost COMMIT acknowledgement. Source,
    // artifact, profile, namespace, exact database/storage identity, roles, and
    // final inventory remain fixed and independently re-attested.
    let release_binding_digest = framed_migration_digest(
        PRODUCTION_MIGRATION_RELEASE_BINDING_DIGEST_CONTRACT,
        &[
            ("deployment_id", proof.deployment_id()),
            ("trust_domain_id", proof.trust_domain_id()),
            ("workload_id", proof.workload_id()),
            ("source_revision", proof.source_revision()),
            ("artifact_digest", proof.artifact_digest()),
            ("attestation_profile_id", proof.attestation_profile_id()),
            ("attestation_profile_version", &profile_version),
            (
                "attestation_profile_digest",
                proof.attestation_profile_digest(),
            ),
        ],
    );
    let target_binding_digest = production_migration_target_binding_digest(
        proof.database_provider(),
        proof.provider_route_binding_digest(),
        proof.server_major_version(),
        proof.database_identity_digest(),
        proof.storage_binding_digest(),
        proof.application_role(),
        proof.migration_role(),
    );
    let migration_inventory_digest = execution.expected_migration_inventory_digest().to_owned();
    let operation_id = framed_migration_digest(
        PRODUCTION_MIGRATION_OPERATION_ID_CONTRACT,
        &[
            ("release_binding_digest", &release_binding_digest),
            ("target_binding_digest", &target_binding_digest),
            ("migration_inventory_digest", &migration_inventory_digest),
        ],
    );
    ProductionMigrationOperationMarker {
        operation_id,
        release_binding_digest,
        target_binding_digest,
        migration_inventory_digest,
        attestation_response_digest: proof.response_digest().to_owned(),
        session_binding_digest: proof.session_binding_digest().to_owned(),
    }
}

fn production_migration_preflight_timeouts(
    configured: MigrationTimeouts,
) -> Result<(u64, u64), String> {
    if configured.statement_timeout_secs != REVIEWED_PRODUCTION_MIGRATION_STATEMENT_TIMEOUT_SECS
        || configured.lock_timeout_secs != REVIEWED_PRODUCTION_MIGRATION_LOCK_TIMEOUT_SECS
        || !(MIN_MIGRATION_STATEMENT_TIMEOUT_SECS..=MAX_MIGRATION_STATEMENT_TIMEOUT_SECS)
            .contains(&configured.statement_timeout_secs)
        || !(MIN_MIGRATION_LOCK_TIMEOUT_SECS..=MAX_MIGRATION_LOCK_TIMEOUT_SECS)
            .contains(&configured.lock_timeout_secs)
        || configured.lock_timeout_secs >= configured.statement_timeout_secs
    {
        return Err(
            "production migration timeouts must equal the reviewed 180-second statement and 30-second lock contract"
                .into(),
        );
    }
    let statement_timeout_millis = configured
        .statement_timeout_secs
        .checked_mul(1_000)
        .ok_or_else(|| "production migration statement timeout is out of range".to_owned())?
        .min(PRODUCTION_MIGRATION_PREFLIGHT_TIMEOUT_MILLIS);
    let lock_timeout_millis = configured
        .lock_timeout_secs
        .checked_mul(1_000)
        .ok_or_else(|| "production migration lock timeout is out of range".to_owned())?
        .min(statement_timeout_millis.saturating_sub(1));
    if statement_timeout_millis == 0 || lock_timeout_millis == 0 {
        return Err("production migration preflight timeouts cannot be disabled".into());
    }
    Ok((statement_timeout_millis, lock_timeout_millis))
}

fn production_migration_wave_limits(
    now: DateTime<Utc>,
    proof_valid_until: DateTime<Utc>,
    configured: MigrationTimeouts,
) -> Result<ProductionMigrationWaveLimits, String> {
    let deadline_at = proof_valid_until
        .checked_sub_signed(chrono::TimeDelta::seconds(
            PRODUCTION_MIGRATION_PROOF_SAFETY_MARGIN_SECS,
        ))
        .ok_or_else(|| "PostgreSQL proof validity cannot provide a safe DDL deadline".to_owned())?;
    let remaining_millis = deadline_at.signed_duration_since(now).num_milliseconds();
    if remaining_millis < 2_000 {
        return Err(
            "PostgreSQL proof expires too soon to start an atomic production migration".into(),
        );
    }
    let remaining_millis = u64::try_from(remaining_millis)
        .map_err(|_| "PostgreSQL proof deadline is out of range".to_owned())?;
    let configured_statement_millis = configured
        .statement_timeout_secs
        .checked_mul(1_000)
        .ok_or_else(|| "production migration statement timeout is out of range".to_owned())?;
    let configured_lock_millis = configured
        .lock_timeout_secs
        .checked_mul(1_000)
        .ok_or_else(|| "production migration lock timeout is out of range".to_owned())?;
    let statement_timeout_millis =
        configured_statement_millis.min(remaining_millis.saturating_sub(1_000));
    let lock_timeout_millis =
        configured_lock_millis.min(statement_timeout_millis.saturating_sub(1));
    if statement_timeout_millis == 0 || lock_timeout_millis == 0 {
        return Err("PostgreSQL proof window cannot contain the configured DDL timeouts".into());
    }
    Ok(ProductionMigrationWaveLimits {
        deadline_at,
        whole_wave_timeout: Duration::from_millis(remaining_millis),
        statement_timeout_millis,
        lock_timeout_millis,
    })
}

async fn set_local_migration_timeouts(
    connection: &mut PgConnection,
    statement_timeout_millis: u64,
    lock_timeout_millis: u64,
) -> Result<(), sqlx::Error> {
    let statement_timeout = format!("{statement_timeout_millis}ms");
    let lock_timeout = format!("{lock_timeout_millis}ms");
    sqlx::query(
        "SELECT pg_catalog.set_config('statement_timeout', $1, true), \
                pg_catalog.set_config('lock_timeout', $2, true), \
                pg_catalog.set_config('standard_conforming_strings', 'on', true)",
    )
    .bind(statement_timeout)
    .bind(lock_timeout)
    .execute(&mut *connection)
    .await?;
    let observed: (i64, i64, bool) = sqlx::query_as(
        "SELECT \
             (SELECT setting::bigint FROM pg_catalog.pg_settings \
              WHERE name = 'statement_timeout' AND unit = 'ms'), \
             (SELECT setting::bigint FROM pg_catalog.pg_settings \
              WHERE name = 'lock_timeout' AND unit = 'ms'), \
             pg_catalog.current_setting('standard_conforming_strings') = 'on'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if observed
        != (
            i64::try_from(statement_timeout_millis)
                .map_err(|_| role_protocol_error("statement timeout is out of range"))?,
            i64::try_from(lock_timeout_millis)
                .map_err(|_| role_protocol_error("lock timeout is out of range"))?,
            true,
        )
    {
        return Err(role_protocol_error(
            "migration transaction did not retain the exact bounded timeouts and parser mode",
        ));
    }
    Ok(())
}

async fn establish_exact_migration_role(
    connection: &mut PgConnection,
    contract: &MigrationRoleContract,
) -> Result<(), sqlx::Error> {
    sqlx::query("RESET ROLE").execute(&mut *connection).await?;
    attest_migration_connection(connection, contract).await?;
    attest_safe_default_privileges(connection, &contract.expected).await?;
    let search_path: String =
        sqlx::query_scalar("SELECT pg_catalog.set_config('search_path', 'public', true)")
            .fetch_one(&mut *connection)
            .await?;
    let exact: bool = sqlx::query_scalar(
        "SELECT $1 = 'public' \
                AND pg_catalog.current_setting('search_path') = 'public' \
                AND current_user = $2::name \
                AND pg_catalog.current_setting('role') = $2",
    )
    .bind(search_path)
    .bind(&contract.expected)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "migration transaction did not establish the exact role and search_path",
        ));
    }
    Ok(())
}

async fn acquire_bounded_session_migration_lock(
    connection: &mut PgConnection,
    lock_timeout_millis: u64,
) -> Result<(), sqlx::Error> {
    let timeout = Duration::from_millis(lock_timeout_millis);
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        let remaining = timeout.saturating_sub(elapsed);
        if remaining.is_zero() {
            return Err(role_protocol_error(
                "production migration session advisory-lock deadline elapsed",
            ));
        }
        let acquired: bool = tokio::time::timeout(
            remaining,
            sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_lock($1)")
                .bind(PRODUCTION_MIGRATION_SESSION_LOCK_ID)
                .fetch_one(&mut *connection),
        )
        .await
        .map_err(|_| {
            role_protocol_error("production migration session advisory-lock query deadline elapsed")
        })??;
        if acquired {
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(role_protocol_error(
                "production migration session advisory-lock deadline elapsed",
            ));
        }
        tokio::time::sleep(Duration::from_millis(50).min(timeout.saturating_sub(elapsed))).await;
    }
}

/// Replace the pre-BEGIN session lock with an unreleaseable transaction lock
/// before embedded migration SQL can run. Holding the session lock while the
/// transaction lock is acquired makes this promotion non-blocking with respect
/// to other migration runners. PostgreSQL exposes no transaction-advisory-lock
/// unlock operation, so raw migration SQL cannot drop the serialization fence.
async fn promote_to_transaction_migration_lock(
    connection: &mut PgConnection,
    lock_timeout_millis: u64,
) -> Result<(), sqlx::Error> {
    let timeout = Duration::from_millis(lock_timeout_millis);
    let transaction_lock_acquired: bool = tokio::time::timeout(
        timeout,
        sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_xact_lock($1)")
            .bind(PRODUCTION_MIGRATION_SESSION_LOCK_ID)
            .fetch_one(&mut *connection),
    )
    .await
    .map_err(|_| {
        role_protocol_error(
            "production migration transaction advisory-lock promotion deadline elapsed",
        )
    })??;
    if !transaction_lock_acquired {
        return Err(role_protocol_error(
            "production migration transaction advisory-lock promotion failed while the session lock was held",
        ));
    }

    let session_lock_released: bool = tokio::time::timeout(
        timeout,
        sqlx::query_scalar("SELECT pg_catalog.pg_advisory_unlock($1)")
            .bind(PRODUCTION_MIGRATION_SESSION_LOCK_ID)
            .fetch_one(&mut *connection),
    )
    .await
    .map_err(|_| {
        role_protocol_error(
            "production migration session advisory-lock release deadline elapsed after promotion",
        )
    })??;
    if !session_lock_released {
        return Err(role_protocol_error(
            "production migration session advisory lock was not retained through transaction-lock promotion",
        ));
    }
    Ok(())
}

fn validate_atomic_migration_shape(entries: &[(i64, bool, bool)]) -> Result<(), String> {
    if entries.is_empty() {
        return Err("atomic production migration inventory is empty".into());
    }
    let mut previous = None;
    for (version, is_down, no_tx) in entries {
        if *version <= 0 || previous.is_some_and(|previous| *version <= previous) {
            return Err("atomic production migration versions are not strictly increasing".into());
        }
        if *is_down {
            return Err("atomic production migration inventory contains a down migration".into());
        }
        if *no_tx {
            return Err(
                "atomic production migration inventory contains a no-transaction migration".into(),
            );
        }
        previous = Some(*version);
    }
    Ok(())
}

const MAX_ATOMIC_MIGRATION_SQL_BYTES: usize = 1024 * 1024;
const MAX_ATOMIC_MIGRATION_STATEMENTS: usize = 4_096;
const MAX_ATOMIC_MIGRATION_TOKENS: usize = 65_536;
const MAX_ATOMIC_MIGRATION_TOKENS_PER_STATEMENT: usize = 8_192;
const MAX_ATOMIC_MIGRATION_PAREN_DEPTH: usize = 128;
const MAX_ATOMIC_MIGRATION_BLOCK_COMMENT_DEPTH: usize = 64;
const MAX_ATOMIC_MIGRATION_DOLLAR_TAG_BYTES: usize = 128;
const MAX_ATOMIC_MIGRATION_IDENTIFIER_BYTES: usize = 128;
const MAX_ATOMIC_MIGRATION_CAPTURED_LITERAL_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
enum AtomicMigrationSqlToken {
    Identifier { normalized: String, quoted: bool },
    StringLiteral(Option<String>),
    Equals,
    Other,
}

impl AtomicMigrationSqlToken {
    fn is_keyword(&self, expected: &str) -> bool {
        matches!(
            self,
            Self::Identifier {
                normalized,
                quoted: false,
            } if normalized == expected
        )
    }
}

fn atomic_migration_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || !byte.is_ascii()
}

fn atomic_migration_identifier_continue(byte: u8) -> bool {
    atomic_migration_identifier_start(byte) || byte.is_ascii_digit() || byte == b'$'
}

fn atomic_migration_contains_forbidden_lock_release(sql: &str) -> bool {
    let normalized = sql.to_ascii_uppercase();
    let bytes = normalized.as_bytes();
    ["PG_ADVISORY_UNLOCK", "PG_ADVISORY_UNLOCK_ALL"]
        .into_iter()
        .any(|forbidden| {
            bytes
                .windows(forbidden.len())
                .enumerate()
                .any(|(start, candidate)| {
                    candidate == forbidden.as_bytes()
                        && start
                            .checked_sub(1)
                            .and_then(|before| bytes.get(before))
                            .is_none_or(|byte| !atomic_migration_identifier_continue(*byte))
                        && bytes
                            .get(start + forbidden.len())
                            .is_none_or(|byte| !atomic_migration_identifier_continue(*byte))
                })
        })
}

fn atomic_migration_dollar_delimiter(bytes: &[u8], start: usize) -> Result<Option<&[u8]>, String> {
    if bytes.get(start) != Some(&b'$') {
        return Ok(None);
    }
    let Some(next) = bytes.get(start + 1).copied() else {
        return Ok(None);
    };
    if next == b'$' {
        return Ok(Some(&bytes[start..start + 2]));
    }
    if !(next.is_ascii_alphabetic() || next == b'_') {
        return Ok(None);
    }
    let mut cursor = start + 2;
    while let Some(byte) = bytes.get(cursor).copied() {
        if byte == b'$' {
            let delimiter = &bytes[start..=cursor];
            if delimiter.len() > MAX_ATOMIC_MIGRATION_DOLLAR_TAG_BYTES + 2 {
                return Err("contains an overlong dollar-quote tag".into());
            }
            return Ok(Some(delimiter));
        }
        if !(byte.is_ascii_alphanumeric() || byte == b'_') {
            return Ok(None);
        }
        if cursor - start > MAX_ATOMIC_MIGRATION_DOLLAR_TAG_BYTES {
            return Err("contains an overlong dollar-quote tag".into());
        }
        cursor += 1;
    }
    Ok(None)
}

fn scan_atomic_migration_single_quote(
    sql: &str,
    quote_start: usize,
    backslash_escapes: bool,
) -> Result<(usize, Option<String>), String> {
    let bytes = sql.as_bytes();
    let mut cursor = quote_start + 1;
    let content_start = cursor;
    let mut simple_literal = true;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\'' if bytes.get(cursor + 1) == Some(&b'\'') => {
                simple_literal = false;
                cursor += 2;
            }
            b'\'' => {
                let captured = if simple_literal
                    && cursor - content_start <= MAX_ATOMIC_MIGRATION_CAPTURED_LITERAL_BYTES
                {
                    Some(sql[content_start..cursor].to_owned())
                } else {
                    None
                };
                return Ok((cursor + 1, captured));
            }
            b'\\' if backslash_escapes => {
                simple_literal = false;
                cursor = cursor
                    .checked_add(2)
                    .ok_or_else(|| "contains an overlong escape string".to_owned())?;
            }
            b'\\' if bytes.get(cursor + 1) == Some(&b'\'') => {
                return Err(
                    "contains a backslash-quote sequence whose parse depends on standard_conforming_strings"
                        .into(),
                );
            }
            _ => cursor += 1,
        }
    }
    Err("contains an unterminated string literal".into())
}

fn scan_atomic_migration_quoted_identifier(
    sql: &str,
    quote_start: usize,
) -> Result<(usize, String), String> {
    let bytes = sql.as_bytes();
    let mut cursor = quote_start + 1;
    let mut decoded = Vec::new();
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            if bytes.get(cursor + 1) == Some(&b'"') {
                decoded.push(b'"');
                cursor += 2;
            } else {
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| "contains a malformed quoted identifier".to_owned())?;
                return Ok((cursor + 1, decoded.to_ascii_uppercase()));
            }
        } else {
            decoded.push(bytes[cursor]);
            cursor += 1;
        }
        if decoded.len() > MAX_ATOMIC_MIGRATION_IDENTIFIER_BYTES {
            return Err("contains an overlong quoted identifier".into());
        }
    }
    Err("contains an unterminated quoted identifier".into())
}

fn is_reviewed_atomic_migration_set_exception(tokens: &[AtomicMigrationSqlToken]) -> bool {
    // Six reviewed migrations deliberately cap ACCESS EXCLUSIVE waits at 30
    // seconds. This exact transaction-local, finite setting is dominated by
    // the proof-bounded whole-wave deadline. No other SET form is admitted.
    tokens.len() == 5
        && tokens[0].is_keyword("SET")
        && tokens[1].is_keyword("LOCAL")
        && tokens[2].is_keyword("LOCK_TIMEOUT")
        && tokens[3] == AtomicMigrationSqlToken::Equals
        && matches!(
            &tokens[4],
            AtomicMigrationSqlToken::StringLiteral(Some(value)) if value == "30s"
        )
}

fn validate_atomic_migration_statement(tokens: &[AtomicMigrationSqlToken]) -> Result<(), String> {
    let Some(first) = tokens.first() else {
        return Ok(());
    };
    for forbidden in [
        "BEGIN",
        "COMMIT",
        "END",
        "ROLLBACK",
        "ABORT",
        "SAVEPOINT",
        "RELEASE",
        "DISCARD",
        "LOAD",
    ] {
        if first.is_keyword(forbidden) {
            return Err(format!(
                "contains forbidden top-level {forbidden} statement"
            ));
        }
    }
    if first.is_keyword("START")
        && tokens
            .get(1)
            .is_some_and(|token| token.is_keyword("TRANSACTION"))
    {
        return Err("contains forbidden top-level START TRANSACTION statement".into());
    }
    if first.is_keyword("PREPARE")
        && tokens
            .get(1)
            .is_some_and(|token| token.is_keyword("TRANSACTION"))
    {
        return Err("contains forbidden top-level PREPARE TRANSACTION statement".into());
    }
    if first.is_keyword("RESET") {
        return Err("contains forbidden top-level RESET statement".into());
    }
    if first.is_keyword("SET") {
        if is_reviewed_atomic_migration_set_exception(tokens) {
            return Ok(());
        }
        if tokens
            .get(1)
            .is_some_and(|token| token.is_keyword("CONSTRAINTS"))
        {
            return Ok(());
        }
        return Err("contains forbidden top-level SET outside the reviewed allowlist".into());
    }
    if first.is_keyword("COPY") {
        let direction = tokens
            .iter()
            .position(|token| token.is_keyword("FROM") || token.is_keyword("TO"));
        if direction.is_some_and(|direction| {
            tokens[direction + 1..]
                .iter()
                .any(|token| token.is_keyword("PROGRAM"))
        }) {
            return Err("contains forbidden top-level COPY PROGRAM statement".into());
        }
    }
    Ok(())
}

fn validate_atomic_migration_sql(sql: &str) -> Result<(), String> {
    if sql.len() > MAX_ATOMIC_MIGRATION_SQL_BYTES {
        return Err(format!(
            "exceeds the {MAX_ATOMIC_MIGRATION_SQL_BYTES}-byte lexical validation bound"
        ));
    }
    if atomic_migration_contains_forbidden_lock_release(sql) {
        return Err(
            "contains a forbidden session advisory-lock release primitive anywhere in the migration source"
                .into(),
        );
    }
    let bytes = sql.as_bytes();
    let mut cursor = 0;
    let mut paren_depth = 0;
    let mut token_count = 0;
    let mut statement_count = 0;
    let mut statement = Vec::new();

    let push_token = |statement: &mut Vec<AtomicMigrationSqlToken>,
                      token_count: &mut usize,
                      token: AtomicMigrationSqlToken|
     -> Result<(), String> {
        *token_count = token_count
            .checked_add(1)
            .ok_or_else(|| "contains too many lexical tokens".to_owned())?;
        if *token_count > MAX_ATOMIC_MIGRATION_TOKENS
            || statement.len() >= MAX_ATOMIC_MIGRATION_TOKENS_PER_STATEMENT
        {
            return Err("contains too many top-level lexical tokens".into());
        }
        statement.push(token);
        Ok(())
    };

    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte.is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        if byte == b'-' && bytes.get(cursor + 1) == Some(&b'-') {
            cursor += 2;
            while cursor < bytes.len() && !matches!(bytes[cursor], b'\n' | b'\r') {
                cursor += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
            cursor += 2;
            let mut depth = 1;
            while cursor < bytes.len() && depth > 0 {
                if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
                    depth += 1;
                    if depth > MAX_ATOMIC_MIGRATION_BLOCK_COMMENT_DEPTH {
                        return Err("exceeds the nested block-comment depth bound".into());
                    }
                    cursor += 2;
                } else if bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/') {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            if depth != 0 {
                return Err("contains an unterminated block comment".into());
            }
            continue;
        }
        if matches!(byte, b'e' | b'E') && bytes.get(cursor + 1) == Some(&b'\'') {
            let (end, _) = scan_atomic_migration_single_quote(sql, cursor + 1, true)?;
            if paren_depth == 0 {
                push_token(
                    &mut statement,
                    &mut token_count,
                    AtomicMigrationSqlToken::StringLiteral(None),
                )?;
            }
            cursor = end;
            continue;
        }
        if byte == b'\'' {
            let (end, literal) = scan_atomic_migration_single_quote(sql, cursor, false)?;
            if paren_depth == 0 {
                push_token(
                    &mut statement,
                    &mut token_count,
                    AtomicMigrationSqlToken::StringLiteral(literal),
                )?;
            }
            cursor = end;
            continue;
        }
        if byte == b'"' {
            let (end, normalized) = scan_atomic_migration_quoted_identifier(sql, cursor)?;
            if paren_depth == 0 {
                push_token(
                    &mut statement,
                    &mut token_count,
                    AtomicMigrationSqlToken::Identifier {
                        normalized,
                        quoted: true,
                    },
                )?;
            }
            cursor = end;
            continue;
        }
        if byte == b'$' {
            if let Some(delimiter) = atomic_migration_dollar_delimiter(bytes, cursor)? {
                let body_start = cursor + delimiter.len();
                let Some(relative_end) = bytes[body_start..]
                    .windows(delimiter.len())
                    .position(|window| window == delimiter)
                else {
                    return Err("contains an unterminated dollar-quoted body".into());
                };
                cursor = body_start + relative_end + delimiter.len();
                if paren_depth == 0 {
                    push_token(
                        &mut statement,
                        &mut token_count,
                        AtomicMigrationSqlToken::StringLiteral(None),
                    )?;
                }
                continue;
            }
        }
        if atomic_migration_identifier_start(byte) {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len() && atomic_migration_identifier_continue(bytes[cursor]) {
                cursor += 1;
            }
            if cursor - start > MAX_ATOMIC_MIGRATION_IDENTIFIER_BYTES {
                return Err("contains an overlong unquoted identifier".into());
            }
            if paren_depth == 0 {
                push_token(
                    &mut statement,
                    &mut token_count,
                    AtomicMigrationSqlToken::Identifier {
                        normalized: sql[start..cursor].to_ascii_uppercase(),
                        quoted: false,
                    },
                )?;
            }
            continue;
        }
        match byte {
            b'(' => {
                paren_depth += 1;
                if paren_depth > MAX_ATOMIC_MIGRATION_PAREN_DEPTH {
                    return Err("exceeds the parenthesis depth bound".into());
                }
                cursor += 1;
            }
            b')' => {
                paren_depth = paren_depth
                    .checked_sub(1)
                    .ok_or_else(|| "contains an unmatched closing parenthesis".to_owned())?;
                cursor += 1;
            }
            b';' => {
                if paren_depth != 0 {
                    cursor += 1;
                    continue;
                }
                if !statement.is_empty() {
                    statement_count += 1;
                    if statement_count > MAX_ATOMIC_MIGRATION_STATEMENTS {
                        return Err("contains too many top-level statements".into());
                    }
                    validate_atomic_migration_statement(&statement)
                        .map_err(|error| format!("statement {statement_count} {error}"))?;
                    statement.clear();
                }
                cursor += 1;
            }
            b'=' => {
                if paren_depth == 0 {
                    push_token(
                        &mut statement,
                        &mut token_count,
                        AtomicMigrationSqlToken::Equals,
                    )?;
                }
                cursor += 1;
            }
            _ => {
                if paren_depth == 0 {
                    push_token(
                        &mut statement,
                        &mut token_count,
                        AtomicMigrationSqlToken::Other,
                    )?;
                }
                cursor += 1;
            }
        }
    }
    if paren_depth != 0 {
        return Err("contains an unterminated parenthesized expression".into());
    }
    if !statement.is_empty() {
        statement_count += 1;
        if statement_count > MAX_ATOMIC_MIGRATION_STATEMENTS {
            return Err("contains too many top-level statements".into());
        }
        validate_atomic_migration_statement(&statement)
            .map_err(|error| format!("statement {statement_count} {error}"))?;
    }
    Ok(())
}

fn validate_atomic_embedded_migration_plan() -> Result<(), String> {
    let entries = EMBEDDED_MIGRATOR
        .iter()
        .map(|migration| {
            (
                migration.version,
                migration.migration_type.is_down_migration(),
                migration.no_tx,
            )
        })
        .collect::<Vec<_>>();
    validate_atomic_migration_shape(&entries)?;
    if EMBEDDED_MIGRATOR
        .iter()
        .any(|migration| migration.sql.trim().is_empty() || migration.checksum.is_empty())
    {
        return Err("atomic production migration inventory contains empty content".into());
    }
    for migration in EMBEDDED_MIGRATOR.iter() {
        validate_atomic_migration_sql(migration.sql.as_ref()).map_err(|error| {
            format!(
                "atomic production migration {} failed lexical validation: {error}",
                migration.version
            )
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AtomicMigrationTransactionGuard {
    backend_process_id: i32,
    transaction_id: i64,
}

async fn establish_atomic_migration_transaction_guard(
    connection: &mut PgConnection,
) -> Result<AtomicMigrationTransactionGuard, sqlx::Error> {
    let observed: (i32, i64, bool, bool, bool) = sqlx::query_as(
        "SELECT pg_catalog.pg_backend_pid(), \
                pg_catalog.txid_current(), \
                pg_catalog.current_setting('transaction_isolation') = 'repeatable read', \
                pg_catalog.current_setting('transaction_read_only') = 'off', \
                pg_catalog.current_setting('standard_conforming_strings') = 'on'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !observed.2 || !observed.3 || !observed.4 {
        return Err(role_protocol_error(
            "atomic migration transaction/parser settings were not pinned before raw SQL",
        ));
    }
    Ok(AtomicMigrationTransactionGuard {
        backend_process_id: observed.0,
        transaction_id: observed.1,
    })
}

async fn verify_atomic_migration_transaction_guard(
    connection: &mut PgConnection,
    expected: AtomicMigrationTransactionGuard,
) -> Result<(), sqlx::Error> {
    let exact: bool = sqlx::query_scalar(
        "SELECT COALESCE(\
             pg_catalog.pg_backend_pid() = $1 \
             AND pg_catalog.txid_current_if_assigned() = $2 \
             AND pg_catalog.current_setting('transaction_isolation') = 'repeatable read' \
             AND pg_catalog.current_setting('transaction_read_only') = 'off' \
             AND pg_catalog.current_setting('standard_conforming_strings') = 'on', \
             FALSE\
         )",
    )
    .bind(expected.backend_process_id)
    .bind(expected.transaction_id)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "embedded migration changed the backend, transaction identity, isolation, writability, or parser mode",
        ));
    }
    Ok(())
}

async fn apply_atomic_embedded_migrations(
    connection: &mut PgConnection,
    contract: &MigrationRoleContract,
    preflight_ledger: &[(i64, Vec<u8>, bool)],
) -> Result<(), MigrationRunError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS public._sqlx_migrations (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
            success BOOLEAN NOT NULL,
            checksum BYTEA NOT NULL,
            execution_time BIGINT NOT NULL
        )
        "#,
    )
    .execute(&mut *connection)
    .await
    .map_err(|source| MigrationRunError::AtomicApply { version: 0, source })?;
    attest_sqlx_migrations_table(connection, &contract.expected).await?;
    let retained_ledger = read_preflight_migration_ledger(connection, &contract.expected).await?;
    if retained_ledger != preflight_ledger {
        return Err(MigrationRunError::Preflight(
            "migration ledger changed between signed preflight and atomic execution".into(),
        ));
    }

    let transaction_guard = establish_atomic_migration_transaction_guard(connection)
        .await
        .map_err(|source| MigrationRunError::AtomicApply { version: 0, source })?;

    for migration in EMBEDDED_MIGRATOR.iter().skip(preflight_ledger.len()) {
        verify_atomic_migration_transaction_guard(connection, transaction_guard)
            .await
            .map_err(|source| MigrationRunError::AtomicApply {
                version: migration.version,
                source,
            })?;
        let started = Instant::now();
        sqlx::raw_sql(migration.sql.as_ref())
            .execute(&mut *connection)
            .await
            .map_err(|source| MigrationRunError::AtomicApply {
                version: migration.version,
                source,
            })?;
        verify_atomic_migration_transaction_guard(connection, transaction_guard)
            .await
            .map_err(|source| MigrationRunError::AtomicApply {
                version: migration.version,
                source,
            })?;
        let elapsed_nanos = i64::try_from(started.elapsed().as_nanos()).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO public._sqlx_migrations \
             (version, description, success, checksum, execution_time) \
             VALUES ($1, $2, TRUE, $3, $4)",
        )
        .bind(migration.version)
        .bind(migration.description.as_ref())
        .bind(migration.checksum.as_ref())
        .bind(elapsed_nanos)
        .execute(&mut *connection)
        .await
        .map_err(|source| MigrationRunError::AtomicApply {
            version: migration.version,
            source,
        })?;
    }
    Ok(())
}

async fn attest_production_migration_operations_table(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<(), sqlx::Error> {
    let exact: bool = sqlx::query_scalar(
        r#"
        WITH migration AS (
            SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1::name
        ),
        marker AS (
            SELECT class.*
            FROM pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = class.relnamespace
            WHERE namespace.nspname = 'public'
              AND class.relname = 'production_migration_operations'
        ),
        expected_columns(name, type_name, not_null) AS (
            VALUES
                ('operation_id'::text, 'text'::text, TRUE),
                ('release_binding_digest'::text, 'text'::text, TRUE),
                ('target_binding_digest'::text, 'text'::text, TRUE),
                ('migration_inventory_digest'::text, 'text'::text, TRUE),
                ('attestation_response_digest'::text, 'text'::text, TRUE),
                ('session_binding_digest'::text, 'text'::text, TRUE),
                ('completed_at'::text, 'timestamp with time zone'::text, TRUE)
        ),
        actual_columns AS (
            SELECT attribute.attname::text AS name,
                   pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                       AS type_name,
                   attribute.attnotnull AS not_null,
                   default_value.oid IS NOT NULL AS has_default,
                   attribute.attidentity,
                   attribute.attgenerated
            FROM marker
            JOIN pg_catalog.pg_attribute AS attribute
              ON attribute.attrelid = marker.oid
             AND attribute.attnum > 0
             AND NOT attribute.attisdropped
            LEFT JOIN pg_catalog.pg_attrdef AS default_value
              ON default_value.adrelid = attribute.attrelid
             AND default_value.adnum = attribute.attnum
        ),
        primary_key AS (
            SELECT constraint.*
            FROM marker
            JOIN pg_catalog.pg_constraint AS constraint
              ON constraint.conrelid = marker.oid
             AND constraint.contype = 'p'
        ),
        expected_triggers(name, trigger_type) AS (
            VALUES
                ('production_migration_operations_no_mutation'::text, 27::smallint),
                ('production_migration_operations_no_truncate'::text, 34::smallint)
        ),
        actual_triggers AS (
            SELECT trigger.tgname::text AS name,
                   trigger.tgtype AS trigger_type,
                   trigger.tgenabled,
                   trigger.tgdeferrable,
                   trigger.tginitdeferred,
                   trigger.tgconstraint,
                   procedure.proowner,
                   procedure.prorettype,
                   procedure.prosecdef,
                   procedure.proleakproof,
                   procedure.proconfig,
                   procedure.prosrc,
                   procedure.proname,
                   procedure_namespace.nspname AS procedure_namespace,
                   language.lanname
            FROM marker
            JOIN pg_catalog.pg_trigger AS trigger
              ON trigger.tgrelid = marker.oid
             AND NOT trigger.tgisinternal
            JOIN pg_catalog.pg_proc AS procedure
              ON procedure.oid = trigger.tgfoid
            JOIN pg_catalog.pg_namespace AS procedure_namespace
              ON procedure_namespace.oid = procedure.pronamespace
            JOIN pg_catalog.pg_language AS language
              ON language.oid = procedure.prolang
        )
        SELECT COALESCE((
            SELECT marker.relkind = 'r'
               AND marker.relpersistence = 'p'
               AND NOT marker.relispartition
               AND NOT marker.relrowsecurity
               AND NOT marker.relforcerowsecurity
               AND marker.relreplident = 'd'
               AND marker.relowner = migration.oid
               AND marker.relam = (
                    SELECT access_method.oid
                    FROM pg_catalog.pg_am AS access_method
                    WHERE access_method.amname = 'heap'
               )
               AND (SELECT count(*) FROM actual_columns) = 7
               AND NOT EXISTS (
                    SELECT 1
                    FROM expected_columns
                    FULL JOIN actual_columns USING (name)
                    WHERE expected_columns.name IS NULL
                       OR actual_columns.name IS NULL
                       OR expected_columns.type_name <> actual_columns.type_name
                       OR expected_columns.not_null <> actual_columns.not_null
                       OR actual_columns.has_default
                       OR actual_columns.attidentity <> ''
                       OR actual_columns.attgenerated <> ''
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_attribute AS attribute
                    WHERE attribute.attrelid = marker.oid
                      AND attribute.attnum > 0
                      AND attribute.attisdropped
               )
               AND (SELECT count(*) FROM primary_key) = 1
               AND (SELECT conkey FROM primary_key) = ARRAY[
                    (
                        SELECT attribute.attnum
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = marker.oid
                          AND attribute.attname = 'operation_id'
                    )
               ]::smallint[]
               AND NOT (SELECT condeferrable FROM primary_key)
               AND NOT (SELECT condeferred FROM primary_key)
               AND (SELECT convalidated FROM primary_key)
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_constraint AS constraint
                    WHERE constraint.conrelid = marker.oid
                      AND constraint.contype <> 'p'
               )
               AND (SELECT count(*) FROM actual_triggers) = 2
               AND NOT EXISTS (
                    SELECT 1
                    FROM expected_triggers
                    FULL JOIN actual_triggers USING (name, trigger_type)
                    WHERE expected_triggers.name IS NULL
                       OR actual_triggers.name IS NULL
                       OR actual_triggers.tgenabled <> 'O'
                       OR actual_triggers.tgdeferrable
                       OR actual_triggers.tginitdeferred
                       OR actual_triggers.tgconstraint <> 0
                       OR actual_triggers.proowner <> migration.oid
                       OR actual_triggers.prorettype <>
                          'pg_catalog.trigger'::regtype
                       OR actual_triggers.prosecdef
                       OR actual_triggers.proleakproof
                       OR actual_triggers.proconfig IS DISTINCT FROM
                          ARRAY['search_path=pg_catalog']::text[]
                       OR actual_triggers.proname <>
                          'prevent_production_migration_operation_mutation'
                       OR actual_triggers.procedure_namespace <> 'public'
                       OR actual_triggers.lanname <> 'plpgsql'
                       OR actual_triggers.prosrc <> E'\nBEGIN\n    RAISE EXCEPTION ''production migration operation markers are permanent and append-only''\n        USING ERRCODE = ''23514'';\nEND;\n'
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_policy AS policy
                    WHERE policy.polrelid = marker.oid
               )
               AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_inherits AS inheritance
                    WHERE inheritance.inhrelid = marker.oid
                       OR inheritance.inhparent = marker.oid
               )
            FROM marker
            CROSS JOIN migration
        ), FALSE)
        "#,
    )
    .bind(migration_role)
    .fetch_one(&mut *connection)
    .await?;
    if !exact {
        return Err(role_protocol_error(
            "production migration operation marker table is not the exact owner-protected append-only ledger",
        ));
    }
    Ok(())
}

fn validate_production_migration_operation_marker(
    marker: &ProductionMigrationOperationMarker,
) -> Result<(), String> {
    if [
        marker.operation_id.as_str(),
        marker.release_binding_digest.as_str(),
        marker.target_binding_digest.as_str(),
        marker.migration_inventory_digest.as_str(),
        marker.attestation_response_digest.as_str(),
        marker.session_binding_digest.as_str(),
    ]
    .into_iter()
    .any(|value| !canonical_sha256_digest(value))
    {
        return Err("production migration operation marker contains a noncanonical digest".into());
    }
    let expected_operation_id = framed_migration_digest(
        PRODUCTION_MIGRATION_OPERATION_ID_CONTRACT,
        &[
            ("release_binding_digest", &marker.release_binding_digest),
            ("target_binding_digest", &marker.target_binding_digest),
            (
                "migration_inventory_digest",
                &marker.migration_inventory_digest,
            ),
        ],
    );
    if marker.operation_id != expected_operation_id {
        return Err(
            "production migration operation id differs from its exact release/target/inventory projection"
                .into(),
        );
    }
    Ok(())
}

fn marker_reconciles_exact_operation(
    observed: &ProductionMigrationOperationMarker,
    expected: &ProductionMigrationOperationMarker,
) -> Result<bool, String> {
    validate_production_migration_operation_marker(observed)?;
    validate_production_migration_operation_marker(expected)?;
    Ok(observed.operation_id == expected.operation_id
        && observed.release_binding_digest == expected.release_binding_digest
        && observed.target_binding_digest == expected.target_binding_digest
        && observed.migration_inventory_digest == expected.migration_inventory_digest)
}

async fn read_production_migration_operation_marker(
    connection: &mut PgConnection,
    operation_id: &str,
) -> Result<Option<ProductionMigrationOperationMarker>, sqlx::Error> {
    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT operation_id, release_binding_digest, target_binding_digest, \
                migration_inventory_digest, attestation_response_digest, session_binding_digest \
         FROM public.production_migration_operations WHERE operation_id = $1",
    )
    .bind(operation_id)
    .fetch_optional(&mut *connection)
    .await?;
    Ok(row.map(
        |(
            operation_id,
            release_binding_digest,
            target_binding_digest,
            migration_inventory_digest,
            attestation_response_digest,
            session_binding_digest,
        )| ProductionMigrationOperationMarker {
            operation_id,
            release_binding_digest,
            target_binding_digest,
            migration_inventory_digest,
            attestation_response_digest,
            session_binding_digest,
        },
    ))
}

async fn insert_production_migration_operation_marker(
    connection: &mut PgConnection,
    marker: &ProductionMigrationOperationMarker,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.production_migration_operations (\
             operation_id, release_binding_digest, target_binding_digest, \
             migration_inventory_digest, attestation_response_digest, \
             session_binding_digest, completed_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, pg_catalog.clock_timestamp())",
    )
    .bind(&marker.operation_id)
    .bind(&marker.release_binding_digest)
    .bind(&marker.target_binding_digest)
    .bind(&marker.migration_inventory_digest)
    .bind(&marker.attestation_response_digest)
    .bind(&marker.session_binding_digest)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn verify_attested_migration_session_projection(
    execution: &crate::security_contracts::VerifiedProductionMigrationExecution,
    binding: &PostgresqlSessionBinding,
) -> Result<(), String> {
    if execution.session_binding() != binding {
        return Err("execution capability retained a different PostgreSQL session".into());
    }
    let proof = execution.verified_infrastructure();
    proof
        .verify_integrity()
        .map_err(|error| format!("PostgreSQL infrastructure proof lost integrity: {error}"))?;
    if proof.session_binding() != binding || proof.request_tag() != binding.application_name {
        return Err("signed infrastructure proof retained a different PostgreSQL session".into());
    }
    let binding_digest = postgresql_session_binding_digest(binding)
        .map_err(|error| format!("PostgreSQL session digest projection failed: {error}"))?;
    if binding_digest != proof.session_binding_digest() {
        return Err("signed PostgreSQL session digest differs from the exact local session".into());
    }

    let identity = proof.database_identity();
    if proof.database_provider() != identity.database_provider
        || proof.server_major_version() != binding.server_major_version
        || identity.database_name != binding.database_name
        || identity.database_oid != binding.database_oid
        || identity.server_address != binding.server_address
        || identity.server_port != binding.server_port
        || identity.server_major_version != binding.server_major_version
        || identity.primary != binding.primary
        || identity.writable
            != (binding.transaction_writable && binding.default_transaction_writable)
        || identity.tls_enabled != binding.tls_enabled
        || identity.tls_protocol != binding.tls_protocol
        || identity.tls_cipher_suite != binding.tls_cipher_suite
        || identity.tls_cipher_bits != binding.tls_cipher_bits
        || proof.application_role() != execution.role_contract().application
        || proof.migration_role() != execution.role_contract().expected
    {
        return Err(
            "signed database identity/provider/role projection differs from the exact migration session"
                .into(),
        );
    }
    let identity_digest = postgresql_database_identity_digest(identity)
        .map_err(|error| format!("PostgreSQL database identity projection failed: {error}"))?;
    let storage_digest = postgresql_storage_binding_digest(proof.storage_bindings())
        .map_err(|error| format!("PostgreSQL storage projection failed: {error}"))?;
    if identity_digest != proof.database_identity_digest()
        || storage_digest != proof.storage_binding_digest()
        || proof.storage_bindings().iter().any(|binding| {
            binding.provider_cluster_uid_digest != proof.provider_cluster_uid_digest()
        })
        || proof.migration_inventory_digest() != execution.expected_migration_inventory_digest()
    {
        return Err(
            "signed database identity, storage, or migration digest is not self-consistent".into(),
        );
    }
    Ok(())
}

async fn run_atomic_production_migration(
    connection: &mut PgConnection,
    tls_channel_binding: &PostgresqlTlsChannelBinding,
    timeouts: MigrationTimeouts,
    pending: crate::security_contracts::PendingProductionMigrationTarget,
) -> Result<MigrationInventory, MigrationRunError> {
    let application_name = pending
        .request_tag_for_channel(tls_channel_binding)
        .map_err(MigrationRunError::Target)?;
    let role_contract = pending.migration_role_contract().clone();
    let (configured_statement_millis, configured_lock_millis) =
        production_migration_preflight_timeouts(timeouts).map_err(MigrationRunError::Admission)?;
    // Serialize on the physical backend session before BEGIN. As the first
    // command in the transaction, promote that ownership to the same
    // transaction-scoped advisory key before releasing the session lock. Raw
    // migration SQL never receives a session lock it can release, and
    // PostgreSQL provides no transaction-advisory-lock unlock primitive.
    let mut snapshot_state = ProductionMigrationSnapshotState::Connected;
    acquire_bounded_session_migration_lock(connection, configured_lock_millis)
        .await
        .map_err(MigrationRunError::Connect)?;
    snapshot_state = advance_production_migration_snapshot_state(
        snapshot_state,
        ProductionMigrationSnapshotEvent::SessionLockAcquired,
    )
    .map_err(MigrationRunError::Admission)?;
    let mut transaction = connection
        .begin_with("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ WRITE")
        .await
        .map_err(MigrationRunError::Connect)?;
    promote_to_transaction_migration_lock(&mut transaction, configured_lock_millis)
        .await
        .map_err(MigrationRunError::Connect)?;
    snapshot_state = advance_production_migration_snapshot_state(
        snapshot_state,
        ProductionMigrationSnapshotEvent::RepeatableReadStarted,
    )
    .map_err(MigrationRunError::Admission)?;
    debug_assert_eq!(
        snapshot_state,
        ProductionMigrationSnapshotState::RepeatableReadStarted
    );
    set_local_migration_timeouts(
        &mut transaction,
        configured_statement_millis,
        configured_lock_millis,
    )
    .await
    .map_err(MigrationRunError::Connect)?;
    establish_exact_migration_role(&mut transaction, &role_contract)
        .await
        .map_err(MigrationRunError::Connect)?;
    let initial = read_postgresql_migration_session_binding(
        &mut transaction,
        &application_name,
        &role_contract,
        tls_channel_binding,
    )
    .await
    .map_err(MigrationRunError::Preflight)?;
    let preflight_ledger =
        read_preflight_migration_ledger(&mut transaction, &role_contract.expected).await?;
    verify_preflight_migration_inventory(&preflight_ledger)?;

    let execution = pending
        .attest_exact_session(initial.clone(), Utc::now())
        .await
        .map_err(MigrationRunError::Admission)?;
    // Re-run the full role, ownership, schema, and default-ACL proof inside
    // the same snapshot immediately before releasing any DDL authority.
    establish_exact_migration_role(&mut transaction, &role_contract)
        .await
        .map_err(MigrationRunError::Connect)?;
    let repeated = read_postgresql_migration_session_binding(
        &mut transaction,
        &application_name,
        &role_contract,
        tls_channel_binding,
    )
    .await
    .map_err(MigrationRunError::Preflight)?;
    if repeated != initial {
        return Err(MigrationRunError::Preflight(
            "exact PostgreSQL backend row changed during infrastructure attestation".into(),
        ));
    }
    verify_attested_migration_session_projection(&execution, &initial)
        .map_err(MigrationRunError::Preflight)?;
    execution
        .ensure_fresh(Utc::now())
        .map_err(MigrationRunError::Admission)?;
    let proof_valid_until = execution.valid_until();
    let limits = production_migration_wave_limits(Utc::now(), proof_valid_until, timeouts)
        .map_err(MigrationRunError::Admission)?;
    let operation_marker = production_migration_operation_marker(&execution);
    validate_production_migration_operation_marker(&operation_marker)
        .map_err(MigrationRunError::Preflight)?;

    // A fresh independently attested attempt first checks whether an earlier
    // attempt with the same release/target/inventory projection already left
    // its atomic completion witness. This is the only automatic path after a
    // lost COMMIT acknowledgement: it performs no migration or marker write.
    if preflight_ledger.len() == expected_embedded_migrations().len() {
        attest_production_migration_operations_table(&mut transaction, &role_contract.expected)
            .await
            .map_err(MigrationRunError::Connect)?;
        if let Some(committed_marker) = read_production_migration_operation_marker(
            &mut transaction,
            &operation_marker.operation_id,
        )
        .await
        .map_err(MigrationRunError::Connect)?
        {
            if !marker_reconciles_exact_operation(&committed_marker, &operation_marker)
                .map_err(MigrationRunError::Preflight)?
            {
                return Err(MigrationRunError::Preflight(
                    "durable production migration marker does not match the freshly attested release, target, and inventory"
                        .into(),
                ));
            }
            attest_application_acl(&mut transaction, &role_contract.application)
                .await
                .map_err(MigrationRunError::Privileges)?;
            let mut inventory = verify_embedded_migrations_on_connection(&mut transaction).await?;
            if inventory.content_digest != execution.expected_migration_inventory_digest() {
                return Err(MigrationRunError::Admission(
                    "durable operation marker exists but the exact final migration inventory differs"
                        .into(),
                ));
            }
            let final_binding = read_postgresql_migration_session_binding(
                &mut transaction,
                &application_name,
                execution.role_contract(),
                tls_channel_binding,
            )
            .await
            .map_err(MigrationRunError::Preflight)?;
            if final_binding != initial {
                return Err(MigrationRunError::Preflight(
                    "exact PostgreSQL backend row changed during commit reconciliation".into(),
                ));
            }
            verify_attested_migration_session_projection(&execution, &final_binding)
                .map_err(MigrationRunError::Preflight)?;
            execution
                .ensure_fresh(Utc::now())
                .map_err(MigrationRunError::Admission)?;
            let completion = execution.completion_evidence();
            // The pre-BEGIN session lock was explicitly replaced by an
            // advisory xact lock before this reconciliation path ran. A lost
            // ROLLBACK response cannot invalidate the already-read durable
            // commit witness.
            let _ = transaction.rollback().await;
            inventory.production_attestation = Some(completion);
            inventory.production_operation = Some(ProductionMigrationOperationReceipt {
                operation_id: operation_marker.operation_id,
                reconciled_after_prior_attempt: true,
            });
            return Ok(inventory);
        }
    }

    let remaining_ddl_timeout = limits
        .deadline_at
        .signed_duration_since(Utc::now())
        .to_std()
        .map_err(|_| {
            MigrationRunError::Admission(
                "PostgreSQL proof safety deadline elapsed before the DDL wave".into(),
            )
        })?
        .min(limits.whole_wave_timeout);
    let wave = async move {
        set_local_migration_timeouts(
            &mut transaction,
            limits.statement_timeout_millis,
            limits.lock_timeout_millis,
        )
        .await
        .map_err(MigrationRunError::Connect)?;
        apply_atomic_embedded_migrations(
            &mut transaction,
            execution.role_contract(),
            &preflight_ledger,
        )
        .await?;
        reconcile_application_privileges_in_transaction(
            &mut transaction,
            execution.role_contract(),
        )
        .await
        .map_err(MigrationRunError::Privileges)?;
        attest_sqlx_migrations_table(&mut transaction, &role_contract.expected).await?;
        let inventory = verify_embedded_migrations_on_connection(&mut transaction).await?;
        if inventory.content_digest != execution.expected_migration_inventory_digest() {
            return Err(MigrationRunError::Admission(
                "verified post-migration ledger differs from the admitted inventory".into(),
            ));
        }
        attest_production_migration_operations_table(&mut transaction, &role_contract.expected)
            .await
            .map_err(MigrationRunError::Connect)?;
        let final_binding = read_postgresql_migration_session_binding(
            &mut transaction,
            &application_name,
            execution.role_contract(),
            tls_channel_binding,
        )
        .await
        .map_err(MigrationRunError::Preflight)?;
        if final_binding != initial {
            return Err(MigrationRunError::Preflight(
                "exact PostgreSQL backend row changed during atomic migration execution".into(),
            ));
        }
        verify_attested_migration_session_projection(&execution, &final_binding)
            .map_err(MigrationRunError::Preflight)?;
        execution
            .ensure_fresh(Utc::now())
            .map_err(MigrationRunError::Admission)?;
        if Utc::now() >= limits.deadline_at {
            return Err(MigrationRunError::Admission(
                "atomic migration reached the proof safety margin before commit".into(),
            ));
        }
        insert_production_migration_operation_marker(&mut transaction, &operation_marker)
            .await
            .map_err(MigrationRunError::Connect)?;
        let retained_marker = read_production_migration_operation_marker(
            &mut transaction,
            &operation_marker.operation_id,
        )
        .await
        .map_err(MigrationRunError::Connect)?
        .ok_or_else(|| {
            MigrationRunError::Preflight(
                "production migration operation marker was not retained in the atomic transaction"
                    .into(),
            )
        })?;
        if retained_marker != operation_marker {
            return Err(MigrationRunError::Preflight(
                "production migration operation marker changed before commit".into(),
            ));
        }
        execution
            .ensure_fresh(Utc::now())
            .map_err(MigrationRunError::Admission)?;
        if Utc::now() >= limits.deadline_at {
            return Err(MigrationRunError::Admission(
                "atomic migration reached the proof safety margin before commit dispatch".into(),
            ));
        }
        Ok::<_, MigrationRunError>((transaction, inventory, execution, operation_marker))
    };
    let (transaction, mut inventory, execution, operation_marker) =
        tokio::time::timeout(remaining_ddl_timeout, wave)
            .await
            .map_err(|_| {
                MigrationRunError::Admission(
                    "atomic production migration exceeded the proof-bounded whole-wave deadline"
                        .into(),
                )
            })??;

    // Every DDL statement, ledger row, ACL reconciliation, final inventory
    // check, and durable operation marker is complete before COMMIT is sent.
    // COMMIT acknowledgement is deliberately outside the proof-bounded DDL
    // future: once dispatched, timeout or connection error is not evidence of
    // rollback and must never be mapped to the ordinary pre-commit error path.
    let commit_dispatch_check_at = Utc::now();
    execution
        .ensure_fresh(commit_dispatch_check_at)
        .map_err(MigrationRunError::Admission)?;
    if commit_dispatch_check_at >= limits.deadline_at {
        return Err(MigrationRunError::Admission(
            "atomic migration reached the proof safety margin before COMMIT dispatch".into(),
        ));
    }
    let completion = execution.completion_evidence();
    let remaining_commit_millis = proof_valid_until
        .signed_duration_since(Utc::now())
        .num_milliseconds();
    if remaining_commit_millis < 2 {
        return Err(MigrationRunError::Admission(
            "PostgreSQL proof expired before COMMIT could be dispatched".into(),
        ));
    }
    let commit_ack_timeout = Duration::from_millis(
        u64::try_from(remaining_commit_millis - 1)
            .unwrap_or(0)
            .min(PRODUCTION_MIGRATION_COMMIT_ACK_TIMEOUT_SECS * 1_000),
    );
    match tokio::time::timeout(commit_ack_timeout, transaction.commit()).await {
        Ok(Ok(())) => {
            inventory.production_attestation = Some(completion);
            inventory.production_operation = Some(ProductionMigrationOperationReceipt {
                operation_id: operation_marker.operation_id,
                reconciled_after_prior_attempt: false,
            });
            Ok(inventory)
        }
        Ok(Err(source)) => Err(MigrationRunError::CommitOutcomeUnknown {
            operation_id: operation_marker.operation_id,
            reason: "PostgreSQL returned an error after COMMIT was dispatched",
            source: Some(source),
        }),
        Err(_) => Err(MigrationRunError::CommitOutcomeUnknown {
            operation_id: operation_marker.operation_id,
            reason: "the bounded COMMIT acknowledgement deadline elapsed",
            source: None,
        }),
    }
}

async fn apply_embedded_production_migrations(
    url: &str,
    timeouts: MigrationTimeouts,
    pending: crate::security_contracts::PendingProductionMigrationTarget,
) -> Result<MigrationInventory, MigrationRunError> {
    validate_atomic_embedded_migration_plan().map_err(MigrationRunError::Preflight)?;
    // Reject an unreviewed production timeout profile before DNS, TLS, or
    // database authentication touches the selected target.
    production_migration_preflight_timeouts(timeouts).map_err(MigrationRunError::Admission)?;
    let target = production_migration_target(url).map_err(MigrationRunError::Target)?;
    let (database_provider, expected_route_digest) = pending
        .database_provider_and_route_digest()
        .map_err(MigrationRunError::Admission)?;
    let established = target
        .establish(
            database_provider,
            expected_route_digest,
            pending.tls_exporter_context(),
        )
        .await
        .map_err(|error| MigrationRunError::Target(error.to_string()))?;
    let application_name = pending
        .request_tag_for_channel(established.binding())
        .map_err(MigrationRunError::Admission)?;
    let mut channel = established
        .connect_sqlx(&application_name)
        .await
        .map_err(|error| MigrationRunError::Target(error.to_string()))?;
    if !channel.relay_is_active() {
        channel.close_hard().await;
        return Err(MigrationRunError::Target(
            "direct PostgreSQL TLS relay terminated before migration preflight".into(),
        ));
    }
    let tls_channel_binding = channel.binding().clone();
    let result = run_atomic_production_migration(
        channel.connection_mut(),
        &tls_channel_binding,
        timeouts,
        pending,
    )
    .await;
    match result {
        Ok(inventory) => {
            // Commit already succeeded; a graceful-close transport error
            // cannot retroactively turn the atomic database outcome partial.
            channel.close().await;
            Ok(inventory)
        }
        Err(error) => {
            let failure_boundary = if error.commit_outcome_unknown() {
                ProductionMigrationFailureBoundary::CommitDispatched
            } else {
                ProductionMigrationFailureBoundary::BeforeCommitDispatch
            };
            match classify_production_migration_failure(failure_boundary) {
                ProductionMigrationFailureDisposition::RollbackExpected => {
                    // Before COMMIT dispatch, dropping the outer transaction
                    // and terminating the backend is the cancellation fence.
                    channel.close_hard().await;
                }
                ProductionMigrationFailureDisposition::OutcomeUnknown => {
                    // COMMIT was already sent. Hard-closing bounds the broken
                    // transport but is not, and must never be reported as, a
                    // rollback. A fresh run can only reconcile the durable
                    // marker and exact final inventory for this operation id.
                    channel.close_hard().await;
                }
            }
            Err(error)
        }
    }
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

pub(crate) async fn apply_embedded_migrations_with_admission(
    url: &str,
    timeouts: MigrationTimeouts,
    admission: crate::security_contracts::VerifiedApplyOnlyMigrationAdmission,
) -> Result<MigrationInventory, MigrationRunError> {
    let result = async {
        let preflight = admission
            .into_database_preflight(Utc::now())
            .map_err(MigrationRunError::Admission)?;
        match preflight {
            crate::security_contracts::MigrationDatabasePreflight::NonProduction {
                role_contract,
                expected_migration_inventory_digest,
            } => {
                // Preserve the existing local/nonproduction pool path exactly;
                // the direct no-reconnect protocol is a production boundary.
                let inventory =
                    apply_embedded_migrations_inner(url, timeouts, Some(role_contract)).await?;
                if inventory.content_digest != expected_migration_inventory_digest {
                    return Err(MigrationRunError::Admission(
                        "verified post-migration ledger differs from the admitted inventory".into(),
                    ));
                }
                Ok(inventory)
            }
            crate::security_contracts::MigrationDatabasePreflight::Production(pending) => {
                apply_embedded_production_migrations(url, timeouts, *pending).await
            }
        }
    }
    .await;
    set_migration_status(if result.is_ok() {
        MigrationStatus::Applied
    } else {
        MigrationStatus::Failed
    });
    result
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
        build_application_pool, build_migration_pool, embedded_migration_inventory_digest,
        expected_embedded_migrations, get_db, live_platform_health, migration_status,
        set_migration_status_for_test, try_connect_with_url,
        verify_embedded_migrations_on_connection, verify_migration_inventory, MigrationStartupMode,
        MigrationStatus, MigrationTimeouts, MigrationVerificationError, DB_TEST_SERIAL,
    };
    use ryuki_engine::health_monitor::{HealthSource, HealthStatus};
    use sha2::Digest as _;
    use sqlx::{Connection, PgConnection};

    struct TestVerifiedPostgresqlInfrastructureEvidence {
        valid: std::sync::atomic::AtomicBool,
        deployment_id: String,
        trust_domain_id: String,
        database_provider: ryuki_core::security_profile::ProductionDatabaseProvider,
        attestation_profile_id: String,
        attestation_profile_version: u64,
        attestation_profile_digest: String,
        provider_route_binding_digest: String,
        cluster_system_identifier: String,
        storage_bindings: Vec<ryuki_core::security_profile::PostgresqlStorageBinding>,
    }

    impl super::VerifiedPostgresqlInfrastructureEvidence
        for TestVerifiedPostgresqlInfrastructureEvidence
    {
        fn verify_integrity(&self) -> Result<(), String> {
            self.valid
                .load(std::sync::atomic::Ordering::Acquire)
                .then_some(())
                .ok_or_else(|| "test evidence invalidated".into())
        }

        fn deployment_id(&self) -> &str {
            &self.deployment_id
        }

        fn trust_domain_id(&self) -> &str {
            &self.trust_domain_id
        }

        fn database_provider(&self) -> ryuki_core::security_profile::ProductionDatabaseProvider {
            self.database_provider
        }

        fn attestation_profile_id(&self) -> &str {
            &self.attestation_profile_id
        }

        fn attestation_profile_version(&self) -> u64 {
            self.attestation_profile_version
        }

        fn attestation_profile_digest(&self) -> &str {
            &self.attestation_profile_digest
        }

        fn provider_route_binding_digest(&self) -> &str {
            &self.provider_route_binding_digest
        }

        fn cluster_system_identifier(&self) -> &str {
            &self.cluster_system_identifier
        }

        fn storage_bindings(&self) -> &[ryuki_core::security_profile::PostgresqlStorageBinding] {
            &self.storage_bindings
        }
    }

    fn durable_postgresql_verification_fixture() -> (
        super::UnpublishedPostgresqlRuntime,
        std::sync::Arc<TestVerifiedPostgresqlInfrastructureEvidence>,
        ryuki_core::security_profile::RuntimeGuardExpectedValue,
    ) {
        use ryuki_core::security_profile::{
            postgresql_database_identity_digest, postgresql_migration_inventory_digest,
            postgresql_storage_binding_digest, PostgresqlDatabaseIdentity,
            PostgresqlMigrationInventoryRow, PostgresqlStorageBinding, PostgresqlStoragePurpose,
            ProductionDatabaseProvider, RuntimeGuardExpectedValue,
        };

        fn digest(character: char) -> String {
            format!("sha256:{}", character.to_string().repeat(64))
        }

        let roles = super::ProductionDatabaseRoles::new(
            "ryuki_app_runtime".into(),
            "ryuki_schema_migrator".into(),
        )
        .unwrap();
        let checksum = b"embedded-migration-checksum".to_vec();
        let observation = std::sync::Arc::new(super::PostgresqlRuntimeObservation {
            server_version_num: 180_002,
            server_version: "18.2".into(),
            server_major_version: 18,
            database_name: "ryuki".into(),
            database_oid: 16_384,
            server_address: "192.0.2.10".parse().unwrap(),
            server_port: 5432,
            primary: true,
            transaction_writable: true,
            default_transaction_writable: true,
            application_role: roles.application_role.clone(),
            migration_role: roles.migration_role.clone(),
            session_login_role: "ryuki_login_20260720".into(),
            tls: super::PostgresqlTlsObservation {
                protocol: "TLSv1.3".into(),
                cipher: "TLS_AES_256_GCM_SHA384".into(),
                bits: 256,
                client_distinguished_name: None,
                issuer_distinguished_name: None,
            },
            migration_ledger: vec![super::PostgresqlMigrationLedgerRow {
                version: 196,
                checksum: checksum.clone().into_boxed_slice(),
            }]
            .into_boxed_slice(),
        });
        let roles = std::sync::Arc::new(roles);
        let retained = super::RetainedPostgresqlRuntime {
            pool: std::sync::Arc::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgresql://placeholder@example.invalid/ryuki")
                    .unwrap(),
            ),
            observation,
            roles: roles.clone(),
            connection_binding: std::sync::Arc::new(
                super::ProductionDatabaseConnectionBinding::new(roles),
            ),
        };
        let storage_bindings = vec![PostgresqlStorageBinding {
            purpose: PostgresqlStoragePurpose::Data,
            provider_cluster_uid_digest: digest('1'),
            persistent_volume_claim_uid_digest: digest('2'),
            persistent_volume_uid_digest: digest('3'),
            csi_driver: "storage.csi.example.test".into(),
            volume_handle_digest: digest('4'),
            storage_class: "encrypted-rwo".into(),
        }];
        let evidence = std::sync::Arc::new(TestVerifiedPostgresqlInfrastructureEvidence {
            valid: std::sync::atomic::AtomicBool::new(true),
            deployment_id: "deployment:production".into(),
            trust_domain_id: "trust-domain:production".into(),
            database_provider: ProductionDatabaseProvider::CloudNativePg,
            attestation_profile_id: "postgresql-infrastructure-attestation-profile:production-v1"
                .into(),
            attestation_profile_version: 1,
            attestation_profile_digest: digest('9'),
            provider_route_binding_digest: digest('8'),
            cluster_system_identifier: "7482247594438774091".into(),
            storage_bindings: storage_bindings.clone(),
        });
        let identity = PostgresqlDatabaseIdentity {
            deployment_id: evidence.deployment_id.clone(),
            trust_domain_id: evidence.trust_domain_id.clone(),
            database_provider: evidence.database_provider,
            database_name: "ryuki".into(),
            database_oid: 16_384,
            cluster_system_identifier: evidence.cluster_system_identifier.clone(),
            server_address: "192.0.2.10".into(),
            server_port: 5432,
            tls_enabled: true,
            tls_protocol: "tlsv1.3".into(),
            tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
            tls_cipher_bits: 256,
            server_major_version: 18,
            primary: true,
            writable: true,
        };
        let migrations = vec![PostgresqlMigrationInventoryRow {
            version: 196,
            checksum_digest: format!("sha256:{:x}", sha2::Sha256::digest(checksum)),
        }];
        let expected = RuntimeGuardExpectedValue::DurablePostgresql {
            database_provider: ProductionDatabaseProvider::CloudNativePg,
            server_major_version: 18,
            attestation_profile_id: evidence.attestation_profile_id.clone(),
            attestation_profile_version: evidence.attestation_profile_version,
            attestation_profile_digest: evidence.attestation_profile_digest.clone(),
            provider_route_binding_digest: evidence.provider_route_binding_digest.clone(),
            database_identity_digest: postgresql_database_identity_digest(&identity).unwrap(),
            storage_binding_digest: postgresql_storage_binding_digest(&storage_bindings).unwrap(),
            migration_inventory_digest: postgresql_migration_inventory_digest(&migrations).unwrap(),
            application_role: "ryuki_app_runtime".into(),
            migration_role: "ryuki_schema_migrator".into(),
        };
        (
            super::UnpublishedPostgresqlRuntime { retained },
            evidence,
            expected,
        )
    }

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
    fn production_migration_url_requires_one_dns_tls_target() {
        let target = super::production_migration_target(
            "postgresql://ephemeral_login:fixture%2Dvalue@postgresql.database.svc:6432/ryuki?sslmode=verify-full&sslrootcert=/var/run/ryuki/postgresql-ca.pem",
        )
        .expect("canonical DNS target with explicit credential, port, database, and CA");
        let (hostname, port, username, database, root_certificate_path) = target.test_projection();
        assert_eq!(hostname, "postgresql.database.svc");
        assert_eq!(port, 6432);
        assert_eq!(username, "ephemeral_login");
        assert_eq!(database, "ryuki");
        assert_eq!(
            root_certificate_path,
            std::path::Path::new("/var/run/ryuki/postgresql-ca.pem")
        );

        for invalid in [
            // Credentials and target selection must never fall back to ambient
            // libpq defaults or a pgpass file.
            "postgresql://login@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@postgresql.database.svc/ryuki?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@192.0.2.10:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@[2001:db8::10]:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@postgresql.database.svc:5432/?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@postgresql.database.svc:5432/postgres?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki/other?sslmode=verify-full&sslrootcert=/ca.pem",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=require&sslrootcert=/ca.pem",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=relative-ca.pem",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem&host=/var/run/postgresql",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem&hostaddr=192.0.2.10",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem&dbname=substitute",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem&password=x",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem&options=-c%20search_path%3Devil",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslrootcert=/ca.pem&application_name=override",
            "postgresql://login:fixture@postgresql.database.svc:5432/ryuki?sslmode=verify-full&sslmode=disable&sslrootcert=/ca.pem",
        ] {
            assert!(
                super::production_migration_target(invalid).is_err(),
                "unsafe migration target was accepted: {invalid}"
            );
        }
    }

    #[test]
    fn production_migration_deadline_preserves_proof_safety_margin() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-20T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let valid_until = now + chrono::TimeDelta::seconds(300);
        let limits = super::production_migration_wave_limits(
            now,
            valid_until,
            super::MigrationTimeouts {
                statement_timeout_secs: super::REVIEWED_PRODUCTION_MIGRATION_STATEMENT_TIMEOUT_SECS,
                lock_timeout_secs: super::REVIEWED_PRODUCTION_MIGRATION_LOCK_TIMEOUT_SECS,
            },
        )
        .expect("five-minute proof window");
        assert_eq!(
            limits.deadline_at,
            valid_until - chrono::TimeDelta::seconds(30)
        );
        assert_eq!(
            limits.whole_wave_timeout,
            std::time::Duration::from_secs(270)
        );
        assert_eq!(limits.statement_timeout_millis, 180_000);
        assert_eq!(limits.lock_timeout_millis, 30_000);
        assert!(limits.statement_timeout_millis < 270_000);
        assert!(limits.lock_timeout_millis < limits.statement_timeout_millis);

        assert!(super::production_migration_wave_limits(
            now,
            now + chrono::TimeDelta::seconds(31),
            super::MigrationTimeouts {
                statement_timeout_secs: super::REVIEWED_PRODUCTION_MIGRATION_STATEMENT_TIMEOUT_SECS,
                lock_timeout_secs: super::REVIEWED_PRODUCTION_MIGRATION_LOCK_TIMEOUT_SECS,
            },
        )
        .is_err());
    }

    #[test]
    fn atomic_migration_shape_rejects_down_no_tx_and_order_anomalies() {
        assert!(
            super::validate_atomic_migration_shape(&[(1, false, false), (2, false, false)]).is_ok()
        );
        for invalid in [
            vec![],
            vec![(0, false, false)],
            vec![(2, false, false), (1, false, false)],
            vec![(1, false, false), (1, false, false)],
            vec![(1, true, false)],
            vec![(1, false, true)],
        ] {
            assert!(
                super::validate_atomic_migration_shape(&invalid).is_err(),
                "unsafe migration shape was accepted"
            );
        }
    }

    #[test]
    fn atomic_migration_sql_scanner_rejects_outer_transaction_escape() {
        for unsafe_sql in [
            "BEGIN; SELECT 1;",
            "START/**/TRANSACTION;",
            "START-- split keyword\nTRANSACTION;",
            "SELECT 1; COMMIT;",
            "SELECT 1; END WORK;",
            "ROLLBACK TO SAVEPOINT before_ddl;",
            "ABORT;",
            "SAVEPOINT before_ddl;",
            "RELEASE SAVEPOINT before_ddl;",
            "PREPARE TRANSACTION 'partial-ddl';",
            "SET TRANSACTION READ ONLY;",
            "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;",
            "SET SESSION AUTHORIZATION 'untrusted';",
            "SET LOCAL SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;",
            "SET LOCAL SESSION AUTHORIZATION 'untrusted';",
            "SET LOCAL ROLE untrusted;",
            "sEt/**/\"statement_timeout\" = 0;",
            "SET search_path = untrusted, public;",
            "SET statement_timeout = 0;",
            "SET LOCAL lock_timeout = '31s';",
            "SET LOCAL lock_timeout = E'30s';",
            "SET LOCAL \"lock_timeout\" = '30s';",
            "SET SESSION idle_in_transaction_session_timeout = 0;",
            "SET default_transaction_read_only = on;",
            "SET standard_conforming_strings = off;",
            "RESET ALL;",
            "RESET statement_timeout;",
            "DISCARD ALL;",
            "LOAD '/tmp/unreviewed-extension.so';",
            "COPY public.audit_log TO PROGRAM 'id';",
            "COPY (SELECT 'PROGRAM') TO/**/PROGRAM E'id';",
            "SET LOCAL lock_timeout = '30s'; COMMIT;",
            r"SELECT 'a\'b'; COMMIT; SELECT 'c\'d';",
        ] {
            assert!(
                super::validate_atomic_migration_sql(unsafe_sql).is_err(),
                "outer-transaction escape was accepted: {unsafe_sql}"
            );
        }
    }

    #[test]
    fn atomic_migration_sql_scanner_rejects_session_lock_release_anywhere() {
        for unsafe_sql in [
            "SELECT pg_catalog.pg_advisory_unlock_all();",
            "SELECT pg_catalog.pg_advisory_unlock(8248622371235458407::bigint);",
            "DO $$ BEGIN PERFORM pg_catalog.pg_advisory_unlock_all(); END $$;",
            "DO $body$ BEGIN PERFORM \"pg_advisory_unlock\"(1::bigint); END $body$;",
        ] {
            assert!(
                super::validate_atomic_migration_sql(unsafe_sql).is_err(),
                "session advisory-lock release was accepted: {unsafe_sql}"
            );
        }

        assert!(super::validate_atomic_migration_sql(
            "SELECT pg_catalog.pg_advisory_xact_lock(1::bigint);"
        )
        .is_ok());
    }

    #[test]
    fn atomic_migration_sql_scanner_rejects_parser_mode_hidden_commit() {
        assert!(
            super::validate_atomic_migration_sql("SET standard_conforming_strings = off;").is_err()
        );
        assert!(
            super::validate_atomic_migration_sql(r"SELECT 'a\'b'; COMMIT; SELECT 'c\'d';").is_err()
        );
    }

    #[test]
    fn atomic_migration_sql_scanner_ignores_quoted_and_nested_decoys() {
        for safe_sql in [
            "-- COMMIT; SET ROLE untrusted;\nSELECT 1;",
            "/* COMMIT; /* ROLLBACK; */ SET statement_timeout = 0; */ SELECT 1;",
            "SELECT 'COMMIT; SET ROLE untrusted; COPY t TO PROGRAM ''id''';",
            r"SELECT E'escaped quote \' ; COMMIT; SET ROLE untrusted';",
            "CREATE TABLE \"COMMIT;ROLLBACK\" (id bigint PRIMARY KEY);",
            "DO $body$ BEGIN PERFORM 1; END $body$;",
            "DO $tag_1$ BEGIN COPY t TO PROGRAM 'id'; END $tag_1$;",
            "CREATE FUNCTION public.decoy() RETURNS text AS 'BEGIN; COMMIT; END' LANGUAGE sql;",
            "UPDATE public.jobs SET role_name = 'migration' WHERE id = 1;",
            "CREATE FUNCTION public.pinned() RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$ BEGIN NULL; END $$;",
            "COPY (SELECT 'PROGRAM') TO STDOUT;",
            "PREPARE reviewed_query AS SELECT 1;",
            "SET CONSTRAINTS ALL IMMEDIATE;",
            "SET LOCAL lock_timeout = '30s';",
        ] {
            assert!(
                super::validate_atomic_migration_sql(safe_sql).is_ok(),
                "quoted or legitimate SQL was rejected: {safe_sql}"
            );
        }

        super::validate_atomic_embedded_migration_plan()
            .expect("current embedded migrations remain atomically admissible");
    }

    #[test]
    fn atomic_migration_sql_scanner_enforces_lexical_bounds() {
        for malformed in [
            "SELECT 'unterminated",
            "SELECT E'unterminated\\'",
            "SELECT \"unterminated",
            "SELECT $body$ unterminated",
            "SELECT 1 /* unterminated",
            "SELECT (1;",
            "SELECT 1);",
        ] {
            assert!(
                super::validate_atomic_migration_sql(malformed).is_err(),
                "malformed SQL escaped lexical validation: {malformed}"
            );
        }

        let overlong = " ".repeat(super::MAX_ATOMIC_MIGRATION_SQL_BYTES + 1);
        assert!(super::validate_atomic_migration_sql(&overlong).is_err());

        let mut nested_comment = String::new();
        for _ in 0..=super::MAX_ATOMIC_MIGRATION_BLOCK_COMMENT_DEPTH {
            nested_comment.push_str("/*");
        }
        for _ in 0..=super::MAX_ATOMIC_MIGRATION_BLOCK_COMMENT_DEPTH {
            nested_comment.push_str("*/");
        }
        assert!(super::validate_atomic_migration_sql(&nested_comment).is_err());
    }

    #[test]
    fn production_preflight_timeouts_cannot_be_disabled_or_inverted() {
        assert_eq!(
            super::production_migration_preflight_timeouts(super::MigrationTimeouts {
                statement_timeout_secs: super::REVIEWED_PRODUCTION_MIGRATION_STATEMENT_TIMEOUT_SECS,
                lock_timeout_secs: super::REVIEWED_PRODUCTION_MIGRATION_LOCK_TIMEOUT_SECS,
            })
            .unwrap(),
            (30_000, 29_999)
        );
        for invalid in [
            super::MigrationTimeouts::default(),
            super::MigrationTimeouts {
                statement_timeout_secs: 0,
                lock_timeout_secs: 0,
            },
            super::MigrationTimeouts {
                statement_timeout_secs: 60,
                lock_timeout_secs: 60,
            },
            super::MigrationTimeouts {
                statement_timeout_secs: 7_201,
                lock_timeout_secs: 1,
            },
        ] {
            assert!(super::production_migration_preflight_timeouts(invalid).is_err());
        }
    }

    #[test]
    fn commit_dispatch_failures_are_never_classified_as_rollback() {
        assert_eq!(
            super::classify_production_migration_failure(
                super::ProductionMigrationFailureBoundary::BeforeCommitDispatch,
            ),
            super::ProductionMigrationFailureDisposition::RollbackExpected,
        );
        assert_eq!(
            super::classify_production_migration_failure(
                super::ProductionMigrationFailureBoundary::CommitDispatched,
            ),
            super::ProductionMigrationFailureDisposition::OutcomeUnknown,
        );
    }

    #[test]
    fn session_lock_must_precede_repeatable_read_snapshot() {
        use super::{
            ProductionMigrationSnapshotEvent as Event, ProductionMigrationSnapshotState as State,
        };

        let locked = super::advance_production_migration_snapshot_state(
            State::Connected,
            Event::SessionLockAcquired,
        )
        .expect("session lock is the first transition");
        assert_eq!(
            super::advance_production_migration_snapshot_state(
                locked,
                Event::RepeatableReadStarted,
            ),
            Ok(State::RepeatableReadStarted)
        );
        assert!(super::advance_production_migration_snapshot_state(
            State::Connected,
            Event::RepeatableReadStarted,
        )
        .is_err());
    }

    #[test]
    fn production_operation_marker_is_stable_across_fresh_attestation_readback() {
        fn digest(character: char) -> String {
            format!("sha256:{}", character.to_string().repeat(64))
        }

        fn marker(response: char, session: char) -> super::ProductionMigrationOperationMarker {
            let release_binding_digest = digest('1');
            let target_binding_digest = digest('2');
            let migration_inventory_digest = digest('3');
            let operation_id = super::framed_migration_digest(
                super::PRODUCTION_MIGRATION_OPERATION_ID_CONTRACT,
                &[
                    ("release_binding_digest", &release_binding_digest),
                    ("target_binding_digest", &target_binding_digest),
                    ("migration_inventory_digest", &migration_inventory_digest),
                ],
            );
            super::ProductionMigrationOperationMarker {
                operation_id,
                release_binding_digest,
                target_binding_digest,
                migration_inventory_digest,
                attestation_response_digest: digest(response),
                session_binding_digest: digest(session),
            }
        }

        let committed = marker('4', '5');
        let freshly_attested = marker('6', '7');
        assert!(super::validate_production_migration_operation_marker(&committed).is_ok());
        assert!(
            super::marker_reconciles_exact_operation(&committed, &freshly_attested)
                .expect("canonical marker projection")
        );

        let mut different_target = freshly_attested.clone();
        different_target.target_binding_digest = digest('8');
        different_target.operation_id = super::framed_migration_digest(
            super::PRODUCTION_MIGRATION_OPERATION_ID_CONTRACT,
            &[
                (
                    "release_binding_digest",
                    &different_target.release_binding_digest,
                ),
                (
                    "target_binding_digest",
                    &different_target.target_binding_digest,
                ),
                (
                    "migration_inventory_digest",
                    &different_target.migration_inventory_digest,
                ),
            ],
        );
        assert!(
            !super::marker_reconciles_exact_operation(&committed, &different_target)
                .expect("canonical substituted target projection")
        );

        let mut forged = committed;
        forged.operation_id = digest('f');
        assert!(super::validate_production_migration_operation_marker(&forged).is_err());
    }

    #[test]
    fn production_operation_target_binding_includes_provider_route() {
        fn digest(character: char) -> String {
            format!("sha256:{}", character.to_string().repeat(64))
        }

        let first_route = super::production_migration_target_binding_digest(
            ryuki_core::security_profile::ProductionDatabaseProvider::CloudNativePg,
            &digest('1'),
            18,
            &digest('2'),
            &digest('3'),
            "ryuki_app_runtime",
            "ryuki_schema_migrator",
        );
        let substituted_route = super::production_migration_target_binding_digest(
            ryuki_core::security_profile::ProductionDatabaseProvider::CloudNativePg,
            &digest('4'),
            18,
            &digest('2'),
            &digest('3'),
            "ryuki_app_runtime",
            "ryuki_schema_migrator",
        );
        assert_ne!(first_route, substituted_route);
    }

    #[test]
    fn migration_session_binding_validation_rejects_substitution() {
        fn valid_channel() -> ryuki_core::postgresql_infrastructure::PostgresqlTlsChannelBinding {
            ryuki_core::postgresql_infrastructure::PostgresqlTlsChannelBinding {
                provider_route_binding_digest: format!("sha256:{}", "1".repeat(64)),
                server_name: "postgresql.database.svc".into(),
                peer_address: "192.0.2.10".into(),
                peer_port: 5432,
                trust_anchor_bundle_digest: format!("sha256:{}", "2".repeat(64)),
                peer_leaf_certificate_digest: format!("sha256:{}", "3".repeat(64)),
                peer_certificate_chain_digest: format!("sha256:{}", "4".repeat(64)),
                exporter_digest: format!("sha256:{}", "5".repeat(64)),
                tls_protocol: "tlsv1.3".into(),
                tls_cipher_suite: "tls_aes_256_gcm_sha384".into(),
                tls_cipher_bits: 256,
            }
        }

        fn valid_raw() -> super::RawPostgresqlMigrationSessionBinding {
            super::RawPostgresqlMigrationSessionBinding {
                server_version_num: 180_002,
                database_name: "ryuki".into(),
                database_oid: 16_384,
                datid: Some(16_384),
                server_address: Some("192.0.2.10".into()),
                server_port: Some(5432),
                primary: true,
                transaction_writable: true,
                default_transaction_writable: true,
                client_address: Some("192.0.2.20".into()),
                client_port: Some(42_424),
                backend_process_id: 8123,
                backend_start: chrono::DateTime::parse_from_rfc3339("2026-07-20T08:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                backend_type: "client backend".into(),
                application_name: "ryuki-pg-attest-0123456789abcdef0123456789abcdef01234567".into(),
                session_login_role: "ryuki_login_20260720".into(),
                session_user_oid: Some(32_768),
                current_role: "ryuki_schema_migrator".into(),
                selected_role: "ryuki_schema_migrator".into(),
                tls_enabled: Some(true),
                tls_protocol: Some("TLSv1.3".into()),
                tls_cipher: Some("TLS_AES_256_GCM_SHA384".into()),
                tls_bits: Some(256),
                client_distinguished_name: None,
                issuer_distinguished_name: None,
            }
        }

        let tag = "ryuki-pg-attest-0123456789abcdef0123456789abcdef01234567";
        let contract = super::MigrationRoleContract::from_values(
            "ryuki_schema_migrator".into(),
            "ryuki_app_runtime".into(),
        )
        .unwrap();
        let channel = valid_channel();
        let binding = super::validate_postgresql_migration_session_binding(
            valid_raw(),
            tag,
            &contract,
            &channel,
        )
        .expect("exact migration backend session");
        assert_eq!(binding.tls_protocol, "tlsv1.3");
        assert_eq!(binding.tls_cipher_suite, "tls_aes_256_gcm_sha384");
        assert!(
            ryuki_core::postgresql_infrastructure::postgresql_session_binding_digest(&binding)
                .is_ok()
        );

        let mut dnat_channel = valid_channel();
        dnat_channel.peer_address = "192.0.2.11".into();
        assert!(
            super::validate_postgresql_migration_session_binding(
                valid_raw(),
                tag,
                &contract,
                &dnat_channel,
            )
            .is_ok(),
            "the signed channel entry address may differ from the PostgreSQL backend behind reviewed DNAT"
        );

        let mut wrong_tag = valid_raw();
        wrong_tag.application_name =
            "ryuki-pg-attest-ffffffffffffffffffffffffffffffffffffffff".into();
        assert!(super::validate_postgresql_migration_session_binding(
            wrong_tag, tag, &contract, &channel,
        )
        .is_err());
        let mut wrong_database = valid_raw();
        wrong_database.datid = Some(16_385);
        assert!(super::validate_postgresql_migration_session_binding(
            wrong_database,
            tag,
            &contract,
            &channel,
        )
        .is_err());
        let mut unix = valid_raw();
        unix.client_address = None;
        assert!(super::validate_postgresql_migration_session_binding(
            unix, tag, &contract, &channel
        )
        .is_err());
        let mut standby = valid_raw();
        standby.primary = false;
        assert!(super::validate_postgresql_migration_session_binding(
            standby, tag, &contract, &channel,
        )
        .is_err());
        let mut wrong_role = valid_raw();
        wrong_role.selected_role = "ryuki_app_runtime".into();
        assert!(super::validate_postgresql_migration_session_binding(
            wrong_role, tag, &contract, &channel,
        )
        .is_err());
        let mut weak_tls = valid_raw();
        weak_tls.tls_bits = Some(64);
        assert!(super::validate_postgresql_migration_session_binding(
            weak_tls, tag, &contract, &channel,
        )
        .is_err());

        let mut wrong_channel = channel;
        wrong_channel.tls_cipher_suite = "tls_aes_128_gcm_sha256".into();
        wrong_channel.tls_cipher_bits = 128;
        assert!(super::validate_postgresql_migration_session_binding(
            valid_raw(),
            tag,
            &contract,
            &wrong_channel,
        )
        .is_err());
    }

    #[test]
    fn production_preflight_ledger_accepts_only_an_exact_embedded_prefix() {
        let expected = expected_embedded_migrations();
        assert!(expected.len() > 1);
        let complete = expected
            .iter()
            .map(|(version, checksum)| (*version, checksum.to_vec(), true))
            .collect::<Vec<_>>();
        assert!(super::verify_preflight_migration_inventory(&[]).is_ok());
        assert!(super::verify_preflight_migration_inventory(&complete[..2]).is_ok());
        assert!(super::verify_preflight_migration_inventory(&complete).is_ok());

        let gap = vec![complete[1].clone()];
        assert!(matches!(
            super::verify_preflight_migration_inventory(&gap),
            Err(MigrationVerificationError::NonPrefixApplied(_))
        ));
        let mut dirty = complete[..2].to_vec();
        dirty[1].2 = false;
        assert!(matches!(
            super::verify_preflight_migration_inventory(&dirty),
            Err(MigrationVerificationError::Dirty(_))
        ));
        let mut substituted = complete[..2].to_vec();
        substituted[0].1[0] ^= 0xff;
        assert!(matches!(
            super::verify_preflight_migration_inventory(&substituted),
            Err(MigrationVerificationError::ChecksumMismatch(_))
        ));
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
            "production_migration_operations",
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

    #[tokio::test]
    async fn local_durable_postgresql_verifier_binds_measured_runtime_and_external_authority() {
        let (unpublished, evidence, expected) = durable_postgresql_verification_fixture();
        let verified = super::verify_local_durable_postgresql_runtime(
            &unpublished,
            evidence.clone(),
            &expected,
        )
        .expect("exact local observation and authenticated infrastructure evidence must verify");

        assert!(verified
            .runtime()
            .same_runtime(&unpublished.retained_handle()));
        assert_eq!(verified.observed_value(), &expected);
        let _freshness_api = super::VerifiedLocalDurablePostgresqlRuntime::remeasure_exact;
        verified
            .recheck_retained_projection()
            .expect("retained evidence and digest projections must remain exact");

        let debug = format!("{verified:?}");
        for forbidden in [
            "deployment:production",
            "trust-domain:production",
            "7482247594438774091",
            "192.0.2.10",
            "ryuki_app_runtime",
            "ryuki_schema_migrator",
        ] {
            assert!(
                !debug.contains(forbidden),
                "verified runtime debug output leaked {forbidden}: {debug}"
            );
        }

        evidence
            .valid
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(matches!(
            verified.recheck_retained_projection(),
            Err(super::DurablePostgresqlRuntimeVerificationError::InfrastructureEvidenceInvalid)
        ));
    }

    #[tokio::test]
    async fn local_durable_postgresql_verifier_rejects_expectation_and_evidence_substitution() {
        let (unpublished, evidence, mut expected) = durable_postgresql_verification_fixture();
        let ryuki_core::security_profile::RuntimeGuardExpectedValue::DurablePostgresql {
            database_identity_digest,
            ..
        } = &mut expected
        else {
            unreachable!("fixture kind is fixed")
        };
        *database_identity_digest = format!("sha256:{}", "f".repeat(64));
        assert!(matches!(
            super::verify_local_durable_postgresql_runtime(&unpublished, evidence, &expected),
            Err(super::DurablePostgresqlRuntimeVerificationError::ExpectedValueMismatch)
        ));

        let (unpublished, evidence, expected) = durable_postgresql_verification_fixture();
        evidence
            .valid
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(matches!(
            super::verify_local_durable_postgresql_runtime(&unpublished, evidence, &expected),
            Err(super::DurablePostgresqlRuntimeVerificationError::InfrastructureEvidenceInvalid)
        ));

        let (unpublished, evidence, _) = durable_postgresql_verification_fixture();
        let wrong_kind = ryuki_core::security_profile::RuntimeGuardExpectedValue::SecureCookies {
            policies: Vec::new(),
            policy_inventory_digest: format!("sha256:{}", "e".repeat(64)),
        };
        assert!(matches!(
            super::verify_local_durable_postgresql_runtime(&unpublished, evidence, &wrong_kind),
            Err(super::DurablePostgresqlRuntimeVerificationError::ExpectedGuardKind)
        ));
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
        assert_eq!(
            complete.content_digest,
            embedded_migration_inventory_digest().unwrap()
        );

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
    async fn live_site_execution_authority_chain_is_attested_against_definition_drift() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let mut connection = PgConnection::connect(&url)
            .await
            .expect("connect live-site execution authority attestation test");
        super::EMBEDDED_MIGRATOR
            .run(&mut connection)
            .await
            .expect("apply live-site execution authority migrations");

        super::attest_live_site_execution_authority_chain(&mut connection)
            .await
            .expect("canonical live-site execution authority chain");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin component authority constraint drift fixture");
        sqlx::query(
            "ALTER TABLE public.component_status \
             DROP CONSTRAINT component_status_one_adapter_per_site",
        )
        .execute(&mut connection)
        .await
        .expect("drop component authority uniqueness inside drift fixture");
        let drift_error = super::attest_live_site_execution_authority_chain(&mut connection)
            .await
            .expect_err("component authority constraint drift must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("live-site execution authority definitions are not canonical"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical component authority uniqueness");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin live-mode constraint case-drift fixture");
        sqlx::query(
            "ALTER TABLE public.agent_jobs \
             DROP CONSTRAINT agent_jobs_open_live_site_fence_required",
        )
        .execute(&mut connection)
        .await
        .expect("drop canonical open-live constraint inside drift fixture");
        sqlx::query(
            r#"
            ALTER TABLE public.agent_jobs
            ADD CONSTRAINT agent_jobs_open_live_site_fence_required
            CHECK (
                mode NOT IN ('liveapply', 'livedestroy')
                OR status NOT IN ('pending', 'leased', 'running')
                OR site_status_authority_epoch IS NOT NULL
            )
            "#,
        )
        .execute(&mut connection)
        .await
        .expect("install case-drifted open-live constraint inside fixture");
        let drift_error = super::attest_live_site_execution_authority_chain(&mut connection)
            .await
            .expect_err("case-drifted live-mode literals must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("live-site execution authority definitions are not canonical"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical open-live constraint");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin acquisition routine drift fixture");
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION public.ryuki_acquire_live_site_execution_epoch(
                requested_site TEXT
            )
            RETURNS BIGINT
            LANGUAGE plpgsql
            VOLATILE
            SECURITY DEFINER
            SET search_path = pg_catalog, public, pg_temp
            AS $$
            BEGIN
                RETURN NULL;
            END;
            $$
            "#,
        )
        .execute(&mut connection)
        .await
        .expect("replace acquisition routine inside drift fixture");
        let drift_error = super::attest_live_site_execution_authority_chain(&mut connection)
            .await
            .expect_err("acquisition routine body drift must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("live-site execution authority definitions are not canonical"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical acquisition routine");

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin freshness-limit routine drift fixture");
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION public.ryuki_live_site_status_max_age_seconds()
            RETURNS BIGINT
            LANGUAGE SQL
            IMMUTABLE
            PARALLEL SAFE
            SET search_path = pg_catalog, public
            AS $$
                SELECT 301::BIGINT
            $$
            "#,
        )
        .execute(&mut connection)
        .await
        .expect("replace freshness-limit routine inside drift fixture");
        let drift_error = super::attest_live_site_execution_authority_chain(&mut connection)
            .await
            .expect_err("freshness-limit routine body drift must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("live-site execution authority definitions are not canonical"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical freshness-limit routine");

        for (table, trigger) in [
            ("site_status", "trg_site_status_authority_epoch"),
            ("site_registry", "trg_site_registry_live_execution_epoch"),
            ("component_status", "trg_component_status_observation"),
            (
                "component_status",
                "trg_component_status_live_execution_epoch",
            ),
            ("component_status", "trg_component_status_no_truncate"),
            ("site_status", "trg_site_status_no_delete"),
            ("site_status", "trg_site_status_no_truncate"),
        ] {
            sqlx::query("BEGIN")
                .execute(&mut connection)
                .await
                .expect("begin live-site trigger drift fixture");
            sqlx::query(&format!(
                "ALTER TABLE public.{table} DISABLE TRIGGER {trigger}"
            ))
            .execute(&mut connection)
            .await
            .expect("disable one live-site authority trigger");
            let drift_error = super::attest_live_site_execution_authority_chain(&mut connection)
                .await
                .expect_err("disabled live-site authority trigger must fail attestation");
            assert!(drift_error
                .to_string()
                .contains("live-site execution authority definitions are not canonical"));
            sqlx::query("ROLLBACK")
                .execute(&mut connection)
                .await
                .expect("restore canonical live-site authority trigger state");
        }

        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin upstream epoch trigger body drift fixture");
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION public.ryuki_bump_site_epoch_after_registry_change()
            RETURNS TRIGGER
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public, pg_temp
            AS $$
            BEGIN
                RETURN NEW;
            END;
            $$
            "#,
        )
        .execute(&mut connection)
        .await
        .expect("replace upstream epoch trigger function inside drift fixture");
        let drift_error = super::attest_live_site_execution_authority_chain(&mut connection)
            .await
            .expect_err("upstream epoch trigger body drift must fail attestation");
        assert!(drift_error
            .to_string()
            .contains("live-site execution authority definitions are not canonical"));
        sqlx::query("ROLLBACK")
            .execute(&mut connection)
            .await
            .expect("restore canonical upstream epoch trigger function");
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

        for trigger in [
            "trg_agent_jobs_request_resource_version_owned",
            "trg_agent_jobs_live_site_fence_persistence",
        ] {
            sqlx::query("BEGIN")
                .execute(&mut connection)
                .await
                .expect("begin binding trigger drift fixture");
            sqlx::query(&format!(
                "ALTER TABLE public.agent_jobs DISABLE TRIGGER {trigger}"
            ))
            .execute(&mut connection)
            .await
            .expect("disable one authority-binding trigger");
            let drift_error =
                super::attest_request_authority_version_binding_triggers(&mut connection)
                    .await
                    .expect_err("disabled binding trigger must fail attestation");
            assert!(drift_error
                .to_string()
                .contains("binding trigger definitions are not canonical and always enabled"));
            sqlx::query("ROLLBACK")
                .execute(&mut connection)
                .await
                .expect("restore canonical authority-binding trigger state");
        }

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
                "site_status_authority_epoch",
                "UPDATE public.agent_jobs \
                 SET site_status_authority_epoch = 1 WHERE id = $1",
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
        super::apply_embedded_migrations_inner(
            &migration_url,
            MigrationTimeouts::default(),
            Some(migration_contract),
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
                "ryuki_acquire_live_site_execution_epoch".to_owned(),
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
            .expect("the reviewed bounded reconciler must remain executable");
        assert!((0..=1).contains(&repaired));
        let missing_site_epoch: Option<i64> = sqlx::query_scalar(
            "SELECT public.ryuki_acquire_live_site_execution_epoch('__missing_site__')",
        )
        .fetch_one(&pool)
        .await
        .expect("the reviewed live-site execution fence must remain executable");
        assert_eq!(missing_site_epoch, None);
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
