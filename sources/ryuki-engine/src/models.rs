use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub offering_id: String,
    pub request_type: RequestType,
    pub status: RequestStatus,
    pub requester: String,
    pub owner: String,
    pub site: String,
    pub environment: String,
    pub criticality: String,
    pub stages: Vec<Stage>,
    pub created_at: String,
    pub updated_at: String,
    pub dry_run_required: bool,
    pub approval_route: Vec<String>,
    pub evidence_manifest_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl Request {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        offering_id: String,
        request_type: RequestType,
        requester: String,
        owner: String,
        site: String,
        environment: String,
        criticality: String,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Request {
            id,
            offering_id,
            request_type,
            status: RequestStatus::Draft,
            requester,
            owner,
            site,
            environment,
            criticality,
            stages: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
            dry_run_required: true,
            approval_route: Vec::new(),
            evidence_manifest_id: None,
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RequestType {
    ServerDeployment,
    PatchMaintenance,
    RebootOrchestration,
    ControlledRestore,
    ZabbixOnboarding,
    CmdbImport,
    CmdbUpdateExport,
    OperatorRunbookLaunch,
    ApplicationEnvironmentRetirement,
    VmDecommissionQuarantine,
    RequestPreflight,
    VmDay2Change,
    SnapshotGovernance,
    BackupCoverageReport,
}

impl std::fmt::Display for RequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestType::ServerDeployment => write!(f, "server-deployment"),
            RequestType::PatchMaintenance => write!(f, "patch-maintenance"),
            RequestType::RebootOrchestration => write!(f, "reboot-orchestration"),
            RequestType::ControlledRestore => write!(f, "controlled-restore"),
            RequestType::ZabbixOnboarding => write!(f, "zabbix-onboarding"),
            RequestType::CmdbImport => write!(f, "cmdb-import"),
            RequestType::CmdbUpdateExport => write!(f, "cmdb-update-export"),
            RequestType::OperatorRunbookLaunch => write!(f, "operator-runbook-launch"),
            RequestType::ApplicationEnvironmentRetirement => {
                write!(f, "application-environment-retirement")
            }
            RequestType::VmDecommissionQuarantine => write!(f, "vm-decommission-quarantine"),
            RequestType::RequestPreflight => write!(f, "request-preflight"),
            RequestType::VmDay2Change => write!(f, "vm-day2-change"),
            RequestType::SnapshotGovernance => write!(f, "snapshot-governance"),
            RequestType::BackupCoverageReport => write!(f, "backup-coverage-report"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RequestStatus {
    Draft,
    Intake,
    Validated,
    Planned,
    Approved,
    Locked,
    Executing,
    Verifying,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stage {
    pub name: String,
    pub status: StageStatus,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub evidence: Vec<EvidenceItem>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StageStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub site: String,
    pub environment: String,
    pub criticality: String,
    pub owner: String,
    pub specs: ServerSpecs,
    pub hypervisor: HypervisorType,
    pub tags: HashMap<String, String>,
    pub backup_policy: Option<String>,
    pub monitoring_profile: Option<String>,
    pub cmdb_ci_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerSpecs {
    pub cpu: u32,
    pub memory_gb: u32,
    pub disk_gb: u32,
    pub os: OsType,
    pub os_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OsType {
    Windows,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HypervisorType {
    VMware,
    HyperV,
    Proxmox,
}

impl std::fmt::Display for HypervisorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HypervisorType::VMware => write!(f, "vmware"),
            HypervisorType::HyperV => write!(f, "hyperv"),
            HypervisorType::Proxmox => write!(f, "proxmox"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryItem {
    pub id: String,
    pub name: String,
    pub item_type: InventoryType,
    pub owner: String,
    pub site: String,
    pub environment: String,
    pub criticality: String,
    pub last_synced: String,
    pub source: String,
    pub stale: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InventoryType {
    Server,
    Database,
    FileShare,
    Certificate,
    NetworkVlan,
    HypervisorHost,
    Cluster,
    Datastore,
    BackupRepository,
    MonitoringHost,
    CmdbCi,
}

impl std::fmt::Display for InventoryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InventoryType::Server => write!(f, "server"),
            InventoryType::Database => write!(f, "database"),
            InventoryType::FileShare => write!(f, "fileshare"),
            InventoryType::Certificate => write!(f, "certificate"),
            InventoryType::NetworkVlan => write!(f, "network-vlan"),
            InventoryType::HypervisorHost => write!(f, "hypervisor-host"),
            InventoryType::Cluster => write!(f, "cluster"),
            InventoryType::Datastore => write!(f, "datastore"),
            InventoryType::BackupRepository => write!(f, "backup-repository"),
            InventoryType::MonitoringHost => write!(f, "monitoring-host"),
            InventoryType::CmdbCi => write!(f, "cmdb-ci"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePack {
    pub id: String,
    pub request_id: String,
    pub items: Vec<EvidenceItem>,
    pub redacted: bool,
    pub created_at: String,
    pub format: String,
    pub compliance_checks: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceItem {
    pub key: String,
    pub value: String,
    pub redacted_value: Option<String>,
    pub redacted: bool,
    pub evidence_type: EvidenceType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    Summary,
    ValidationResult,
    Plan,
    ApprovalDecision,
    LockRecord,
    ExecutionLog,
    InventoryCheck,
    PolicyAssignment,
    ExportPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmdbRecord {
    pub ci_id: String,
    pub ci_name: String,
    pub ci_type: String,
    pub site: String,
    pub environment: String,
    pub owner: String,
    pub support_group: String,
    pub criticality: String,
    pub attributes: HashMap<String, String>,
    pub relationships: Vec<CmdbRelationship>,
    pub import_status: ImportStatus,
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmdbRelationship {
    pub target_ci_id: String,
    pub relationship_type: String,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportStatus {
    Accepted,
    Rejected,
    PendingReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchWave {
    pub id: String,
    pub name: String,
    pub servers: Vec<String>,
    pub site_scope: Vec<String>,
    pub environment_scope: Vec<String>,
    pub schedule: PatchSchedule,
    pub reboot_policy: RebootPolicy,
    pub blackout_dates: Vec<String>,
    pub validation_errors: Vec<String>,
    pub status: PatchWaveStatus,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchSchedule {
    pub start: String,
    pub end: String,
    pub maintenance_window: String,
    pub patch_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RebootPolicy {
    RebootIfRequired,
    RebootAlways,
    NoReboot,
    ScheduleOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatchWaveStatus {
    Draft,
    Validated,
    Approved,
    Scheduled,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterConfig {
    pub id: String,
    pub adapter_type: AdapterType,
    pub name: String,
    pub endpoint: String,
    pub status: AdapterStatus,
    pub readiness: ReadinessState,
    pub api_version: String,
    pub health_check_at: Option<String>,
    pub stale: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdapterType {
    VMware,
    HyperV,
    Proxmox,
    Veeam,
    VeeamOne,
    Zabbix,
    ServiceNow,
}

impl std::fmt::Display for AdapterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterType::VMware => write!(f, "vmware"),
            AdapterType::HyperV => write!(f, "hyperv"),
            AdapterType::Proxmox => write!(f, "proxmox"),
            AdapterType::Veeam => write!(f, "veeam"),
            AdapterType::VeeamOne => write!(f, "veeam-one"),
            AdapterType::Zabbix => write!(f, "zabbix"),
            AdapterType::ServiceNow => write!(f, "servicenow"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReadinessState {
    Configured,
    Blocked,
    Stale,
}

impl std::fmt::Display for ReadinessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadinessState::Configured => write!(f, "configured"),
            ReadinessState::Blocked => write!(f, "blocked"),
            ReadinessState::Stale => write!(f, "stale"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdapterStatus {
    NotConfigured,
    Configured,
    Connected,
    Degraded,
    Error,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationResult {
    pub passed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub failed_rules: Vec<String>,
    pub remediation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Site {
    pub code: String,
    pub country: String,
    pub timezone_code: u32,
    pub ou_pattern: String,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub family: String,
    pub priority: String,
    pub decision: PolicyDecision,
    pub failure_message: String,
    pub remediation: String,
    pub required_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Block,
    Review,
    Warn,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDecision::Block => write!(f, "block"),
            PolicyDecision::Review => write!(f, "review"),
            PolicyDecision::Warn => write!(f, "warn"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmDay2ChangeRequest {
    pub id: String,
    pub target_ci_key: String,
    pub change_type: VmChangeType,
    pub target_value: u32,
    pub site: String,
    pub environment: String,
    pub owner: String,
    pub maintenance_window: String,
    pub status: VmChangeStatus,
    pub plan: Option<VmDay2Plan>,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmChangeType {
    ResizeCpu,
    ResizeMemory,
    AddDisk,
    ExtendDisk,
    MigrateHost,
    MigrateStorage,
}

impl std::fmt::Display for VmChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmChangeType::ResizeCpu => write!(f, "resize-cpu"),
            VmChangeType::ResizeMemory => write!(f, "resize-memory"),
            VmChangeType::AddDisk => write!(f, "add-disk"),
            VmChangeType::ExtendDisk => write!(f, "extend-disk"),
            VmChangeType::MigrateHost => write!(f, "migrate-host"),
            VmChangeType::MigrateStorage => write!(f, "migrate-storage"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmChangeStatus {
    Draft,
    Validated,
    Planned,
    Approved,
    Locked,
    Executed,
    Verified,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmDay2Plan {
    pub current_state: VmCurrentState,
    pub desired_state: VmDesiredState,
    pub capacity_impact: String,
    pub backup_impact: String,
    pub monitoring_impact: String,
    pub rollback_notes: String,
    pub verification_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmCurrentState {
    pub cpu: u32,
    pub memory_gb: u32,
    pub disk_gb: u32,
    pub host: String,
    pub datastore: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmDesiredState {
    pub cpu: u32,
    pub memory_gb: u32,
    pub disk_gb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRecord {
    pub id: String,
    pub platform_ci_key: String,
    pub snapshot_purpose: String,
    pub requested_expiry: String,
    pub owner: String,
    pub support_group: String,
    pub change_context: String,
    pub status: SnapshotStatus,
    pub policy_decision: Option<String>,
    pub backup_impact: Option<String>,
    pub remediation_plan: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapshotStatus {
    Draft,
    ReviewRequested,
    ExpiryApproved,
    StaleFlagged,
    RemediationPlanned,
    Expired,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupCoverageReport {
    pub id: String,
    pub site_scope: Vec<String>,
    pub environment_scope: Vec<String>,
    pub generation_time: String,
    pub total_assets: u32,
    pub covered_assets: u32,
    pub missing_backup: u32,
    pub missing_dr_replica: u32,
    pub stale_policy: u32,
    pub critical_gaps: Vec<String>,
    pub coverage_percentage: f64,
    pub status: CoverageReportStatus,
    pub recommendations: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoverageReportStatus {
    Generated,
    Reviewing,
    ActionRequired,
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreRequest {
    pub id: String,
    pub source_ci_key: String,
    pub restore_type: RestoreType,
    pub restore_point: String,
    pub target_site: String,
    pub target_environment: String,
    pub verification_plan: String,
    pub retention_need: String,
    pub owner: String,
    pub status: RestoreStatus,
    pub dry_run_plan: Option<String>,
    pub created_at: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RestoreType {
    FullVm,
    FileLevel,
    ApplicationItem,
    InstantVmRecovery,
}

impl std::fmt::Display for RestoreType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestoreType::FullVm => write!(f, "full-vm"),
            RestoreType::FileLevel => write!(f, "file-level"),
            RestoreType::ApplicationItem => write!(f, "application-item"),
            RestoreType::InstantVmRecovery => write!(f, "instant-vm-recovery"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RestoreStatus {
    Draft,
    Validated,
    Planned,
    Approved,
    Locked,
    Executed,
    Verified,
    Completed,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_new_defaults_to_draft() {
        let req = Request::new(
            "req-001".into(),
            "windows-server-deployment".into(),
            RequestType::ServerDeployment,
            "alice".into(),
            "bob".into(),
            "LOVE".into(),
            "production".into(),
            "critical".into(),
        );
        assert_eq!(req.status, RequestStatus::Draft);
        assert!(req.dry_run_required);
        assert_eq!(req.site, "LOVE");
    }

    #[test]
    fn test_request_type_display() {
        assert_eq!(
            RequestType::ServerDeployment.to_string(),
            "server-deployment"
        );
        assert_eq!(
            RequestType::PatchMaintenance.to_string(),
            "patch-maintenance"
        );
    }

    #[test]
    fn test_validation_result_defaults() {
        let vr = ValidationResult {
            passed: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            failed_rules: Vec::new(),
            remediation: Vec::new(),
        };
        assert!(vr.passed);
        assert!(vr.errors.is_empty());
    }

    #[test]
    fn test_server_specs_construction() {
        let specs = ServerSpecs {
            cpu: 4,
            memory_gb: 16,
            disk_gb: 100,
            os: OsType::Windows,
            os_version: "2022".into(),
        };
        assert_eq!(specs.cpu, 4);
        assert_eq!(specs.memory_gb, 16);
    }

    #[test]
    fn test_evidence_item_redaction_state() {
        let item = EvidenceItem {
            key: "ssh_key".into(),
            value: "secret-value".into(),
            redacted_value: Some("***REDACTED***".into()),
            redacted: true,
            evidence_type: EvidenceType::ExecutionLog,
        };
        assert!(item.redacted);
        assert!(item.redacted_value.is_some());
    }

    #[test]
    fn test_cmdb_record_validation_errors() {
        let record = CmdbRecord {
            ci_id: "ci-001".into(),
            ci_name: "server01".into(),
            ci_type: "Windows Server".into(),
            site: "LOVE".into(),
            environment: "production".into(),
            owner: "".into(),
            support_group: "".into(),
            criticality: "".into(),
            attributes: HashMap::new(),
            relationships: Vec::new(),
            import_status: ImportStatus::Rejected,
            validation_errors: vec!["Missing owner".into()],
        };
        assert_eq!(record.import_status, ImportStatus::Rejected);
        assert_eq!(record.validation_errors.len(), 1);
    }

    #[test]
    fn test_readiness_state_display() {
        assert_eq!(ReadinessState::Configured.to_string(), "configured");
        assert_eq!(ReadinessState::Blocked.to_string(), "blocked");
        assert_eq!(ReadinessState::Stale.to_string(), "stale");
    }
}
