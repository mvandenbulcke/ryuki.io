use crate::models::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

pub fn plan_patch_wave_from_servers(servers: &[Server]) -> Result<PatchWave, String> {
    if servers.is_empty() {
        return Err("Cannot plan patch wave with zero servers".into());
    }

    let id = format!(
        "pw-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let server_ids: Vec<String> = servers.iter().map(|s| s.id.clone()).collect();
    let site_scope: Vec<String> = {
        let mut sites: Vec<String> = servers.iter().map(|s| s.site.clone()).collect();
        sites.sort();
        sites.dedup();
        sites
    };
    let environment_scope: Vec<String> = {
        let mut envs: Vec<String> = servers.iter().map(|s| s.environment.clone()).collect();
        envs.sort();
        envs.dedup();
        envs
    };

    let mut wave = PatchWave {
        id,
        name: format!(
            "Patch Wave - {} sites - {} servers",
            site_scope.len(),
            servers.len()
        ),
        servers: server_ids,
        site_scope,
        environment_scope,
        schedule: PatchSchedule {
            start: "2026-06-15T22:00:00Z".into(),
            end: "2026-06-16T06:00:00Z".into(),
            maintenance_window: "EU-Overnight".into(),
            patch_group: Some("Group-A".into()),
        },
        reboot_policy: RebootPolicy::RebootIfRequired,
        blackout_dates: Vec::new(),
        validation_errors: Vec::new(),
        status: PatchWaveStatus::Draft,
        metadata: HashMap::new(),
    };

    wave.metadata.insert(
        "critical_server_count".into(),
        servers
            .iter()
            .filter(|s| s.criticality == "critical")
            .count()
            .to_string(),
    );

    Ok(wave)
}

pub fn validate_patch_policy(wave: &PatchWave) -> Result<Vec<String>, String> {
    let mut results: Vec<String> = Vec::new();

    if wave.servers.is_empty() {
        results.push("FAIL: Patch wave has no servers".into());
    } else {
        results.push(format!(
            "PASS: Patch wave targets {} servers",
            wave.servers.len()
        ));
    }

    if wave.maintenance_window_is_empty() {
        results.push("FAIL: No maintenance window defined".into());
    } else {
        results.push(format!(
            "PASS: Maintenance window: {}",
            wave.schedule.maintenance_window
        ));
    }

    for site in &wave.site_scope {
        if !VALID_SITES.contains(&site.as_str()) {
            results.push(format!("FAIL: Unknown site in scope: {}", site));
        } else {
            results.push(format!("PASS: Site {} is valid", site));
        }
    }

    match &wave.reboot_policy {
        RebootPolicy::NoReboot => {
            results.push("WARN: No-reboot policy may leave unapplied patches".into());
        }
        RebootPolicy::RebootIfRequired => {
            results
                .push("PASS: Reboot-if-required policy is appropriate for most workloads".into());
        }
        RebootPolicy::RebootAlways => {
            results.push("WARN: Reboot-always policy may cause unnecessary downtime".into());
        }
        RebootPolicy::ScheduleOnly => {
            results.push("WARN: Schedule-only policy requires manual reboot coordination".into());
        }
    }

    if wave.blackout_dates.is_empty() {
        results.push("INFO: No blackout dates configured".into());
    } else {
        results.push(format!(
            "PASS: {} blackout date(s) configured",
            wave.blackout_dates.len()
        ));
    }

    if wave.patch_group_is_empty() {
        results.push("FAIL: No patch group assigned".into());
    } else {
        results.push("PASS: Patch group assigned".into());
    }

    let critical_count: usize = wave
        .metadata
        .get("critical_server_count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if critical_count > 0 {
        results.push(format!(
            "INFO: Wave includes {} critical server(s) - ensure backup is verified before patching",
            critical_count
        ));
    }

    Ok(results)
}

pub fn orchestrate_reboot(wave: &PatchWave) -> Result<Vec<Stage>, String> {
    if wave.servers.is_empty() {
        return Err("Cannot orchestrate reboot with zero servers".into());
    }

    // Reboot orchestration only applies to policies that actually reboot. A
    // NoReboot wave performs no reboots, and a ScheduleOnly wave reboots only
    // via manual coordination outside this orchestrator; for either, emitting
    // per-server reboot stages would misrepresent the wave, so reject them.
    match wave.reboot_policy {
        RebootPolicy::RebootIfRequired | RebootPolicy::RebootAlways => {}
        RebootPolicy::NoReboot => {
            return Err(
                "Cannot orchestrate reboot: wave reboot policy is NoReboot (no reboots planned)"
                    .into(),
            );
        }
        RebootPolicy::ScheduleOnly => {
            return Err("Cannot orchestrate reboot: wave reboot policy is ScheduleOnly (reboots require manual coordination)".into());
        }
    }

    let mut stages: Vec<Stage> = Vec::new();

    stages.push(Stage {
        name: "pre-reboot-backup-verify".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: vec![EvidenceItem {
            key: "backup-verification".into(),
            value: format!(
                "DRY-RUN: Verified backup status for {} servers (simulated, no Veeam calls)",
                wave.servers.len()
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Plan,
        }],
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    });

    stages.push(Stage {
        name: "drain-workloads".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: vec![EvidenceItem {
            key: "drain-plan".into(),
            value: format!(
                "DRY-RUN: Planned drain for {} servers across sites {:?} (simulated)",
                wave.servers.len(),
                wave.site_scope
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Plan,
        }],
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    });

    for (i, server_id) in wave.servers.iter().enumerate() {
        stages.push(Stage {
            name: format!("reboot-server-{}", i + 1),
            status: StageStatus::Pending,
            started_at: None,
            completed_at: None,
            evidence: vec![EvidenceItem {
                key: format!("reboot-server-{}", server_id),
                value: format!(
                    "DRY-RUN: Planned reboot for server {} (simulated, no hypervisor calls)",
                    server_id
                ),
                redacted_value: Some("***DRY-RUN***".into()),
                redacted: true,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            metadata: HashMap::from([
                ("server_id".into(), server_id.clone()),
                ("dry_run".into(), "true".into()),
            ]),
        });
    }

    stages.push(Stage {
        name: "post-reboot-health-check".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: vec![EvidenceItem {
            key: "health-check".into(),
            value: format!(
                "DRY-RUN: Planned health checks for {} servers (simulated, no monitoring calls)",
                wave.servers.len()
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Plan,
        }],
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    });

    Ok(stages)
}

impl PatchWave {
    fn maintenance_window_is_empty(&self) -> bool {
        self.schedule.maintenance_window.is_empty()
    }

    fn patch_group_is_empty(&self) -> bool {
        self.schedule
            .patch_group
            .as_deref()
            .is_none_or(|g| g.is_empty())
    }
}

// ─── Pure public transition functions ────────────────────────────────────────
//
// These replace the old store-mutating functions. Each takes the loaded wave by
// reference and returns the updated wave (and any additional output) without
// performing any I/O. The repository layer in ryuki-api owns persistence; the
// handler owns the transition contract (404/409/503).

/// Create a new Draft patch wave for the given site, os_family, and criticality.
///
/// The returned wave has a non-UUID id of the form "pw-<short>". Callers that
/// persist the wave MUST replace the id with a UUID before inserting (exactly
/// as the decommission handler does).
pub fn plan_patch_wave(
    site: &str,
    os_family: &str,
    criticality: &str,
) -> Result<PatchWave, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    if os_family.is_empty() {
        return Err("os_family cannot be empty".into());
    }
    let valid_os = ["windows", "linux"];
    if !valid_os.contains(&os_family) {
        return Err(format!(
            "Invalid os_family '{}'. Must be 'windows' or 'linux'",
            os_family
        ));
    }

    let id = format!(
        "pw-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let os_prefix = match os_family {
        "windows" => "w",
        "linux" => "l",
        _ => "s",
    };
    let site_lower = site.to_lowercase();
    let mock_servers: Vec<String> = (1..=3)
        .map(|i| format!("{}-{}-srv-{:02}", os_prefix, site_lower, i))
        .collect();

    let wave = PatchWave {
        id,
        name: format!("Patch Wave - {} - {} ({})", site, os_family, criticality),
        servers: mock_servers,
        site_scope: vec![site.to_string()],
        environment_scope: vec!["production".into()],
        schedule: PatchSchedule {
            start: "2026-06-15T22:00:00Z".into(),
            end: "2026-06-16T06:00:00Z".into(),
            maintenance_window: "EU-Overnight".into(),
            patch_group: Some("Group-A".into()),
        },
        reboot_policy: RebootPolicy::RebootIfRequired,
        blackout_dates: Vec::new(),
        validation_errors: Vec::new(),
        status: PatchWaveStatus::Draft,
        metadata: HashMap::from([
            ("os_family".into(), os_family.to_string()),
            ("criticality".into(), criticality.to_string()),
            ("dry_run".into(), "true".into()),
        ]),
    };

    Ok(wave)
}

/// Validate a patch wave that is in Draft status.
///
/// Returns the updated wave (with validation_errors and metadata written, and
/// status advanced to Validated if validation passed) alongside the
/// ValidationResult. If validation fails the returned wave remains in Draft
/// status but carries the errors and metadata — the handler MUST still persist
/// it via transition so that validation_errors are durable.
pub fn validate_patch_wave(wave: &PatchWave) -> Result<(PatchWave, ValidationResult), String> {
    if wave.status != PatchWaveStatus::Draft {
        return Err(format!(
            "Cannot validate patch wave in status {:?}. Must be Draft first.",
            wave.status
        ));
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if wave.servers.is_empty() {
        errors.push("Patch wave has no servers".into());
        failed_rules.push("p0-patch-servers-required".into());
        remediation.push("Add servers to the patch wave.".into());
    }

    if wave.schedule.maintenance_window.is_empty() {
        errors.push("No maintenance window defined".into());
        failed_rules.push("p0-maintenance-window-required".into());
        remediation.push("Define a maintenance window for this wave.".into());
    }

    for site in &wave.site_scope {
        if !VALID_SITES.contains(&site.as_str()) {
            errors.push(format!("Unknown site in scope: {}", site));
            failed_rules.push("p0-valid-site-required".into());
            remediation.push(format!("Correct site '{}' to a known site code.", site));
        }
    }

    warnings.push("DRY-RUN: Backup state verified (simulated)".into());
    warnings.push("DRY-RUN: Dependency graph checked (simulated)".into());
    warnings.push("DRY-RUN: Maintenance window availability confirmed (simulated)".into());

    let passed = errors.is_empty();

    let mut validated = wave.clone();
    validated.validation_errors = errors.clone();
    validated
        .metadata
        .insert("validation_passed".into(), passed.to_string());
    validated
        .metadata
        .insert("validation_dry_run".into(), "true".into());

    if passed {
        validated.status = PatchWaveStatus::Validated;
        validated
            .metadata
            .insert("validated_at".into(), chrono::Utc::now().to_rfc3339());
    }

    let result = ValidationResult {
        passed,
        errors,
        warnings,
        failed_rules,
        remediation,
    };

    Ok((validated, result))
}

/// Approve a patch wave that is in Validated status.
///
/// Returns the updated wave with status Approved and approver/approved_at
/// metadata set.
pub fn approve_patch_wave(wave: &PatchWave, approver: &str) -> Result<PatchWave, String> {
    if wave.status != PatchWaveStatus::Validated {
        return Err(format!(
            "Cannot approve patch wave in status {:?}. Must pass validation first.",
            wave.status
        ));
    }

    let mut approved = wave.clone();
    approved.status = PatchWaveStatus::Approved;
    // The approver is the authenticated caller (from the request session), never
    // a hardcoded string — the approval audit trail must name the real principal.
    approved
        .metadata
        .insert("approver".into(), approver.to_string());
    approved
        .metadata
        .insert("approved_at".into(), chrono::Utc::now().to_rfc3339());

    Ok(approved)
}

/// Execute a patch wave that is in Approved status.
///
/// Returns the updated wave (status Completed, with executed_at and
/// execution_evidence_count metadata) and the evidence items collected during
/// execution.
pub fn execute_patch_wave(wave: &PatchWave) -> Result<(PatchWave, Vec<EvidenceItem>), String> {
    if wave.status != PatchWaveStatus::Approved {
        return Err(format!(
            "Cannot execute patch wave in status {:?}. Must be Approved first.",
            wave.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "pre-patch-backup-check".into(),
        value: format!(
            "DRY-RUN: Backup state verified for {} servers before patching (simulated)",
            wave.servers.len()
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    for server_id in &wave.servers {
        evidence.push(EvidenceItem {
            key: format!("patch-apply-{}", server_id),
            value: format!(
                "DRY-RUN: Patches applied to {} (simulated, no provider calls)",
                server_id
            ),
            redacted_value: Some("***DRY-RUN SIMULATION***".into()),
            redacted: true,
            evidence_type: EvidenceType::ExecutionLog,
        });
    }

    let needs_reboot = matches!(
        wave.reboot_policy,
        RebootPolicy::RebootAlways | RebootPolicy::RebootIfRequired
    );
    if needs_reboot {
        evidence.push(EvidenceItem {
            key: "post-patch-reboot".into(),
            value: format!(
                "DRY-RUN: Reboot queued for {} servers with policy {:?} (simulated)",
                wave.servers.len(),
                wave.reboot_policy
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::ExecutionLog,
        });
    }

    evidence.push(EvidenceItem {
        key: "post-patch-health-check".into(),
        value: format!(
            "DRY-RUN: Health check passed for {} servers (simulated)",
            wave.servers.len()
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    let mut completed = wave.clone();
    completed.status = PatchWaveStatus::Completed;
    completed
        .metadata
        .insert("executed_at".into(), chrono::Utc::now().to_rfc3339());
    completed.metadata.insert(
        "execution_evidence_count".into(),
        evidence.len().to_string(),
    );
    completed.metadata.insert(
        "execution_summary".into(),
        format!(
            "DRY-RUN: Patch wave completed for {} servers (simulated, no provider calls)",
            completed.servers.len()
        ),
    );

    Ok((completed, evidence))
}

/// Verify that a patch wave has been correctly executed (evidence-only check).
///
/// The wave must be in Completed status. Returns a ValidationResult; does NOT
/// transition the wave — verification is read-only at this stage.
pub fn verify_patch_wave(wave: &PatchWave) -> Result<ValidationResult, String> {
    if wave.status != PatchWaveStatus::Completed {
        return Err(format!(
            "Cannot verify patch wave in status {:?}. Must be Completed first.",
            wave.status
        ));
    }

    let mut warnings: Vec<String> = Vec::new();

    warnings.push(format!(
        "DRY-RUN: Compliance check passed for site {} (simulated)",
        wave.site_scope.join(", ")
    ));
    warnings.push(format!(
        "DRY-RUN: {} servers verified compliant (simulated)",
        wave.servers.len()
    ));
    warnings.push("DRY-RUN: Patch inventory reconciled (simulated)".into());

    Ok(ValidationResult {
        passed: true,
        errors: Vec::new(),
        warnings,
        failed_rules: Vec::new(),
        remediation: Vec::new(),
    })
}

pub fn get_patch_compliance() -> Result<Value, String> {
    Ok(json!({
        "source": "dry-run",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "sites": [
            {"site": "DEFRA", "windows": {"patched": 42, "pending": 3, "compliant": true}, "linux": {"patched": 18, "pending": 1, "compliant": true}},
            {"site": "GBLON", "windows": {"patched": 35, "pending": 5, "compliant": true}, "linux": {"patched": 12, "pending": 2, "compliant": false}},
            {"site": "FRPAR", "windows": {"patched": 28, "pending": 7, "compliant": false}, "linux": {"patched": 9, "pending": 0, "compliant": true}},
            {"site": "NLAMS", "windows": {"patched": 31, "pending": 4, "compliant": true}, "linux": {"patched": 14, "pending": 1, "compliant": true}},
            {"site": "DEBER", "windows": {"patched": 20, "pending": 2, "compliant": true}, "linux": {"patched": 6, "pending": 0, "compliant": true}},
            {"site": "DEFRA", "windows": {"patched": 25, "pending": 3, "compliant": true}, "linux": {"patched": 11, "pending": 1, "compliant": true}},
            {"site": "FRPAR", "windows": {"patched": 33, "pending": 6, "compliant": false}, "linux": {"patched": 8, "pending": 2, "compliant": false}},
            {"site": "GBLON", "windows": {"patched": 19, "pending": 1, "compliant": true}, "linux": {"patched": 10, "pending": 0, "compliant": true}},
            {"site": "NLAMS", "windows": {"patched": 27, "pending": 4, "compliant": true}, "linux": {"patched": 13, "pending": 1, "compliant": true}},
            {"site": "DEBER", "windows": {"patched": 22, "pending": 2, "compliant": true}, "linux": {"patched": 7, "pending": 0, "compliant": true}},
            {"site": "GBLON", "windows": {"patched": 30, "pending": 3, "compliant": true}, "linux": {"patched": 15, "pending": 2, "compliant": true}},
            {"site": "FRPAR", "windows": {"patched": 24, "pending": 5, "compliant": false}, "linux": {"patched": 5, "pending": 0, "compliant": true}},
            {"site": "NLAMS", "windows": {"patched": 16, "pending": 1, "compliant": true}, "linux": {"patched": 4, "pending": 0, "compliant": true}}
        ],
        "overall_compliance_percentage": 87.5,
        "dry_run": true
    }))
}

pub fn get_pending_reboots() -> Result<Value, String> {
    Ok(json!({
        "source": "dry-run",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "pending_reboots": [
            {"server": "w-defra-srv-01", "site": "DEFRA", "os_family": "windows", "reason": "Patch KB5034127 requires reboot", "since": "2026-06-10T22:00:00Z"},
            {"server": "w-gblon-srv-03", "site": "GBLON", "os_family": "windows", "reason": "Patch KB5034285 requires reboot", "since": "2026-06-10T22:30:00Z"},
            {"server": "w-frpar-srv-02", "site": "FRPAR", "os_family": "windows", "reason": "Patch KB5034441 requires reboot", "since": "2026-06-11T01:00:00Z"},
            {"server": "l-frpar-srv-01", "site": "FRPAR", "os_family": "linux", "reason": "Kernel update 5.15.0-91 requires reboot", "since": "2026-06-11T02:00:00Z"},
            {"server": "w-frpar-srv-01", "site": "FRPAR", "os_family": "windows", "reason": "Patch KB5034439 requires reboot", "since": "2026-06-10T23:00:00Z"}
        ],
        "total_pending": 5,
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_server(id: &str, name: &str, site: &str, env: &str, criticality: &str) -> Server {
        Server {
            id: id.into(),
            name: name.into(),
            site: site.into(),
            environment: env.into(),
            criticality: criticality.into(),
            owner: "test-team".into(),
            specs: ServerSpecs {
                cpu: 4,
                memory_gb: 16,
                disk_gb: 100,
                os: OsType::Windows,
                os_version: "2022".into(),
            },
            hypervisor: HypervisorType::VMware,
            tags: HashMap::new(),
            backup_policy: Some("daily".into()),
            monitoring_profile: Some("standard".into()),
            cmdb_ci_id: Some(format!("ci-{}", id)),
        }
    }

    #[test]
    fn test_plan_patch_wave_empty_servers_fails() {
        assert!(plan_patch_wave_from_servers(&[]).is_err());
    }

    #[test]
    fn test_plan_patch_wave_creates_wave() {
        let servers = vec![
            make_test_server("srv-001", "web01", "DEFRA", "production", "high"),
            make_test_server("srv-002", "app01", "DEFRA", "production", "critical"),
            make_test_server("srv-003", "db01", "GBLON", "production", "critical"),
        ];

        let wave = plan_patch_wave_from_servers(&servers).unwrap();
        assert_eq!(wave.servers.len(), 3);
        assert_eq!(wave.site_scope.len(), 2);
        assert_eq!(wave.status, PatchWaveStatus::Draft);
        assert!(
            wave.metadata
                .get("critical_server_count")
                .unwrap()
                .parse::<usize>()
                .unwrap()
                == 2
        );
    }

    #[test]
    fn test_validate_patch_policy_all_pass() {
        let servers = vec![make_test_server(
            "srv-001",
            "web01",
            "DEFRA",
            "production",
            "high",
        )];
        let wave = plan_patch_wave_from_servers(&servers).unwrap();
        let results = validate_patch_policy(&wave).unwrap();

        let has_failures = results.iter().any(|r| r.starts_with("FAIL:"));
        assert!(!has_failures, "Expected no failures but got: {:?}", results);
    }

    #[test]
    fn test_validate_patch_policy_unknown_site() {
        let servers = vec![make_test_server(
            "srv-001",
            "web01",
            "UNKNOWN",
            "production",
            "high",
        )];
        let mut wave = plan_patch_wave_from_servers(&servers).unwrap();
        wave.site_scope = vec!["UNKNOWN".into()];
        let results = validate_patch_policy(&wave).unwrap();
        assert!(results.iter().any(|r| r.contains("Unknown site")));
    }

    #[test]
    fn test_validate_patch_policy_no_servers() {
        let wave = PatchWave {
            id: "pw-001".into(),
            name: "Test Wave".into(),
            servers: Vec::new(),
            site_scope: Vec::new(),
            environment_scope: Vec::new(),
            schedule: PatchSchedule {
                start: "2026-06-15T22:00:00Z".into(),
                end: "2026-06-16T06:00:00Z".into(),
                maintenance_window: "EU-Overnight".into(),
                patch_group: Some("Group-A".into()),
            },
            reboot_policy: RebootPolicy::RebootIfRequired,
            blackout_dates: Vec::new(),
            validation_errors: Vec::new(),
            status: PatchWaveStatus::Draft,
            metadata: HashMap::new(),
        };

        let results = validate_patch_policy(&wave).unwrap();
        assert!(results.iter().any(|r| r.contains("no servers")));
    }

    #[test]
    fn test_orchestrate_reboot_generates_stages() {
        let servers = vec![
            make_test_server("srv-001", "web01", "DEFRA", "production", "high"),
            make_test_server("srv-002", "app01", "GBLON", "production", "critical"),
        ];
        let wave = plan_patch_wave_from_servers(&servers).unwrap();
        let stages = orchestrate_reboot(&wave).unwrap();

        assert!(stages.iter().any(|s| s.name == "pre-reboot-backup-verify"));
        assert!(stages.iter().any(|s| s.name == "drain-workloads"));
        assert!(stages.iter().any(|s| s.name == "post-reboot-health-check"));
        assert_eq!(
            stages
                .iter()
                .filter(|s| s.name.starts_with("reboot-server-"))
                .count(),
            2
        );
    }

    #[test]
    fn test_orchestrate_reboot_empty_servers_fails() {
        let wave = PatchWave {
            id: "pw-002".into(),
            name: "Empty Wave".into(),
            servers: Vec::new(),
            site_scope: Vec::new(),
            environment_scope: Vec::new(),
            schedule: PatchSchedule {
                start: "2026-06-15T22:00:00Z".into(),
                end: "2026-06-16T06:00:00Z".into(),
                maintenance_window: "EU-Overnight".into(),
                patch_group: Some("Group-A".into()),
            },
            reboot_policy: RebootPolicy::RebootIfRequired,
            blackout_dates: Vec::new(),
            validation_errors: Vec::new(),
            status: PatchWaveStatus::Draft,
            metadata: HashMap::new(),
        };

        assert!(orchestrate_reboot(&wave).is_err());
    }

    #[test]
    fn test_orchestrate_reboot_rejects_non_rebooting_policies() {
        let servers = vec![make_test_server(
            "srv-001",
            "web01",
            "DEFRA",
            "production",
            "high",
        )];
        let mut wave = plan_patch_wave_from_servers(&servers).unwrap();

        // NoReboot and ScheduleOnly do not auto-reboot, so orchestration must
        // refuse rather than emit misleading per-server reboot stages.
        wave.reboot_policy = RebootPolicy::NoReboot;
        assert!(orchestrate_reboot(&wave).is_err());

        wave.reboot_policy = RebootPolicy::ScheduleOnly;
        assert!(orchestrate_reboot(&wave).is_err());

        // The two rebooting policies still produce per-server reboot stages.
        for policy in [RebootPolicy::RebootIfRequired, RebootPolicy::RebootAlways] {
            wave.reboot_policy = policy;
            let stages = orchestrate_reboot(&wave).unwrap();
            assert!(
                stages.iter().any(|s| s.name.starts_with("reboot-server-")),
                "policy {:?} should still emit per-server reboot stages",
                wave.reboot_policy
            );
        }
    }

    #[test]
    fn test_all_stages_are_dry_run() {
        let servers = vec![make_test_server(
            "srv-001",
            "web01",
            "DEFRA",
            "production",
            "high",
        )];
        let wave = plan_patch_wave_from_servers(&servers).unwrap();
        let stages = orchestrate_reboot(&wave).unwrap();

        for stage in &stages {
            let is_dry_run = stage
                .metadata
                .get("dry_run")
                .map(|v| v == "true")
                .unwrap_or(false);
            assert!(
                is_dry_run,
                "Stage '{}' should be marked dry_run=true",
                stage.name
            );
        }
    }

    #[test]
    fn test_plan_patch_wave_by_site() {
        let wave = plan_patch_wave("DEFRA", "windows", "critical").unwrap();
        assert!(wave.id.starts_with("pw-"));
        assert_eq!(wave.status, PatchWaveStatus::Draft);
        assert_eq!(wave.servers.len(), 3);
        assert_eq!(wave.site_scope, vec!["DEFRA"]);
        assert_eq!(wave.metadata.get("os_family").unwrap(), "windows");
        assert_eq!(wave.metadata.get("criticality").unwrap(), "critical");
        assert_eq!(wave.metadata.get("dry_run").unwrap(), "true");
    }

    #[test]
    fn test_plan_patch_wave_unknown_site_fails() {
        assert!(plan_patch_wave("UNKNOWN", "windows", "high").is_err());
    }

    #[test]
    fn test_plan_patch_wave_invalid_os_fails() {
        assert!(plan_patch_wave("DEFRA", "solaris", "high").is_err());
    }

    #[test]
    fn test_plan_patch_wave_empty_os_fails() {
        assert!(plan_patch_wave("DEFRA", "", "high").is_err());
    }

    #[test]
    fn test_validate_patch_wave_by_id() {
        let wave = plan_patch_wave("GBLON", "linux", "high").unwrap();
        let (updated, result) = validate_patch_wave(&wave).unwrap();
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
        assert_eq!(updated.status, PatchWaveStatus::Validated);
        assert_eq!(updated.metadata.get("validation_passed").unwrap(), "true");
        assert_eq!(updated.metadata.get("validation_dry_run").unwrap(), "true");
        assert!(updated.metadata.contains_key("validated_at"));
    }

    #[test]
    fn test_validate_patch_wave_failed_validation_does_not_validate() {
        let wave = PatchWave {
            id: format!("pw-invalid-{}", Uuid::new_v4()),
            name: "Invalid Patch Wave".into(),
            servers: Vec::new(),
            site_scope: vec!["UNKNOWN".into()],
            environment_scope: vec!["production".into()],
            schedule: PatchSchedule {
                start: "2026-06-15T22:00:00Z".into(),
                end: "2026-06-16T06:00:00Z".into(),
                maintenance_window: "".into(),
                patch_group: Some("Group-A".into()),
            },
            reboot_policy: RebootPolicy::RebootIfRequired,
            blackout_dates: Vec::new(),
            validation_errors: Vec::new(),
            status: PatchWaveStatus::Draft,
            metadata: HashMap::from([("dry_run".into(), "true".into())]),
        };

        let (updated, result) = validate_patch_wave(&wave).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .failed_rules
                .contains(&"p0-patch-servers-required".to_string())
        );
        assert_eq!(updated.status, PatchWaveStatus::Draft);
        assert_eq!(updated.metadata.get("validation_passed").unwrap(), "false");
        assert_eq!(updated.metadata.get("validation_dry_run").unwrap(), "true");
        assert!(!updated.validation_errors.is_empty());
        // Approving a still-Draft wave must fail
        assert!(approve_patch_wave(&updated, "patch-approver").is_err());
    }

    #[test]
    fn test_validate_patch_wave_refuses_completed_wave() {
        let wave = plan_patch_wave("GBLON", "linux", "critical").unwrap();
        let (validated, _) = validate_patch_wave(&wave).unwrap();
        let approved = approve_patch_wave(&validated, "patch-approver").unwrap();
        let (completed, _) = execute_patch_wave(&approved).unwrap();

        let err = validate_patch_wave(&completed).unwrap_err();
        assert!(err.contains("Must be Draft first"));
        assert_eq!(completed.status, PatchWaveStatus::Completed);
    }

    #[test]
    fn test_validate_patch_wave_refuses_failed_wave() {
        let mut wave = plan_patch_wave("NLAMS", "windows", "medium").unwrap();
        wave.status = PatchWaveStatus::Failed;
        let err = validate_patch_wave(&wave).unwrap_err();
        assert!(err.contains("Must be Draft first"));
        assert_eq!(wave.status, PatchWaveStatus::Failed);
    }

    #[test]
    fn test_approve_patch_wave() {
        let wave = plan_patch_wave("NLAMS", "windows", "medium").unwrap();
        let (validated, validation) = validate_patch_wave(&wave).unwrap();
        assert!(validation.passed);
        let approved = approve_patch_wave(&validated, "patch-approver").unwrap();
        assert_eq!(approved.status, PatchWaveStatus::Approved);
        // The approver recorded is the one passed in (the real session principal),
        // not a hardcoded string.
        assert_eq!(approved.metadata.get("approver").unwrap(), "patch-approver");
    }

    #[test]
    fn test_approve_patch_wave_draft_fails() {
        let wave = plan_patch_wave("NLAMS", "windows", "medium").unwrap();
        let result = approve_patch_wave(&wave, "patch-approver").unwrap_err();
        assert!(result.contains("Must pass validation first"));
        assert_eq!(wave.status, PatchWaveStatus::Draft);
    }

    #[test]
    fn test_execute_patch_wave() {
        let wave = plan_patch_wave("DEFRA", "windows", "high").unwrap();
        let (validated, validation) = validate_patch_wave(&wave).unwrap();
        assert!(validation.passed);
        let approved = approve_patch_wave(&validated, "patch-approver").unwrap();
        let (completed, evidence) = execute_patch_wave(&approved).unwrap();
        assert!(evidence.len() >= 5);
        assert!(evidence.iter().any(|e| e.key == "pre-patch-backup-check"));
        assert!(evidence.iter().any(|e| e.key == "post-patch-reboot"));
        assert!(evidence.iter().any(|e| e.key == "post-patch-health-check"));
        assert_eq!(completed.status, PatchWaveStatus::Completed);
        assert_eq!(
            completed.metadata.get("execution_evidence_count").unwrap(),
            &evidence.len().to_string()
        );
        assert!(completed.metadata.contains_key("executed_at"));
    }

    #[test]
    fn test_execute_patch_wave_not_approved_fails() {
        let wave = plan_patch_wave("GBLON", "linux", "low").unwrap();
        assert!(execute_patch_wave(&wave).is_err());
    }

    #[test]
    fn test_verify_patch_wave_requires_execution() {
        let wave = plan_patch_wave("GBLON", "linux", "critical").unwrap();
        assert!(verify_patch_wave(&wave).is_err());
    }

    #[test]
    fn test_verify_patch_wave_after_execute() {
        let wave = plan_patch_wave("GBLON", "linux", "critical").unwrap();
        let (validated, validation) = validate_patch_wave(&wave).unwrap();
        assert!(validation.passed);
        let approved = approve_patch_wave(&validated, "patch-approver").unwrap();
        let (completed, _) = execute_patch_wave(&approved).unwrap();
        let result = verify_patch_wave(&completed).unwrap();
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_patch_wave_happy_path_plan_validate_approve_execute_verify() {
        let wave = plan_patch_wave("DEBER", "linux", "critical").unwrap();
        assert_eq!(wave.status, PatchWaveStatus::Draft);

        let (validated, validation) = validate_patch_wave(&wave).unwrap();
        assert!(validation.passed);
        assert_eq!(validated.status, PatchWaveStatus::Validated);
        assert_eq!(validated.metadata.get("validation_passed").unwrap(), "true");
        assert_eq!(
            validated.metadata.get("validation_dry_run").unwrap(),
            "true"
        );

        let approved = approve_patch_wave(&validated, "patch-approver").unwrap();
        assert_eq!(approved.status, PatchWaveStatus::Approved);

        let (completed, evidence) = execute_patch_wave(&approved).unwrap();
        assert!(evidence.iter().all(|e| e.value.contains("DRY-RUN")));

        let verification = verify_patch_wave(&completed).unwrap();
        assert!(verification.passed);
        assert!(verification.warnings.iter().all(|w| w.contains("DRY-RUN")));
    }

    #[test]
    fn test_get_patch_compliance() {
        let compliance = get_patch_compliance().unwrap();
        assert_eq!(compliance["source"], "dry-run");
        assert_eq!(compliance["dry_run"], true);
        assert!(compliance["sites"].as_array().unwrap().len() == 13);
    }

    #[test]
    fn test_get_pending_reboots() {
        let reboots = get_pending_reboots().unwrap();
        assert_eq!(reboots["source"], "dry-run");
        assert_eq!(reboots["dry_run"], true);
        assert_eq!(reboots["total_pending"], 5);
        assert!(reboots["pending_reboots"].as_array().unwrap().len() == 5);
    }
}
