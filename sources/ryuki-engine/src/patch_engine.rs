use crate::models::*;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &[
    "LOVE", "BUR1", "CCSS", "TOR1", "TRUJ", "VILL", "ALBI", "AOST", "MACL", "SSYM", "WIJH", "RMA1",
    "PITE",
];

pub fn plan_patch_wave(servers: &[Server]) -> Result<PatchWave, String> {
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
        assert!(plan_patch_wave(&[]).is_err());
    }

    #[test]
    fn test_plan_patch_wave_creates_wave() {
        let servers = vec![
            make_test_server("srv-001", "web01", "LOVE", "production", "high"),
            make_test_server("srv-002", "app01", "LOVE", "production", "critical"),
            make_test_server("srv-003", "db01", "BUR1", "production", "critical"),
        ];

        let wave = plan_patch_wave(&servers).unwrap();
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
            "LOVE",
            "production",
            "high",
        )];
        let wave = plan_patch_wave(&servers).unwrap();
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
        let mut wave = plan_patch_wave(&servers).unwrap();
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
            make_test_server("srv-001", "web01", "LOVE", "production", "high"),
            make_test_server("srv-002", "app01", "BUR1", "production", "critical"),
        ];
        let wave = plan_patch_wave(&servers).unwrap();
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
    fn test_all_stages_are_dry_run() {
        let servers = vec![make_test_server(
            "srv-001",
            "web01",
            "LOVE",
            "production",
            "high",
        )];
        let wave = plan_patch_wave(&servers).unwrap();
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
}
