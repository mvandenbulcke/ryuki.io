use crate::models::*;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

pub fn plan_vm_day2_change(
    target_ci_key: &str,
    change_type: VmChangeType,
    target_value: u32,
    site: &str,
    environment: &str,
    owner: &str,
    maintenance_window: &str,
) -> Result<VmDay2ChangeRequest, String> {
    if target_ci_key.is_empty() {
        return Err("target_ci_key cannot be empty".into());
    }
    if site.is_empty() {
        return Err("site cannot be empty".into());
    }
    if owner.is_empty() {
        return Err("owner cannot be empty".into());
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let id = format!(
        "vmch-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let now = chrono::Utc::now().to_rfc3339();

    let plan = VmDay2Plan {
        current_state: VmCurrentState {
            cpu: 4,
            memory_gb: 16,
            disk_gb: 100,
            host: "esx-host-01".into(),
            datastore: "datastore-01".into(),
        },
        desired_state: VmDesiredState {
            cpu: match change_type {
                VmChangeType::ResizeCpu => target_value,
                _ => 4,
            },
            memory_gb: match change_type {
                VmChangeType::ResizeMemory => target_value,
                _ => 16,
            },
            disk_gb: match change_type {
                VmChangeType::ExtendDisk => 100 + target_value,
                VmChangeType::AddDisk => 100 + target_value,
                _ => 100,
            },
        },
        capacity_impact: format!(
            "DRY-RUN: Capacity impact assessed for {} change on {}. Cluster headroom reviewed (simulated).",
            change_type, target_ci_key
        ),
        backup_impact: format!(
            "DRY-RUN: Backup policy verification for {} after {} change (simulated, no Veeam calls)",
            target_ci_key, change_type
        ),
        monitoring_impact: format!(
            "DRY-RUN: Monitoring impact reviewed for {} after {} change (simulated, no Zabbix calls)",
            target_ci_key, change_type
        ),
        rollback_notes: format!(
            "DRY-RUN: Rollback plan: revert {} to previous {} value if needed",
            change_type,
            match change_type {
                VmChangeType::ResizeCpu => "cpu=4",
                VmChangeType::ResizeMemory => "memory_gb=16",
                VmChangeType::AddDisk | VmChangeType::ExtendDisk => "disk_gb=100",
                VmChangeType::MigrateHost => "host=esx-host-01",
                VmChangeType::MigrateStorage => "datastore=datastore-01",
            }
        ),
        verification_plan: "DRY-RUN: Post-change verification: service health, CPU/memory/disk metrics, backup status (simulated)".to_string(),
    };

    Ok(VmDay2ChangeRequest {
        id,
        target_ci_key: target_ci_key.to_string(),
        change_type,
        target_value,
        site: site.to_string(),
        environment: environment.to_string(),
        owner: owner.to_string(),
        maintenance_window: maintenance_window.to_string(),
        status: VmChangeStatus::Planned,
        plan: Some(plan),
        created_at: now.clone(),
        updated_at: now,
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    })
}

pub fn validate_vm_day2_change(change: &VmDay2ChangeRequest) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if change.target_ci_key.is_empty() {
        errors.push("Missing target CI key".into());
        failed_rules.push("p0-missing-ci-key".into());
        remediation.push("Provide a valid platform CI key.".into());
    }

    if !VALID_SITES.contains(&change.site.as_str()) {
        errors.push(format!("Unknown site: {}", change.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(format!(
            "Select a known site. Valid sites: {:?}",
            VALID_SITES
        ));
    }

    if change.maintenance_window.is_empty() {
        errors.push("Missing maintenance window".into());
        failed_rules.push("p0-maintenance-window-required".into());
        remediation.push("Provide an approved maintenance window.".into());
    }

    match change.change_type {
        VmChangeType::ResizeCpu if change.target_value == 0 => {
            errors.push("CPU target value cannot be zero".into());
            failed_rules.push("p0-invalid-target-value".into());
            remediation.push("Provide valid CPU count.".into());
        }
        VmChangeType::ResizeMemory if change.target_value == 0 => {
            errors.push("Memory target value cannot be zero".into());
            failed_rules.push("p0-invalid-target-value".into());
            remediation.push("Provide valid memory size in GB.".into());
        }
        VmChangeType::ExtendDisk | VmChangeType::AddDisk if change.target_value == 0 => {
            errors.push("Disk target value cannot be zero".into());
            failed_rules.push("p0-invalid-target-value".into());
            remediation.push("Provide valid disk size in GB.".into());
        }
        _ => {}
    }

    warnings.push("DRY-RUN: No live provider validation performed".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn execute_vm_day2_change(change: &VmDay2ChangeRequest) -> Result<VmDay2ChangeRequest, String> {
    if change.status == VmChangeStatus::Failed || change.status == VmChangeStatus::Completed {
        return Err(format!(
            "Cannot execute change in terminal status: {:?}",
            change.status
        ));
    }

    let mut executed = change.clone();
    executed.status = VmChangeStatus::Executed;
    executed.updated_at = chrono::Utc::now().to_rfc3339();
    executed.metadata.insert(
        "execution_log".into(),
        format!(
            "DRY-RUN: Simulated {} change for {} (no hypervisor calls made)",
            executed.change_type, executed.target_ci_key
        ),
    );

    Ok(executed)
}

pub fn verify_vm_day2_change(change: &VmDay2ChangeRequest) -> Result<Vec<EvidenceItem>, String> {
    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "vm-pre-change-state".into(),
        value: format!(
            "DRY-RUN: Pre-change state snapshot for {} (simulated)",
            change.target_ci_key
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "vm-post-change-state".into(),
        value: format!(
            "DRY-RUN: Post-change state verification for {} (simulated)",
            change.target_ci_key
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "vm-service-health".into(),
        value: "DRY-RUN: Service health check passed after change (simulated)".into(),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_vm_resize_cpu() {
        let change = plan_vm_day2_change(
            "ci-vm-001",
            VmChangeType::ResizeCpu,
            8,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight-2026-06-15",
        )
        .unwrap();
        assert_eq!(change.change_type, VmChangeType::ResizeCpu);
        assert_eq!(change.status, VmChangeStatus::Planned);
        let plan = change.plan.unwrap();
        assert_eq!(plan.desired_state.cpu, 8);
        assert_eq!(plan.desired_state.memory_gb, 16);
    }

    #[test]
    fn test_plan_vm_extend_disk() {
        let change = plan_vm_day2_change(
            "ci-vm-002",
            VmChangeType::ExtendDisk,
            50,
            "GBLON",
            "production",
            "db-team",
            "EU-Overnight-2026-06-16",
        )
        .unwrap();
        let plan = change.plan.unwrap();
        assert_eq!(plan.desired_state.disk_gb, 150);
    }

    #[test]
    fn test_plan_vm_empty_ci_key_fails() {
        assert!(
            plan_vm_day2_change(
                "",
                VmChangeType::ResizeCpu,
                4,
                "DEFRA",
                "production",
                "owner",
                "window"
            )
            .is_err()
        );
    }

    #[test]
    fn test_plan_vm_unknown_site_fails() {
        assert!(
            plan_vm_day2_change(
                "ci-001",
                VmChangeType::ResizeCpu,
                4,
                "UNKNOWN",
                "production",
                "owner",
                "window"
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_vm_change_passes() {
        let change = plan_vm_day2_change(
            "ci-vm-001",
            VmChangeType::ResizeMemory,
            32,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight",
        )
        .unwrap();
        let result = validate_vm_day2_change(&change).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_vm_change_detects_bad_site() {
        let mut change = plan_vm_day2_change(
            "ci-vm-001",
            VmChangeType::ResizeCpu,
            4,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight",
        )
        .unwrap();
        change.site = "INVALID".into();
        let result = validate_vm_day2_change(&change).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_execute_vm_change() {
        let change = plan_vm_day2_change(
            "ci-vm-001",
            VmChangeType::MigrateHost,
            0,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight",
        )
        .unwrap();
        let executed = execute_vm_day2_change(&change).unwrap();
        assert_eq!(executed.status, VmChangeStatus::Executed);
        assert!(executed.metadata.contains_key("execution_log"));
    }

    #[test]
    fn test_verify_vm_change() {
        let change = plan_vm_day2_change(
            "ci-vm-001",
            VmChangeType::ResizeCpu,
            8,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight",
        )
        .unwrap();
        let evidence = verify_vm_day2_change(&change).unwrap();
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().any(|e| e.key == "vm-pre-change-state"));
        assert!(evidence.iter().any(|e| e.key == "vm-service-health"));
    }

    #[test]
    fn test_all_change_types_have_display() {
        let types = [
            VmChangeType::ResizeCpu,
            VmChangeType::ResizeMemory,
            VmChangeType::AddDisk,
            VmChangeType::ExtendDisk,
            VmChangeType::MigrateHost,
            VmChangeType::MigrateStorage,
        ];
        for t in &types {
            let s = t.to_string();
            assert!(!s.is_empty());
        }
    }
}
