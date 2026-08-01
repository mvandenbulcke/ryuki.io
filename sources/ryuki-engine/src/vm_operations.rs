use crate::{models::*, site_registry};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

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
    if environment.is_empty() {
        return Err("environment cannot be empty".into());
    }
    if owner.is_empty() {
        return Err("owner cannot be empty".into());
    }
    if !site_registry::is_valid_site(site) {
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
                // target_value is caller-supplied; saturate so a huge value can
                // never overflow u32 (panic in debug / wrap in release).
                VmChangeType::ExtendDisk => target_value.saturating_add(100),
                VmChangeType::AddDisk => target_value.saturating_add(100),
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
        target_authority: None,
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
        governance: None,
    })
}

/// Stable digest for the immutable Day-2 plan. Governance evidence deliberately
/// excludes status, timestamps that change after planning, metadata, approval,
/// and lock fields so each lifecycle transition can recompute the same value.
pub fn vm_day2_plan_digest(change: &VmDay2ChangeRequest) -> Result<String, String> {
    let material = serde_json::json!({
        "id": change.id,
        "target_ci_key": change.target_ci_key,
        "target_authority": change.target_authority,
        "change_type": change.change_type,
        "target_value": change.target_value,
        "site": change.site,
        "environment": change.environment,
        "owner": change.owner,
        "maintenance_window": change.maintenance_window,
        "plan": change.plan,
        "created_at": change.created_at,
    });
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| format!("cannot encode VM Day-2 plan digest material: {error}"))?;
    let digest = Sha256::digest(encoded);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Bind the immutable CMDB UUID selected by the repository's typed authorized
/// target. Callers cannot select another provenance kind.
pub fn bind_vm_day2_target_authority(
    change: &mut VmDay2ChangeRequest,
    configuration_item_id: &str,
) -> Result<(), String> {
    if change.status != VmChangeStatus::Planned {
        return Err("VM Day-2 target authority can only be bound while Planned".into());
    }
    if change.governance.is_some() || change.target_authority.is_some() {
        return Err("VM Day-2 target authority is already bound".into());
    }
    let configuration_item_id = Uuid::parse_str(configuration_item_id)
        .map_err(|_| "VM Day-2 CMDB target identity must be a UUID")?;
    change.target_authority = Some(VmDay2TargetAuthority {
        configuration_item_id: configuration_item_id.to_string(),
        provenance: VmDay2TargetProvenance::CmdbConfigurationItem,
    });
    Ok(())
}

/// Bind a newly planned operation to its verified maker after the API has
/// replaced the engine's display id with the durable UUID primary key.
pub fn bind_vm_day2_governance(
    change: &mut VmDay2ChangeRequest,
    planned_by: &str,
) -> Result<(), String> {
    if planned_by.trim().is_empty() {
        return Err("planned_by cannot be empty".into());
    }
    if change.status != VmChangeStatus::Planned {
        return Err("VM Day-2 governance can only be bound while Planned".into());
    }
    if change.governance.is_some() {
        return Err("VM Day-2 governance is already bound".into());
    }
    let authority = change
        .target_authority
        .as_ref()
        .ok_or_else(|| "VM Day-2 operation has no authoritative CMDB target".to_string())?;
    Uuid::parse_str(&authority.configuration_item_id)
        .map_err(|_| "VM Day-2 CMDB target identity must be a UUID")?;
    let plan_digest = vm_day2_plan_digest(change)?;
    change.governance = Some(VmDay2Governance {
        plan_digest,
        planned_by: planned_by.to_string(),
        approval: None,
        operation_lock: None,
    });
    Ok(())
}

fn current_governance(change: &VmDay2ChangeRequest) -> Result<&VmDay2Governance, String> {
    let authority = change
        .target_authority
        .as_ref()
        .ok_or_else(|| "VM Day-2 operation has no authoritative CMDB target".to_string())?;
    Uuid::parse_str(&authority.configuration_item_id)
        .map_err(|_| "VM Day-2 CMDB target identity must be a UUID")?;
    let governance = change
        .governance
        .as_ref()
        .ok_or_else(|| "VM Day-2 operation has no trusted governance binding".to_string())?;
    if governance.planned_by.trim().is_empty() {
        return Err("VM Day-2 operation has no trusted planner".into());
    }
    let current_digest = vm_day2_plan_digest(change)?;
    if governance.plan_digest != current_digest {
        return Err("VM Day-2 plan changed after governance binding".into());
    }
    Ok(governance)
}

fn current_approval(governance: &VmDay2Governance) -> Result<&VmDay2ApprovalEvidence, String> {
    let approval = governance
        .approval
        .as_ref()
        .ok_or_else(|| "VM Day-2 approval evidence is missing".to_string())?;
    if approval.approved_by.trim().is_empty()
        || approval.approved_by == governance.planned_by
        || approval.plan_digest != governance.plan_digest
        || DateTime::parse_from_rfc3339(&approval.approved_at).is_err()
    {
        return Err("VM Day-2 approval evidence is invalid or stale".into());
    }
    Ok(approval)
}

pub fn approve_vm_day2_change(
    change: &VmDay2ChangeRequest,
    approver: &str,
) -> Result<VmDay2ChangeRequest, String> {
    if approver.trim().is_empty() {
        return Err("approver cannot be empty".into());
    }
    if change.status != VmChangeStatus::Validated {
        return Err(format!(
            "Cannot approve VM Day-2 operation in status {:?}. Must be Validated first.",
            change.status
        ));
    }
    let governance = current_governance(change)?;
    if governance.planned_by == approver {
        return Err("VM Day-2 planner cannot approve the same operation".into());
    }
    if governance.approval.is_some() || governance.operation_lock.is_some() {
        return Err("VM Day-2 operation already carries governance decision state".into());
    }

    let mut approved = change.clone();
    approved.status = VmChangeStatus::Approved;
    approved.updated_at = Utc::now().to_rfc3339();
    approved
        .governance
        .as_mut()
        .expect("validated governance above")
        .approval = Some(VmDay2ApprovalEvidence {
        approved_by: approver.to_string(),
        approved_at: Utc::now().to_rfc3339(),
        plan_digest: governance.plan_digest.clone(),
    });
    Ok(approved)
}

/// Acquire a short, server-timed lock for the exact approved plan. Cross-row
/// overlap is enforced by the repository in the same transaction that stores
/// this evidence.
pub fn lock_vm_day2_change(
    change: &VmDay2ChangeRequest,
    locked_by: &str,
) -> Result<VmDay2ChangeRequest, String> {
    if locked_by.trim().is_empty() {
        return Err("lock owner cannot be empty".into());
    }
    if change.status != VmChangeStatus::Approved {
        return Err(format!(
            "Cannot lock VM Day-2 operation in status {:?}. Must be Approved first.",
            change.status
        ));
    }
    let governance = current_governance(change)?;
    current_approval(governance)?;
    if governance.operation_lock.is_some() {
        return Err("VM Day-2 operation already carries a lock".into());
    }

    let now = Utc::now();
    let mut locked = change.clone();
    locked.status = VmChangeStatus::Locked;
    locked.updated_at = now.to_rfc3339();
    locked
        .governance
        .as_mut()
        .expect("approved governance above")
        .operation_lock = Some(VmDay2LockEvidence {
        lock_id: Uuid::new_v4().to_string(),
        locked_by: locked_by.to_string(),
        acquired_at: now.to_rfc3339(),
        expires_at: (now + Duration::minutes(15)).to_rfc3339(),
        plan_digest: governance.plan_digest.clone(),
    });
    Ok(locked)
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

    if !site_registry::is_valid_site(&change.site) {
        errors.push(format!("Unknown site: {}", change.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(format!(
            "Select an active site. Valid sites: {:?}",
            site_registry::get_active_site_codes().unwrap_or_default()
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

    if let Err(error) = current_governance(change) {
        errors.push(error);
        failed_rules.push("p0-governance-plan-binding-required".into());
        remediation.push(
            "Replan the operation so approval and lock evidence bind to the immutable plan.".into(),
        );
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
    if change.status != VmChangeStatus::Locked {
        return Err(format!(
            "Cannot execute VM Day-2 operation in status {:?}. Must be Approved and Locked first.",
            change.status
        ));
    }
    let governance = current_governance(change)?;
    current_approval(governance)?;
    let operation_lock = governance
        .operation_lock
        .as_ref()
        .ok_or_else(|| "VM Day-2 operation lock is missing".to_string())?;
    if Uuid::parse_str(&operation_lock.lock_id).is_err()
        || operation_lock.locked_by.trim().is_empty()
        || operation_lock.plan_digest != governance.plan_digest
    {
        return Err("VM Day-2 operation lock is invalid or stale".into());
    }
    let acquired_at = DateTime::parse_from_rfc3339(&operation_lock.acquired_at)
        .map_err(|_| "VM Day-2 operation lock acquisition time is invalid".to_string())?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&operation_lock.expires_at)
        .map_err(|_| "VM Day-2 operation lock expiry is invalid".to_string())?
        .with_timezone(&Utc);
    if expires_at <= acquired_at {
        return Err("VM Day-2 operation lock interval is invalid".into());
    }
    if expires_at <= Utc::now() {
        return Err("VM Day-2 operation lock has expired".into());
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
    if change.status != VmChangeStatus::Executed {
        return Err(format!(
            "Cannot verify VM Day-2 operation in status {:?}. Must be Executed first.",
            change.status
        ));
    }
    let governance = current_governance(change)?;
    current_approval(governance)?;
    let operation_lock = governance
        .operation_lock
        .as_ref()
        .ok_or_else(|| "VM Day-2 operation lock is missing".to_string())?;
    let acquired_at = DateTime::parse_from_rfc3339(&operation_lock.acquired_at)
        .map_err(|_| "VM Day-2 operation lock acquisition time is invalid".to_string())?;
    let expires_at = DateTime::parse_from_rfc3339(&operation_lock.expires_at)
        .map_err(|_| "VM Day-2 operation lock expiry is invalid".to_string())?;
    if Uuid::parse_str(&operation_lock.lock_id).is_err()
        || operation_lock.locked_by.trim().is_empty()
        || operation_lock.plan_digest != governance.plan_digest
        || expires_at <= acquired_at
    {
        return Err("VM Day-2 operation lock is invalid or stale".into());
    }

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

    fn governed_change(change_type: VmChangeType, target_value: u32) -> VmDay2ChangeRequest {
        let mut change = plan_vm_day2_change(
            "ci-vm-governed",
            change_type,
            target_value,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight",
        )
        .unwrap();
        change.id = Uuid::new_v4().to_string();
        bind_vm_day2_target_authority(&mut change, &Uuid::new_v4().to_string()).unwrap();
        bind_vm_day2_governance(&mut change, "stable.vm.planner").unwrap();
        change
    }

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
    fn governance_requires_and_digests_cmdb_target_authority() {
        let mut change = plan_vm_day2_change(
            "ci-vm-001",
            VmChangeType::ResizeCpu,
            4,
            "DEFRA",
            "production",
            "owner",
            "window",
        )
        .unwrap();
        change.id = Uuid::new_v4().to_string();

        let missing = bind_vm_day2_governance(&mut change, "stable.vm.planner")
            .expect_err("an arbitrary target string cannot be governed");
        assert!(missing.contains("no authoritative CMDB target"));

        bind_vm_day2_target_authority(&mut change, &Uuid::new_v4().to_string()).unwrap();
        bind_vm_day2_governance(&mut change, "stable.vm.planner").unwrap();
        change
            .target_authority
            .as_mut()
            .expect("bound target")
            .configuration_item_id = Uuid::new_v4().to_string();
        let stale = validate_vm_day2_change(&change).unwrap();
        assert!(!stale.passed);
        assert!(
            stale
                .errors
                .iter()
                .any(|error| error.contains("changed after governance binding"))
        );
    }

    #[test]
    fn test_validate_vm_change_passes() {
        let change = governed_change(VmChangeType::ResizeMemory, 32);
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
        change.id = Uuid::new_v4().to_string();
        bind_vm_day2_target_authority(&mut change, &Uuid::new_v4().to_string()).unwrap();
        bind_vm_day2_governance(&mut change, "stable.vm.planner").unwrap();
        change.site = "INVALID".into();
        let result = validate_vm_day2_change(&change).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_execute_vm_change() {
        let mut change = governed_change(VmChangeType::MigrateHost, 0);
        change.status = VmChangeStatus::Validated;
        let approved = approve_vm_day2_change(&change, "stable.vm.approver").unwrap();
        let locked = lock_vm_day2_change(&approved, "stable.vm.executor").unwrap();
        let executed = execute_vm_day2_change(&locked).unwrap();
        assert_eq!(executed.status, VmChangeStatus::Executed);
        assert!(executed.metadata.contains_key("execution_log"));
    }

    #[test]
    fn execution_rejects_missing_stale_and_expired_governance() {
        let mut validated = governed_change(VmChangeType::ResizeCpu, 8);
        validated.status = VmChangeStatus::Validated;
        let error = execute_vm_day2_change(&validated)
            .expect_err("technical validation alone must not authorize execution");
        assert!(error.contains("Approved and Locked"));

        let approved = approve_vm_day2_change(&validated, "stable.vm.approver").unwrap();
        let error = execute_vm_day2_change(&approved)
            .expect_err("approval without a target lock must not execute");
        assert!(error.contains("Approved and Locked"));

        let mut locked = lock_vm_day2_change(&approved, "stable.vm.executor").unwrap();
        let expired_at = Utc::now() - Duration::seconds(1);
        let operation_lock = locked
            .governance
            .as_mut()
            .unwrap()
            .operation_lock
            .as_mut()
            .unwrap();
        operation_lock.acquired_at = (expired_at - Duration::seconds(1)).to_rfc3339();
        operation_lock.expires_at = expired_at.to_rfc3339();
        let error = execute_vm_day2_change(&locked).expect_err("an expired lock must fail closed");
        assert!(error.contains("expired"));

        let mut stale = approved;
        stale.target_value = stale.target_value.saturating_add(1);
        let error = lock_vm_day2_change(&stale, "stable.vm.executor")
            .expect_err("approval cannot authorize a modified plan");
        assert!(error.contains("changed after governance binding"));
    }

    #[test]
    fn vm_day2_planner_cannot_self_approve() {
        let mut validated = governed_change(VmChangeType::ResizeCpu, 8);
        validated.status = VmChangeStatus::Validated;
        let before = validated.clone();

        let error = approve_vm_day2_change(&validated, "stable.vm.planner")
            .expect_err("maker/checker separation must use stable subjects");

        assert!(error.contains("planner cannot approve"));
        assert_eq!(validated, before);
    }

    #[test]
    fn test_verify_vm_change() {
        let mut change = governed_change(VmChangeType::ResizeCpu, 8);
        change.status = VmChangeStatus::Validated;
        let approved = approve_vm_day2_change(&change, "stable.vm.approver").unwrap();
        let locked = lock_vm_day2_change(&approved, "stable.vm.executor").unwrap();
        let executed = execute_vm_day2_change(&locked).unwrap();
        let evidence = verify_vm_day2_change(&executed).unwrap();
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().any(|e| e.key == "vm-pre-change-state"));
        assert!(evidence.iter().any(|e| e.key == "vm-service-health"));
    }

    #[test]
    fn verify_rejects_ungoverned_arbitrary_target() {
        let mut change = plan_vm_day2_change(
            "attacker-selected-target",
            VmChangeType::ResizeCpu,
            8,
            "DEFRA",
            "production",
            "app-team",
            "EU-Overnight",
        )
        .unwrap();
        change.status = VmChangeStatus::Executed;
        let error = verify_vm_day2_change(&change)
            .expect_err("an arbitrary ungoverned target cannot produce evidence");
        assert!(error.contains("no authoritative CMDB target"));
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
