use crate::models::*;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

pub fn generate_backup_coverage_report(
    site_scope: &[String],
    environment_scope: &[String],
) -> Result<BackupCoverageReport, String> {
    if site_scope.is_empty() {
        return Err("site_scope cannot be empty".into());
    }

    for site in site_scope {
        if !VALID_SITES.contains(&site.as_str()) {
            return Err(format!("Unknown site in scope: {}", site));
        }
    }

    let id = format!(
        "bcr-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let total = (site_scope.len() * 12) as u32;
    let covered = total.saturating_sub(3);
    let missing_backup = 1;
    let missing_dr = 1;
    let stale_policy = 1;

    let mut critical_gaps: Vec<String> = Vec::new();
    critical_gaps.push(format!(
        "DRY-RUN: Site {} has 1 server without backup policy assignment",
        site_scope.first().unwrap_or(&"unknown".into())
    ));
    critical_gaps.push(format!(
        "DRY-RUN: Site {} has 1 server without DR replica configuration",
        site_scope.last().unwrap_or(&"unknown".into())
    ));
    critical_gaps
        .push("DRY-RUN: 1 server has stale backup policy (last verified > 30 days ago)".into());

    let coverage_percentage = if total > 0 {
        (covered as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    Ok(BackupCoverageReport {
        id,
        site_scope: site_scope.to_vec(),
        environment_scope: environment_scope.to_vec(),
        generation_time: chrono::Utc::now().to_rfc3339(),
        total_assets: total,
        covered_assets: covered,
        missing_backup,
        missing_dr_replica: missing_dr,
        stale_policy,
        critical_gaps,
        coverage_percentage,
        status: CoverageReportStatus::Generated,
        recommendations: vec![
            format!(
                "DRY-RUN: Review backup policy assignments for servers across sites {:?} (simulated, no Veeam calls)",
                site_scope
            ),
            "DRY-RUN: Schedule DR replica verification for flagged servers".into(),
            "DRY-RUN: Update stale backup policies before next patch cycle".into(),
        ],
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    })
}

pub fn plan_restore(
    source_ci_key: &str,
    restore_type: RestoreType,
    restore_point: &str,
    target_site: &str,
    target_environment: &str,
    owner: &str,
) -> Result<RestoreRequest, String> {
    if source_ci_key.is_empty() {
        return Err("source_ci_key cannot be empty".into());
    }
    if owner.is_empty() {
        return Err("owner cannot be empty".into());
    }
    if !VALID_SITES.contains(&target_site) {
        return Err(format!("Unknown site: {}", target_site));
    }

    let id = format!(
        "rest-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let dry_run_plan = format!(
        "DRY-RUN: {} restore plan for {} from restore point {}. \
         Target: site={} env={}. \
         Pre-restore checks: backup integrity, target capacity, network isolation. \
         Post-restore verification: service health, data consistency, monitoring re-registration. \
         (Simulated — no Veeam, hypervisor, or provider calls made)",
        restore_type, source_ci_key, restore_point, target_site, target_environment,
    );

    Ok(RestoreRequest {
        id,
        source_ci_key: source_ci_key.to_string(),
        restore_type,
        restore_point: restore_point.to_string(),
        target_site: target_site.to_string(),
        target_environment: target_environment.to_string(),
        verification_plan: "DRY-RUN: Standard verification — service health, data integrity, app connectivity (simulated)".into(),
        retention_need: "30 days post-restore verification retention".into(),
        owner: owner.to_string(),
        status: RestoreStatus::Planned,
        dry_run_plan: Some(dry_run_plan),
        created_at: chrono::Utc::now().to_rfc3339(),
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    })
}

pub fn validate_restore_request(restore: &RestoreRequest) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if restore.source_ci_key.is_empty() {
        errors.push("Missing source CI key".into());
        failed_rules.push("p0-source-ci-key-required".into());
        remediation.push("Provide a valid source CI key.".into());
    }

    if restore.restore_point.is_empty() {
        errors.push("Missing restore point".into());
        failed_rules.push("p0-restore-point-required".into());
        remediation.push("Provide a valid restore point timestamp.".into());
    }

    if restore.owner.is_empty() {
        errors.push("Missing owner".into());
        failed_rules.push("p0-owner-required".into());
        remediation.push("Assign an owner to the restore request.".into());
    }

    warnings.push("DRY-RUN: Backup integrity check simulated".into());
    warnings.push("DRY-RUN: Target capacity check simulated".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn approve_restore(restore: &RestoreRequest, approver: &str) -> Result<RestoreRequest, String> {
    if restore.status == RestoreStatus::Completed || restore.status == RestoreStatus::Failed {
        return Err(format!(
            "Cannot approve restore in terminal status: {:?}",
            restore.status
        ));
    }

    let mut approved = restore.clone();
    approved.status = RestoreStatus::Approved;
    approved
        .metadata
        .insert("approver".into(), approver.to_string());

    Ok(approved)
}

pub fn execute_restore(restore: &RestoreRequest) -> Result<Vec<EvidenceItem>, String> {
    if restore.status != RestoreStatus::Approved {
        return Err(format!(
            "Cannot execute restore in status {:?}. Must be Approved first.",
            restore.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "pre-restore-backup-check".into(),
        value: format!(
            "DRY-RUN: Backup integrity verified for {} at restore point {} (simulated)",
            restore.source_ci_key, restore.restore_point
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "restore-execution-log".into(),
        value: format!(
            "DRY-RUN: {} restore executed for {} (simulated, no Veeam or hypervisor calls)",
            restore.restore_type, restore.source_ci_key
        ),
        redacted_value: Some("***DRY-RUN SIMULATION***".into()),
        redacted: true,
        evidence_type: EvidenceType::ExecutionLog,
    });

    evidence.push(EvidenceItem {
        key: "post-restore-verification".into(),
        value: "DRY-RUN: Post-restore service health and data consistency verified (simulated)"
            .into(),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_site_scope() -> Vec<String> {
        vec!["DEFRA".into(), "GBLON".into()]
    }

    #[test]
    fn test_generate_backup_coverage_report() {
        let report =
            generate_backup_coverage_report(&make_site_scope(), &["production".into()]).unwrap();
        assert!(report.id.starts_with("bcr-"));
        assert_eq!(report.status, CoverageReportStatus::Generated);
        assert!(report.coverage_percentage > 0.0);
        assert!(!report.critical_gaps.is_empty());
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_generate_report_empty_sites_fails() {
        assert!(generate_backup_coverage_report(&[], &[]).is_err());
    }

    #[test]
    fn test_generate_report_unknown_site_fails() {
        assert!(generate_backup_coverage_report(&["UNKNOWN".into()], &[]).is_err());
    }

    #[test]
    fn test_plan_restore() {
        let restore = plan_restore(
            "ci-srv-001",
            RestoreType::FullVm,
            "2026-06-10T02:00:00Z",
            "GBLON",
            "production",
            "backup-team",
        )
        .unwrap();
        assert!(restore.id.starts_with("rest-"));
        assert_eq!(restore.status, RestoreStatus::Planned);
        assert!(restore.dry_run_plan.is_some());
    }

    #[test]
    fn test_plan_restore_empty_ci_key_fails() {
        assert!(
            plan_restore("", RestoreType::FullVm, "rp", "DEFRA", "production", "owner").is_err()
        );
    }

    #[test]
    fn test_plan_restore_unknown_site_fails() {
        assert!(
            plan_restore(
                "ci-001",
                RestoreType::FileLevel,
                "rp",
                "UNKNOWN",
                "production",
                "owner"
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_restore_passes() {
        let restore = plan_restore(
            "ci-srv-001",
            RestoreType::ApplicationItem,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "backup-team",
        )
        .unwrap();
        let result = validate_restore_request(&restore).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_approve_restore() {
        let restore = plan_restore(
            "ci-srv-001",
            RestoreType::InstantVmRecovery,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "backup-team",
        )
        .unwrap();
        let approved = approve_restore(&restore, "Datacenter Approver").unwrap();
        assert_eq!(approved.status, RestoreStatus::Approved);
        assert_eq!(
            approved.metadata.get("approver").unwrap(),
            "Datacenter Approver"
        );
    }

    #[test]
    fn test_execute_restore() {
        let restore = plan_restore(
            "ci-srv-001",
            RestoreType::FullVm,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "backup-team",
        )
        .unwrap();
        let approved = approve_restore(&restore, "Backup Operator").unwrap();
        let evidence = execute_restore(&approved).unwrap();
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().any(|e| e.key == "restore-execution-log"));
    }

    #[test]
    fn test_execute_restore_not_approved_fails() {
        let restore = plan_restore(
            "ci-srv-001",
            RestoreType::FullVm,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "backup-team",
        )
        .unwrap();
        assert!(execute_restore(&restore).is_err());
    }
}
