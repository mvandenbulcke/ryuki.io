use crate::{models::*, site_registry};
use std::collections::HashMap;
use uuid::Uuid;

/// Conservative byte ceiling for each durable restore-authority component.
/// This is shared with the scheduler and migration 186; it bounds both storage
/// and every downstream composite queue key.
pub const RESTORE_AUTHORITY_COMPONENT_MAX_BYTES: usize = 512;

/// Canonical resource/principal components are nonblank, exact-trimmed UTF-8
/// and bounded by bytes (the database uses `octet_length`, not character
/// count).  Callers reject rather than normalize so scope checks, persistence,
/// audit, and queue dedup all refer to one exact authority value.
pub fn is_canonical_restore_authority_component(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= RESTORE_AUTHORITY_COMPONENT_MAX_BYTES
}

fn require_canonical_restore_authority_component(value: &str, label: &str) -> Result<(), String> {
    if is_canonical_restore_authority_component(value) {
        Ok(())
    } else {
        Err(format!(
            "{label} must be nonblank, exact-trimmed, and at most \
             {RESTORE_AUTHORITY_COMPONENT_MAX_BYTES} bytes"
        ))
    }
}

/// Prove the maker/checker identities required by every Approved-or-later
/// restore operation.  Persisted legacy records cannot acquire fabricated
/// provenance at execution time; they must be replanned.
pub fn validate_restore_approval_provenance(restore: &RestoreRequest) -> Result<(), String> {
    let planned_by = restore
        .metadata
        .get("planned_by")
        .ok_or_else(|| "Restore has no trusted planner identity; replan before use".to_string())?;
    require_canonical_restore_authority_component(planned_by, "planned_by")?;

    let approver = restore
        .metadata
        .get("approver")
        .ok_or_else(|| "Restore has no trusted approver identity; replan before use".to_string())?;
    require_canonical_restore_authority_component(approver, "approver")?;
    if planned_by == approver {
        return Err("The restore planner cannot approve the same restore".into());
    }
    Ok(())
}

pub fn generate_backup_coverage_report(
    site_scope: &[String],
    environment_scope: &[String],
) -> Result<BackupCoverageReport, String> {
    if site_scope.is_empty() {
        return Err("site_scope cannot be empty".into());
    }

    for site in site_scope {
        if !site_registry::is_valid_site(site) {
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
    planned_by: &str,
) -> Result<RestoreRequest, String> {
    require_canonical_restore_authority_component(source_ci_key, "source_ci_key")?;
    require_canonical_restore_authority_component(target_site, "target_site")?;
    require_canonical_restore_authority_component(target_environment, "target_environment")?;
    require_canonical_restore_authority_component(planned_by, "planned_by")?;
    if owner.is_empty() {
        return Err("owner cannot be empty".into());
    }
    // restore_point is a required p0 field (validate_restore_request enforces it
    // too). Rejecting it here means a Planned restore always satisfies every p0
    // validation rule, so approving a Planned restore can never bless an
    // incomplete request.
    if restore_point.is_empty() {
        return Err("restore_point cannot be empty".into());
    }
    if !site_registry::is_valid_site(target_site) {
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
        metadata: HashMap::from([
            ("dry_run".into(), "true".into()),
            ("planned_by".into(), planned_by.to_string()),
        ]),
    })
}

pub fn validate_restore_request(restore: &RestoreRequest) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if !is_canonical_restore_authority_component(&restore.source_ci_key) {
        errors.push("Missing source CI key".into());
        failed_rules.push("p0-source-ci-key-required".into());
        remediation.push("Provide a canonical, bounded source CI key.".into());
    }

    if !is_canonical_restore_authority_component(&restore.target_site) {
        errors.push("Invalid target site authority".into());
        failed_rules.push("p0-target-site-canonical".into());
        remediation.push("Provide a canonical, bounded target site.".into());
    }

    if !is_canonical_restore_authority_component(&restore.target_environment) {
        errors.push("Invalid target environment authority".into());
        failed_rules.push("p0-target-environment-canonical".into());
        remediation.push("Provide a canonical, bounded target environment.".into());
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
    require_canonical_restore_authority_component(approver, "approver")?;
    if restore.status != RestoreStatus::Planned {
        return Err(format!(
            "Cannot approve restore in status {:?}. Must be Planned first.",
            restore.status
        ));
    }
    let planned_by = restore.metadata.get("planned_by").ok_or_else(|| {
        "Restore has no trusted planner identity; replan before approval".to_string()
    })?;
    require_canonical_restore_authority_component(planned_by, "planned_by")?;
    if planned_by == approver {
        return Err("The restore planner cannot approve the same restore".into());
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
    validate_restore_approval_provenance(restore)?;

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

    fn register_backup_test_site(code: &str, active: bool) {
        site_registry::upsert_site(
            site_registry::SiteEntry {
                unlocode: code.into(),
                name: format!("Backup test site {code}"),
                country: "Test country".into(),
                country_code: "ZZ".into(),
                timezone: "UTC".into(),
                active,
            },
            site_registry::SiteCodeSystem::Custom,
        )
        .unwrap();
    }

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
    fn registered_custom_site_is_admitted_but_inactive_and_unknown_sites_are_rejected() {
        const ACTIVE: &str = "LEGACY-BACKUP-ACTIVE";
        const INACTIVE: &str = "LEGACY-BACKUP-INACTIVE";
        register_backup_test_site(ACTIVE, true);
        register_backup_test_site(INACTIVE, false);

        assert!(generate_backup_coverage_report(&[ACTIVE.into()], &[]).is_ok());
        assert!(
            plan_restore(
                "ci-custom-001",
                RestoreType::FullVm,
                "2026-07-10T00:00:00Z",
                ACTIVE,
                "test",
                "backup-test",
                "backup.planner",
            )
            .is_ok()
        );
        assert!(generate_backup_coverage_report(&[INACTIVE.into()], &[]).is_err());
        assert!(generate_backup_coverage_report(&["LEGACY-BACKUP-UNKNOWN".into()], &[]).is_err());
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
            "backup.planner",
        )
        .unwrap();
        assert!(restore.id.starts_with("rest-"));
        assert_eq!(restore.status, RestoreStatus::Planned);
        assert!(restore.dry_run_plan.is_some());
        assert_eq!(
            restore.metadata.get("planned_by").map(String::as_str),
            Some("backup.planner")
        );
    }

    #[test]
    fn test_plan_restore_empty_ci_key_fails() {
        assert!(
            plan_restore(
                "",
                RestoreType::FullVm,
                "rp",
                "DEFRA",
                "production",
                "owner",
                "backup.planner"
            )
            .is_err()
        );
    }

    #[test]
    fn restore_authority_components_reject_padding_and_oversize_at_ingress() {
        let oversized = "x".repeat(RESTORE_AUTHORITY_COMPONENT_MAX_BYTES + 1);
        for source_ci_key in [" ci-001", "ci-001 ", "\tci-001", oversized.as_str()] {
            let result = plan_restore(
                source_ci_key,
                RestoreType::FullVm,
                "rp",
                "DEFRA",
                "production",
                "owner",
                "backup.planner",
            );
            assert!(
                result.is_err(),
                "malformed authority was accepted: {source_ci_key:?}"
            );
        }

        assert!(
            plan_restore(
                "ci-001",
                RestoreType::FullVm,
                "rp",
                "DEFRA ",
                "production",
                "owner",
                "backup.planner",
            )
            .is_err()
        );
        assert!(
            plan_restore(
                "ci-001",
                RestoreType::FullVm,
                "rp",
                "DEFRA",
                " production",
                "owner",
                "backup.planner",
            )
            .is_err()
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
                "owner",
                "backup.planner"
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
            "backup.planner",
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
            "backup.planner",
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
    fn restore_planner_cannot_approve_own_plan_and_legacy_rows_fail_closed() {
        let restore = plan_restore(
            "ci-srv-001",
            RestoreType::InstantVmRecovery,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "business-owner",
            "stable.subject.planner",
        )
        .unwrap();
        let before = restore.clone();

        let error = approve_restore(&restore, "stable.subject.planner")
            .expect_err("the verified planner must not self-approve");
        assert!(error.contains("planner cannot approve"));
        assert_eq!(restore, before, "a denied pure transition is immutable");

        let mut legacy = restore;
        legacy.metadata.remove("planned_by");
        let error = approve_restore(&legacy, "different.approver")
            .expect_err("makerless legacy rows cannot prove separation of duties");
        assert!(error.contains("no trusted planner identity"));
        assert_eq!(legacy.status, RestoreStatus::Planned);
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
            "backup.planner",
        )
        .unwrap();
        let approved = approve_restore(&restore, "Backup Operator").unwrap();
        let evidence = execute_restore(&approved).unwrap();
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().any(|e| e.key == "restore-execution-log"));
    }

    #[test]
    fn every_execute_rechecks_distinct_canonical_approval_provenance() {
        let restore = plan_restore(
            "ci-srv-approval-proof",
            RestoreType::FullVm,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "backup-team",
            "backup.planner",
        )
        .unwrap();
        let approved = approve_restore(&restore, "backup.approver").unwrap();
        assert!(execute_restore(&approved).is_ok());

        for bad_approver in [
            None,
            Some(""),
            Some(" backup.approver"),
            Some("backup.planner"),
        ] {
            let mut tampered = approved.clone();
            match bad_approver {
                Some(value) => {
                    tampered.metadata.insert("approver".into(), value.into());
                }
                None => {
                    tampered.metadata.remove("approver");
                }
            }
            assert!(
                execute_restore(&tampered).is_err(),
                "execute accepted invalid approval provenance: {bad_approver:?}"
            );
        }
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
            "backup.planner",
        )
        .unwrap();
        assert!(execute_restore(&restore).is_err());
    }

    /// approve_restore must reject any record that is not in Planned status.
    /// A Draft record has never gone through plan_restore so it is not Planned.
    #[test]
    fn test_approve_rejects_non_planned() {
        let mut restore = plan_restore(
            "ci-srv-001",
            RestoreType::FullVm,
            "2026-06-10T02:00:00Z",
            "DEFRA",
            "production",
            "backup-team",
            "backup.planner",
        )
        .unwrap();
        // Manually set status to Draft to simulate a non-Planned record.
        restore.status = RestoreStatus::Draft;
        let result = approve_restore(&restore, "approver");
        assert!(result.is_err(), "approve must reject a non-Planned restore");
        assert!(
            result.unwrap_err().contains("Must be Planned first"),
            "error message must mention Planned"
        );
    }

    #[test]
    fn test_plan_restore_empty_restore_point_fails() {
        // restore_point is a required p0 field; plan must reject an empty one so
        // an incomplete restore can never reach Planned (and thus never be
        // approved).
        let result = plan_restore(
            "ci-srv-001",
            RestoreType::FullVm,
            "",
            "DEFRA",
            "production",
            "backup-team",
            "backup.planner",
        );
        assert!(result.is_err(), "plan must reject an empty restore_point");
    }
}
