use crate::models::*;
use std::collections::HashMap;
use uuid::Uuid;

pub fn plan_snapshot(
    platform_ci_key: &str,
    snapshot_purpose: &str,
    requested_expiry: &str,
    owner: &str,
    support_group: &str,
    change_context: &str,
) -> Result<SnapshotRecord, String> {
    if platform_ci_key.is_empty() {
        return Err("platform_ci_key cannot be empty".into());
    }
    if owner.is_empty() {
        return Err("owner cannot be empty".into());
    }
    if requested_expiry.is_empty() {
        return Err("requested_expiry cannot be empty".into());
    }

    let id = format!(
        "snap-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let now = chrono::Utc::now().to_rfc3339();

    Ok(SnapshotRecord {
        id,
        platform_ci_key: platform_ci_key.to_string(),
        snapshot_purpose: snapshot_purpose.to_string(),
        requested_expiry: requested_expiry.to_string(),
        owner: owner.to_string(),
        support_group: support_group.to_string(),
        change_context: change_context.to_string(),
        status: SnapshotStatus::Draft,
        policy_decision: Some(
            "DRY-RUN: Snapshot governance policy reviewed — planned exception with approved expiry"
                .into(),
        ),
        backup_impact: Some(format!(
            "DRY-RUN: Backup impact reviewed for snapshot on {} (simulated, no Veeam calls)",
            platform_ci_key
        )),
        remediation_plan: Some(format!(
            "DRY-RUN: Remediation plan: snapshot will be deleted at expiry {} unless renewed by owner {}",
            requested_expiry, owner
        )),
        created_at: now.clone(),
        updated_at: now,
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    })
}

pub fn validate_snapshot(record: &SnapshotRecord) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if record.owner.is_empty() {
        errors.push("Missing owner".into());
        failed_rules.push("p0-owner-required".into());
        remediation.push("Assign an owner to the snapshot.".into());
    }

    if record.platform_ci_key.is_empty() {
        errors.push("Missing platform CI key".into());
        failed_rules.push("p0-ci-key-required".into());
        remediation.push("Provide a valid platform CI key.".into());
    }

    if record.requested_expiry.is_empty() {
        errors.push("Missing expiry date".into());
        failed_rules.push("p0-expiry-required".into());
        remediation.push("Provide an approved expiry date for the snapshot.".into());
    }

    warnings.push("DRY-RUN: Backup conflict check simulated".into());
    warnings.push("DRY-RUN: No live hypervisor snapshot operations performed".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn review_snapshot_policy(record: &SnapshotRecord) -> Result<SnapshotRecord, String> {
    let mut reviewed = record.clone();

    if record.status == SnapshotStatus::Expired || record.status == SnapshotStatus::Completed {
        return Err(format!(
            "Cannot review snapshot in status: {:?}",
            record.status
        ));
    }

    reviewed.status = SnapshotStatus::ReviewRequested;
    reviewed.updated_at = chrono::Utc::now().to_rfc3339();
    reviewed.policy_decision =
        Some("DRY-RUN: Policy review completed — snapshot approved with planned expiry".into());

    Ok(reviewed)
}

pub fn flag_stale_snapshots(records: &[SnapshotRecord]) -> Result<Vec<SnapshotRecord>, String> {
    let now = chrono::Utc::now();
    let mut flagged: Vec<SnapshotRecord> = Vec::new();

    for record in records {
        if record.status == SnapshotStatus::Expired || record.status == SnapshotStatus::Completed {
            continue;
        }
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&record.requested_expiry)
            && expiry < now
        {
            let mut stale = record.clone();
            stale.status = SnapshotStatus::StaleFlagged;
            stale.updated_at = now.to_rfc3339();
            stale.metadata.insert(
                "stale_reason".into(),
                format!("Snapshot expired at {}", record.requested_expiry),
            );
            flagged.push(stale);
        }
    }

    Ok(flagged)
}

pub fn plan_snapshot_remediation(record: &SnapshotRecord) -> Result<SnapshotRecord, String> {
    let mut remediated = record.clone();
    remediated.status = SnapshotStatus::RemediationPlanned;
    remediated.updated_at = chrono::Utc::now().to_rfc3339();
    remediated.remediation_plan = Some(format!(
        "DRY-RUN: Remediation plan for snapshot {} on {} — delete at next maintenance window (simulated)",
        remediated.id, remediated.platform_ci_key
    ));

    Ok(remediated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_snapshot() -> SnapshotRecord {
        plan_snapshot(
            "ci-vm-001",
            "Pre-patch safety snapshot",
            "2026-07-01T00:00:00Z",
            "app-team",
            "wintel-ops",
            "Patch wave June 2026",
        )
        .unwrap()
    }

    #[test]
    fn test_plan_snapshot_creates_record() {
        let record = make_test_snapshot();
        assert!(record.id.starts_with("snap-"));
        assert_eq!(record.status, SnapshotStatus::Draft);
        assert!(record.policy_decision.is_some());
        assert!(record.backup_impact.is_some());
    }

    #[test]
    fn test_plan_snapshot_empty_ci_key_fails() {
        assert!(plan_snapshot("", "purpose", "expiry", "owner", "sg", "ctx").is_err());
    }

    #[test]
    fn test_plan_snapshot_empty_owner_fails() {
        assert!(plan_snapshot("ci-001", "purpose", "expiry", "", "sg", "ctx").is_err());
    }

    #[test]
    fn test_validate_snapshot_passes() {
        let record = make_test_snapshot();
        let result = validate_snapshot(&record).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_snapshot_detects_missing_owner() {
        let mut record = make_test_snapshot();
        record.owner = "".into();
        let result = validate_snapshot(&record).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_review_snapshot_policy() {
        let record = make_test_snapshot();
        let reviewed = review_snapshot_policy(&record).unwrap();
        assert_eq!(reviewed.status, SnapshotStatus::ReviewRequested);
    }

    #[test]
    fn test_flag_stale_snapshots() {
        let mut record = make_test_snapshot();
        record.requested_expiry = "2020-01-01T00:00:00Z".into();
        record.status = SnapshotStatus::ReviewRequested;

        let flagged = flag_stale_snapshots(&[record]).unwrap();
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].status, SnapshotStatus::StaleFlagged);
    }

    #[test]
    fn test_flag_stale_skips_completed() {
        let mut record = make_test_snapshot();
        record.requested_expiry = "2020-01-01T00:00:00Z".into();
        record.status = SnapshotStatus::Completed;

        let flagged = flag_stale_snapshots(&[record]).unwrap();
        assert!(flagged.is_empty());
    }

    #[test]
    fn test_plan_snapshot_remediation() {
        let mut record = make_test_snapshot();
        record.status = SnapshotStatus::StaleFlagged;
        let remediated = plan_snapshot_remediation(&record).unwrap();
        assert_eq!(remediated.status, SnapshotStatus::RemediationPlanned);
        assert!(remediated.remediation_plan.is_some());
    }
}
