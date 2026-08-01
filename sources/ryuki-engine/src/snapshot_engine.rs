use crate::models::*;
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Maximum encoded size accepted for a caller-supplied snapshot expiry.
/// RFC3339 timestamps are short; this leaves ample room for fractional seconds
/// and an explicit offset while preventing the expiry field from becoming an
/// attacker-controlled unbounded text value.
pub const MAX_REQUESTED_EXPIRY_BYTES: usize = 64;

fn has_strict_rfc3339_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=MAX_REQUESTED_EXPIRY_BYTES).contains(&bytes.len())
        || !value.is_ascii()
        || bytes.starts_with(b"0000")
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }

    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }

    let zone_start = if bytes[19] == b'.' {
        let Some(relative_end) = bytes[20..].iter().position(|byte| !byte.is_ascii_digit()) else {
            return false;
        };
        if relative_end == 0 {
            return false;
        }
        20 + relative_end
    } else {
        19
    };

    let zone = &bytes[zone_start..];
    zone == b"Z"
        || (zone.len() == 6
            && matches!(zone[0], b'+' | b'-')
            && zone[1].is_ascii_digit()
            && zone[2].is_ascii_digit()
            && zone[3] == b':'
            && zone[4].is_ascii_digit()
            && zone[5].is_ascii_digit())
}

/// Validate and normalize a caller-controlled expiry at the domain boundary.
/// The returned UTC value is within the four-digit RFC3339 year range and can
/// therefore be represented safely by PostgreSQL `TIMESTAMPTZ`.
pub fn canonicalize_requested_expiry(value: &str) -> Result<(String, DateTime<Utc>), String> {
    if value.is_empty() {
        return Err("requested_expiry cannot be empty".into());
    }
    if value.len() > MAX_REQUESTED_EXPIRY_BYTES {
        return Err(format!(
            "requested_expiry must be at most {MAX_REQUESTED_EXPIRY_BYTES} bytes"
        ));
    }
    if !has_strict_rfc3339_shape(value) {
        return Err("requested_expiry must be a canonical RFC3339 timestamp".into());
    }

    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| "requested_expiry must be a canonical RFC3339 timestamp".to_string())?
        .with_timezone(&Utc);
    if !(1..=9999).contains(&parsed.year()) {
        return Err("requested_expiry is outside the supported timestamp range".into());
    }

    Ok((parsed.to_rfc3339_opts(SecondsFormat::AutoSi, true), parsed))
}

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
    let (requested_expiry, _) = canonicalize_requested_expiry(requested_expiry)?;

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
        configuration_item_id: None,
        platform_ci_key: platform_ci_key.to_string(),
        site: None,
        environment: None,
        created_by: None,
        scope_provenance: None,
        snapshot_purpose: snapshot_purpose.to_string(),
        requested_expiry: requested_expiry.clone(),
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
    } else if canonicalize_requested_expiry(&record.requested_expiry).is_err() {
        errors.push("Invalid expiry date".into());
        failed_rules.push("p0-expiry-rfc3339".into());
        remediation.push(format!(
            "Provide a canonical RFC3339 expiry no longer than {MAX_REQUESTED_EXPIRY_BYTES} bytes."
        ));
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

    // Ordinary policy review is a single forward transition. Re-reviewing an
    // already reviewed, approved, stale, remediating, or terminal record would
    // silently regress lifecycle state to ReviewRequested. Any future re-review
    // requires a separately authorized transition with its own audit contract.
    if record.status != SnapshotStatus::Draft {
        return Err(format!(
            "Cannot review snapshot in status {:?}; review requires Draft",
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
        // Only live, not-yet-actioned states are eligible to be flagged stale.
        // Excluding StaleFlagged (already flagged), RemediationPlanned (already
        // being remediated), and the terminal Expired/Completed/Failed prevents
        // a flag -> remediate -> re-flag loop and never re-opens terminal rows.
        let eligible = matches!(
            record.status,
            SnapshotStatus::Draft
                | SnapshotStatus::ReviewRequested
                | SnapshotStatus::ExpiryApproved
        );
        if !eligible {
            continue;
        }
        if let Ok((_, expiry)) = canonicalize_requested_expiry(&record.requested_expiry)
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
    // Remediation only applies to a snapshot that has been flagged stale.
    // Without this guard a fresh Draft or a terminal (Completed/Expired/Failed)
    // snapshot could be moved into RemediationPlanned, corrupting the lifecycle.
    if record.status != SnapshotStatus::StaleFlagged {
        return Err(format!(
            "Cannot plan remediation for snapshot in status {:?}. Must be StaleFlagged first.",
            record.status
        ));
    }

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
    fn test_plan_snapshot_rejects_non_rfc3339_and_relaxed_timestamps() {
        for invalid in [
            "not-a-timestamp",
            "infinity",
            "2026-07-01 00:00:00Z",
            "2026-07-01T00:00:00z",
            "0000-01-01T00:00:00Z",
        ] {
            let error = plan_snapshot("ci-001", "purpose", invalid, "owner", "sg", "ctx")
                .expect_err("non-canonical expiry must be rejected");
            assert!(
                error.contains("RFC3339") || error.contains("timestamp range"),
                "unexpected error for {invalid}: {error}"
            );
        }
    }

    #[test]
    fn test_plan_snapshot_enforces_exact_64_byte_expiry_boundary() {
        let maximum = format!("2026-07-01T00:00:00.{}Z", "1".repeat(43));
        assert_eq!(maximum.len(), MAX_REQUESTED_EXPIRY_BYTES);
        assert!(plan_snapshot("ci-001", "purpose", &maximum, "owner", "sg", "ctx").is_ok());

        let oversized = format!("2026-07-01T00:00:00.{}Z", "1".repeat(44));
        assert_eq!(oversized.len(), MAX_REQUESTED_EXPIRY_BYTES + 1);
        let error = plan_snapshot("ci-001", "purpose", &oversized, "owner", "sg", "ctx")
            .expect_err("oversized expiry must be rejected");
        assert!(error.contains("at most 64 bytes"));
    }

    #[test]
    fn test_plan_snapshot_canonicalizes_valid_offset_to_utc() {
        let record = plan_snapshot(
            "ci-001",
            "purpose",
            "2026-07-01T02:30:00+02:30",
            "owner",
            "sg",
            "ctx",
        )
        .expect("valid RFC3339 offset must be accepted");
        assert_eq!(record.requested_expiry, "2026-07-01T00:00:00Z");

        let fractional = plan_snapshot(
            "ci-001",
            "purpose",
            "2026-07-01T00:00:00.123456789123Z",
            "owner",
            "sg",
            "ctx",
        )
        .expect("bounded RFC3339 fractional seconds must be accepted");
        assert_eq!(
            fractional.requested_expiry,
            "2026-07-01T00:00:00.123456789Z"
        );
        assert!(canonicalize_requested_expiry("9999-12-31T23:59:59Z").is_ok());
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
    fn test_validate_snapshot_detects_invalid_expiry() {
        let mut record = make_test_snapshot();
        record.requested_expiry = "2026-07-01 00:00:00Z".into();
        let result = validate_snapshot(&record).unwrap();
        assert!(!result.passed);
        assert_eq!(result.failed_rules, vec!["p0-expiry-rfc3339".to_string()]);
    }

    #[test]
    fn test_review_snapshot_policy() {
        let record = make_test_snapshot();
        let reviewed = review_snapshot_policy(&record).unwrap();
        assert_eq!(reviewed.status, SnapshotStatus::ReviewRequested);
    }

    #[test]
    fn test_review_snapshot_policy_rejects_every_non_draft_state() {
        // The explicit transition table contains only Draft -> ReviewRequested.
        // No reviewed, stale, remediating, or terminal record may be re-opened.
        for status in [
            SnapshotStatus::ReviewRequested,
            SnapshotStatus::ExpiryApproved,
            SnapshotStatus::StaleFlagged,
            SnapshotStatus::RemediationPlanned,
            SnapshotStatus::Expired,
            SnapshotStatus::Completed,
            SnapshotStatus::Failed,
        ] {
            let mut record = make_test_snapshot();
            record.status = status;
            assert!(
                review_snapshot_policy(&record).is_err(),
                "review must be refused from non-Draft status {:?}",
                record.status
            );
        }
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

    #[test]
    fn test_plan_snapshot_remediation_rejects_non_stale() {
        // Remediation must require StaleFlagged — a fresh Draft is rejected.
        let record = make_test_snapshot();
        assert_eq!(record.status, SnapshotStatus::Draft);
        assert!(plan_snapshot_remediation(&record).is_err());

        // Terminal states are rejected too.
        for status in [
            SnapshotStatus::Completed,
            SnapshotStatus::Expired,
            SnapshotStatus::Failed,
            SnapshotStatus::RemediationPlanned,
        ] {
            let mut r = make_test_snapshot();
            r.status = status.clone();
            assert!(
                plan_snapshot_remediation(&r).is_err(),
                "remediation must reject status {:?}",
                status
            );
        }
    }

    #[test]
    fn test_flag_stale_skips_remediation_planned_and_failed() {
        // Past-expiry records in non-eligible states must NOT be re-flagged,
        // which would otherwise cause a flag -> remediate -> re-flag loop or
        // re-open terminal rows.
        for status in [
            SnapshotStatus::RemediationPlanned,
            SnapshotStatus::Failed,
            SnapshotStatus::StaleFlagged,
        ] {
            let mut record = make_test_snapshot();
            record.requested_expiry = "2020-01-01T00:00:00Z".into();
            record.status = status.clone();
            let flagged = flag_stale_snapshots(&[record]).unwrap();
            assert!(
                flagged.is_empty(),
                "status {:?} must not be flagged stale",
                status
            );
        }
    }
}
