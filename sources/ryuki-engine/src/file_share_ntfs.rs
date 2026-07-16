use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShareStatus {
    Compliant,
    Overdue,
    NeedsRecertification,
}

impl std::fmt::Display for ShareStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareStatus::Compliant => write!(f, "Compliant"),
            ShareStatus::Overdue => write!(f, "Overdue"),
            ShareStatus::NeedsRecertification => write!(f, "NeedsRecertification"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionType {
    Read,
    Write,
    Modify,
    FullControl,
}

impl std::fmt::Display for PermissionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionType::Read => write!(f, "Read"),
            PermissionType::Write => write!(f, "Write"),
            PermissionType::Modify => write!(f, "Modify"),
            PermissionType::FullControl => write!(f, "FullControl"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileShare {
    pub id: String,
    pub unc_path: String,
    pub server_name: String,
    pub site: String,
    pub size_gb: f64,
    pub owner: String,
    pub last_recertification: String,
    pub recertification_due: String,
    pub status: ShareStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NTFSFolder {
    pub id: String,
    pub file_share_id: String,
    pub folder_path: String,
    pub permission_type: PermissionType,
    pub ad_group: String,
    pub principal: String,
    pub inherited: bool,
    pub last_reviewed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareDetail {
    pub share: FileShare,
    pub permissions: Vec<NTFSFolder>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionReport {
    pub folder_path: String,
    pub ad_group: String,
    pub permission_type: PermissionType,
    pub risk_level: String,
}

/// Provenance of an immutable recertification evidence snapshot.
///
/// `StaticFixture` is useful for deterministic development and contract tests,
/// but it is deliberately incapable of proving live compliance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecertificationEvidenceSource {
    AuthoritativeProviderSnapshot,
    StaticFixture,
}

impl std::fmt::Display for RecertificationEvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthoritativeProviderSnapshot => write!(f, "AuthoritativeProviderSnapshot"),
            Self::StaticFixture => write!(f, "StaticFixture"),
        }
    }
}

/// The exact server-owned share snapshot against which evidence is evaluated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecertificationSubject {
    pub share_id: String,
    pub share_version: i64,
    pub site: String,
    pub owner: String,
}

/// Immutable evidence metadata supplied by a trusted collector, never by the
/// public recertification request body. Raw ACL/provider payloads are not kept
/// in this control-plane projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecertificationEvidence {
    pub evidence_id: String,
    pub share_id: String,
    pub share_version: i64,
    pub site: String,
    pub source: RecertificationEvidenceSource,
    pub collector_principal: Option<String>,
    pub collector_attestation_ref: Option<String>,
    pub acl_snapshot_version: Option<String>,
    pub acl_snapshot_digest: Option<String>,
    pub observed_at: Option<String>,
    pub valid_until: Option<String>,
    pub owner_attested: bool,
    pub owner_attested_by: Option<String>,
    pub reviewer: Option<String>,
    pub approver: Option<String>,
    pub group_access_reviewed: bool,
    pub ntfs_acl_reviewed: bool,
    pub share_permissions_reviewed: bool,
    pub stale_access_reviewed: bool,
    pub unresolved_findings: Option<i32>,
    pub owner_evidence_ref: Option<String>,
    pub acl_evidence_ref: Option<String>,
    pub reviewer_evidence_ref: Option<String>,
    pub evidence_manifest_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecertificationDecisionStatus {
    Compliant,
    Indeterminate,
}

impl std::fmt::Display for RecertificationDecisionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::Indeterminate => write!(f, "Indeterminate"),
        }
    }
}

/// Pure policy result. The API persists this result together with the evidence
/// id, authenticated reviewer, exact subject version, and evaluation time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecertificationEvaluation {
    pub status: RecertificationDecisionStatus,
    pub reason: String,
    pub recertification_due: Option<String>,
}

/// Durable, idempotently replayable decision returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecertificationDecision {
    pub decision_id: String,
    pub evidence_id: String,
    pub share_id: String,
    pub share_version: i64,
    pub site: String,
    pub reviewer: String,
    pub reviewed_at: String,
    pub evidence_source: RecertificationEvidenceSource,
    pub acl_snapshot_version: Option<String>,
    pub acl_snapshot_digest: Option<String>,
    pub evidence_manifest_ref: Option<String>,
    pub status: RecertificationDecisionStatus,
    pub reason: String,
    pub recertification_due: Option<String>,
}

// ─── Seed helpers (used by the *-contract endpoint and db_tests fixtures) ─────

pub fn seed_shares() -> Vec<FileShare> {
    let now = chrono::Utc::now();
    let future = now + chrono::Duration::days(180);
    let past_due = now - chrono::Duration::days(30);
    let long_past = now - chrono::Duration::days(400);
    vec![
        FileShare {
            id: Uuid::new_v4().to_string(),
            unc_path: "\\\\fs01\\Finance".into(),
            server_name: "fs01.corp.local".into(),
            site: "DEFRA".into(),
            size_gb: 512.0,
            owner: "alice.williams".into(),
            last_recertification: (now - chrono::Duration::days(200)).to_rfc3339(),
            recertification_due: future.to_rfc3339(),
            // Static seed state is illustrative only. Without an immutable
            // authoritative evidence decision it must not claim compliance.
            status: ShareStatus::NeedsRecertification,
        },
        FileShare {
            id: Uuid::new_v4().to_string(),
            unc_path: "\\\\fs02\\Engineering".into(),
            server_name: "fs02.corp.local".into(),
            site: "GBLON".into(),
            size_gb: 1024.0,
            owner: "bob.johnson".into(),
            last_recertification: long_past.to_rfc3339(),
            recertification_due: past_due.to_rfc3339(),
            status: ShareStatus::Overdue,
        },
        FileShare {
            id: Uuid::new_v4().to_string(),
            unc_path: "\\\\fs03\\HR".into(),
            server_name: "fs03.corp.local".into(),
            site: "DEFRA".into(),
            size_gb: 256.0,
            owner: "carol.smith".into(),
            last_recertification: (now - chrono::Duration::days(400)).to_rfc3339(),
            recertification_due: (now - chrono::Duration::days(5)).to_rfc3339(),
            status: ShareStatus::NeedsRecertification,
        },
    ]
}

pub fn seed_permissions(shares: &[FileShare]) -> Vec<NTFSFolder> {
    let now = chrono::Utc::now().to_rfc3339();
    vec![
        NTFSFolder {
            id: Uuid::new_v4().to_string(),
            file_share_id: shares[0].id.clone(),
            folder_path: "\\Finance\\Reports".into(),
            permission_type: PermissionType::Modify,
            ad_group: "GG-Finance-RW".into(),
            principal: "GG-Finance-RW@corp.local".into(),
            inherited: false,
            last_reviewed: now.clone(),
        },
        NTFSFolder {
            id: Uuid::new_v4().to_string(),
            file_share_id: shares[0].id.clone(),
            folder_path: "\\Finance\\Payroll".into(),
            permission_type: PermissionType::FullControl,
            ad_group: "GG-Finance-Admins".into(),
            principal: "GG-Finance-Admins@corp.local".into(),
            inherited: false,
            last_reviewed: now.clone(),
        },
        NTFSFolder {
            id: Uuid::new_v4().to_string(),
            file_share_id: shares[0].id.clone(),
            folder_path: "\\Finance\\Public".into(),
            permission_type: PermissionType::Read,
            ad_group: "Everyone".into(),
            principal: "Everyone".into(),
            inherited: true,
            last_reviewed: now.clone(),
        },
        NTFSFolder {
            id: Uuid::new_v4().to_string(),
            file_share_id: shares[1].id.clone(),
            folder_path: "\\Engineering\\Source".into(),
            permission_type: PermissionType::Modify,
            ad_group: "GG-Engineering-Dev".into(),
            principal: "GG-Engineering-Dev@corp.local".into(),
            inherited: false,
            last_reviewed: (chrono::Utc::now() - chrono::Duration::days(400)).to_rfc3339(),
        },
        NTFSFolder {
            id: Uuid::new_v4().to_string(),
            file_share_id: shares[1].id.clone(),
            folder_path: "\\Engineering\\Design".into(),
            permission_type: PermissionType::FullControl,
            ad_group: "Domain Users".into(),
            principal: "Domain Users@corp.local".into(),
            inherited: true,
            last_reviewed: (chrono::Utc::now() - chrono::Duration::days(400)).to_rfc3339(),
        },
        NTFSFolder {
            id: Uuid::new_v4().to_string(),
            file_share_id: shares[2].id.clone(),
            folder_path: "\\HR\\EmployeeRecords".into(),
            permission_type: PermissionType::Read,
            ad_group: "GG-HR-Staff".into(),
            principal: "GG-HR-Staff@corp.local".into(),
            inherited: false,
            last_reviewed: now,
        },
    ]
}

// ─── Pure engine functions ────────────────────────────────────────────────────

/// Filter shares by site. Empty `site` returns all.
pub fn get_shares<'a>(shares: &'a [FileShare], site: &str) -> Vec<&'a FileShare> {
    if site.is_empty() {
        shares.iter().collect()
    } else {
        shares.iter().filter(|s| s.site == site).collect()
    }
}

/// Return the detail for a share plus all its NTFS permissions.
/// Returns `None` if the share is not found.
pub fn get_share_detail<'a>(
    shares: &'a [FileShare],
    permissions: &'a [NTFSFolder],
    share_id: &str,
) -> Option<ShareDetail> {
    let share = shares.iter().find(|s| s.id == share_id)?.clone();
    let perms: Vec<NTFSFolder> = permissions
        .iter()
        .filter(|p| p.file_share_id == share_id)
        .cloned()
        .collect();
    Some(ShareDetail {
        share,
        permissions: perms,
    })
}

/// Return shares whose `recertification_due` is at or before `now`.
pub fn check_recertification_due<'a>(
    shares: &'a [FileShare],
    site: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<&'a FileShare> {
    shares
        .iter()
        .filter(|s| {
            if !site.is_empty() && s.site != site {
                return false;
            }
            chrono::DateTime::parse_from_rfc3339(&s.recertification_due)
                .map(|due| due.with_timezone(&chrono::Utc) <= now)
                .unwrap_or(false)
        })
        .collect()
}

/// Evaluate a recertification evidence snapshot without fabricating missing
/// facts. Every failure is `Indeterminate`; only a fresh, complete,
/// authoritative snapshot bound to the exact share version and authenticated
/// reviewer can produce `Compliant`.
pub fn evaluate_share_recertification(
    subject: &RecertificationSubject,
    evidence: Option<&RecertificationEvidence>,
    authenticated_reviewer: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> RecertificationEvaluation {
    fn indeterminate(reason: &str) -> RecertificationEvaluation {
        RecertificationEvaluation {
            status: RecertificationDecisionStatus::Indeterminate,
            reason: reason.to_string(),
            recertification_due: None,
        }
    }

    fn nonempty_bounded(value: Option<&str>, max_len: usize) -> Option<&str> {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= max_len)
    }

    let normalized_reviewer = authenticated_reviewer.trim();
    if normalized_reviewer.is_empty() {
        return indeterminate("authenticated-reviewer-missing");
    }
    if normalized_reviewer != authenticated_reviewer {
        return indeterminate("authenticated-reviewer-invalid");
    }
    let authenticated_reviewer = normalized_reviewer;
    let Some(evidence) = evidence else {
        return indeterminate("recertification-evidence-missing");
    };
    if evidence.share_id != subject.share_id {
        return indeterminate("evidence-share-mismatch");
    }
    if evidence.site != subject.site {
        return indeterminate("evidence-scope-mismatch");
    }
    if evidence.share_version != subject.share_version {
        return indeterminate("evidence-share-version-stale");
    }
    if evidence.source != RecertificationEvidenceSource::AuthoritativeProviderSnapshot {
        return indeterminate("static-fixture-is-not-live-compliance-evidence");
    }
    if nonempty_bounded(evidence.collector_principal.as_deref(), 256).is_none()
        || nonempty_bounded(evidence.collector_attestation_ref.as_deref(), 512).is_none()
    {
        return indeterminate("trusted-collector-attestation-missing");
    }

    let Some(_acl_snapshot_version) =
        nonempty_bounded(evidence.acl_snapshot_version.as_deref(), 256)
    else {
        return indeterminate("acl-snapshot-version-missing-or-invalid");
    };
    let Some(acl_snapshot_digest) = evidence.acl_snapshot_digest.as_deref() else {
        return indeterminate("acl-snapshot-digest-missing-or-invalid");
    };
    if acl_snapshot_digest.len() != 64
        || !acl_snapshot_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return indeterminate("acl-snapshot-digest-missing-or-invalid");
    }

    let (Some(observed_at), Some(valid_until)) = (
        evidence
            .observed_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc)),
        evidence
            .valid_until
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc)),
    ) else {
        return indeterminate("evidence-time-missing-or-invalid");
    };
    if observed_at > now || valid_until <= observed_at {
        return indeterminate("evidence-time-window-invalid");
    }
    if now.signed_duration_since(observed_at) > chrono::Duration::hours(24) || valid_until <= now {
        return indeterminate("recertification-evidence-stale");
    }

    let Some(manifest_ref) = evidence
        .evidence_manifest_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return indeterminate("evidence-manifest-missing");
    };
    if manifest_ref.len() > 512 {
        return indeterminate("evidence-manifest-reference-invalid");
    }
    if nonempty_bounded(evidence.owner_evidence_ref.as_deref(), 512).is_none() {
        return indeterminate("owner-evidence-reference-missing");
    }
    if nonempty_bounded(evidence.acl_evidence_ref.as_deref(), 512).is_none() {
        return indeterminate("acl-evidence-reference-missing");
    }
    if nonempty_bounded(evidence.reviewer_evidence_ref.as_deref(), 512).is_none() {
        return indeterminate("reviewer-evidence-reference-missing");
    }

    let Some(owner_attested_by) = evidence
        .owner_attested_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return indeterminate("owner-attestation-missing");
    };
    if !evidence.owner_attested {
        return indeterminate("owner-attestation-incomplete");
    }
    if owner_attested_by != subject.owner {
        return indeterminate("owner-attestor-mismatch");
    }

    let Some(evidence_reviewer) = evidence
        .reviewer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return indeterminate("evidence-reviewer-missing");
    };
    if evidence_reviewer != authenticated_reviewer {
        return indeterminate("evidence-reviewer-mismatch");
    }
    let Some(approver) = evidence
        .approver
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return indeterminate("recertification-approval-missing");
    };
    if approver == authenticated_reviewer || approver == owner_attested_by {
        return indeterminate("recertification-maker-checker-not-separated");
    }

    if !evidence.group_access_reviewed
        || !evidence.ntfs_acl_reviewed
        || !evidence.share_permissions_reviewed
        || !evidence.stale_access_reviewed
    {
        return indeterminate("recertification-evidence-incomplete");
    }
    match evidence.unresolved_findings {
        None => return indeterminate("unresolved-findings-evidence-missing"),
        Some(count) if count < 0 => return indeterminate("unresolved-findings-invalid"),
        Some(count) if count > 0 => return indeterminate("unresolved-findings-remain"),
        Some(_) => {}
    }

    RecertificationEvaluation {
        status: RecertificationDecisionStatus::Compliant,
        reason: "authoritative-evidence-accepted".to_string(),
        recertification_due: Some((now + chrono::Duration::days(365)).to_rfc3339()),
    }
}

/// Return NTFS permissions for a share that grant FullControl to Everyone or Domain Users.
pub fn detect_open_access<'a>(
    permissions: &'a [NTFSFolder],
    share_id: &str,
) -> Vec<&'a NTFSFolder> {
    permissions
        .iter()
        .filter(|p| {
            p.file_share_id == share_id
                && p.permission_type == PermissionType::FullControl
                && (p.ad_group == "Everyone" || p.ad_group == "Domain Users")
        })
        .collect()
}

/// Return shares where `last_recertification` is older than 365 days before `now`.
pub fn get_owner_stale<'a>(
    shares: &'a [FileShare],
    site: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<&'a FileShare> {
    let threshold = now - chrono::Duration::days(365);
    shares
        .iter()
        .filter(|s| {
            if !site.is_empty() && s.site != site {
                return false;
            }
            chrono::DateTime::parse_from_rfc3339(&s.last_recertification)
                .map(|last| last.with_timezone(&chrono::Utc) < threshold)
                .unwrap_or(false)
        })
        .collect()
}

/// Build a permission risk report for a share's NTFS folders.
/// Returns `Err` if `share_id` is not found in `shares`.
pub fn get_permission_report(
    shares: &[FileShare],
    permissions: &[NTFSFolder],
    share_id: &str,
) -> Result<Vec<PermissionReport>, String> {
    if !shares.iter().any(|s| s.id == share_id) {
        return Err(format!("Share {share_id} not found"));
    }
    let report: Vec<PermissionReport> = permissions
        .iter()
        .filter(|p| p.file_share_id == share_id)
        .map(|p| {
            let risk_level = if p.ad_group == "Everyone" || p.ad_group == "Domain Users" {
                if p.permission_type == PermissionType::FullControl {
                    "Critical".into()
                } else {
                    "High".into()
                }
            } else if p.permission_type == PermissionType::FullControl && !p.inherited {
                "Medium".into()
            } else {
                "Low".into()
            };
            PermissionReport {
                folder_path: p.folder_path.clone(),
                ad_group: p.ad_group.clone(),
                permission_type: p.permission_type.clone(),
                risk_level,
            }
        })
        .collect();
    Ok(report)
}

/// Return a new permissions list with the entry for `(file_share_id, ad_group)` removed.
/// Returns `Err` if no matching entry exists.
pub fn revoke_permission(
    permissions: &[NTFSFolder],
    share_id: &str,
    ad_group: &str,
) -> Result<Vec<NTFSFolder>, String> {
    let pos = permissions
        .iter()
        .position(|p| p.file_share_id == share_id && p.ad_group == ad_group)
        .ok_or_else(|| format!("Permission not found for share {share_id} and group {ad_group}"))?;
    let mut updated = permissions.to_vec();
    updated.remove(pos);
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> (Vec<FileShare>, Vec<NTFSFolder>) {
        let shares = seed_shares();
        let perms = seed_permissions(&shares);
        (shares, perms)
    }

    fn recertification_subject() -> RecertificationSubject {
        RecertificationSubject {
            share_id: "share-1".to_string(),
            share_version: 7,
            site: "DEFRA".to_string(),
            owner: "share.owner".to_string(),
        }
    }

    fn authoritative_evidence(now: chrono::DateTime<chrono::Utc>) -> RecertificationEvidence {
        RecertificationEvidence {
            evidence_id: "evidence-1".to_string(),
            share_id: "share-1".to_string(),
            share_version: 7,
            site: "DEFRA".to_string(),
            source: RecertificationEvidenceSource::AuthoritativeProviderSnapshot,
            collector_principal: Some("workload:file-share-evidence".to_string()),
            collector_attestation_ref: Some("evidence://collector/attestation-1".to_string()),
            acl_snapshot_version: Some("provider-acl-version-42".to_string()),
            acl_snapshot_digest: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            observed_at: Some((now - chrono::Duration::minutes(5)).to_rfc3339()),
            valid_until: Some((now + chrono::Duration::hours(1)).to_rfc3339()),
            owner_attested: true,
            owner_attested_by: Some("share.owner".to_string()),
            reviewer: Some("acl.reviewer".to_string()),
            approver: Some("governance.approver".to_string()),
            group_access_reviewed: true,
            ntfs_acl_reviewed: true,
            share_permissions_reviewed: true,
            stale_access_reviewed: true,
            unresolved_findings: Some(0),
            owner_evidence_ref: Some("evidence://owner/attestation-1".to_string()),
            acl_evidence_ref: Some("evidence://acl/snapshot-1".to_string()),
            reviewer_evidence_ref: Some("evidence://review/reviewer-1".to_string()),
            evidence_manifest_ref: Some("evidence://file-share/manifest-1".to_string()),
        }
    }

    #[test]
    fn test_get_shares_returns_all_for_empty_site() {
        let (shares, _) = make_store();
        let result = get_shares(&shares, "");
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_get_shares_filters_by_site() {
        let (shares, _) = make_store();
        let result = get_shares(&shares, "DEFRA");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|s| s.site == "DEFRA"));
    }

    #[test]
    fn test_get_share_detail_includes_permissions() {
        let (shares, perms) = make_store();
        let detail = get_share_detail(&shares, &perms, &shares[0].id);
        assert!(detail.is_some());
        let d = detail.unwrap();
        assert_eq!(d.share.id, shares[0].id);
        assert!(!d.permissions.is_empty());
    }

    #[test]
    fn test_check_recertification_due_finds_overdue() {
        let (shares, _) = make_store();
        let now = chrono::Utc::now();
        let due = check_recertification_due(&shares, "", now);
        assert!(!due.is_empty());
        let non_compliant: Vec<_> = due
            .iter()
            .filter(|s| s.status != ShareStatus::Compliant)
            .collect();
        assert!(!non_compliant.is_empty());
    }

    #[test]
    fn test_recertification_requires_evidence() {
        let now = chrono::Utc::now();
        let result =
            evaluate_share_recertification(&recertification_subject(), None, "acl.reviewer", now);
        assert_eq!(result.status, RecertificationDecisionStatus::Indeterminate);
        assert_eq!(result.reason, "recertification-evidence-missing");
        assert!(result.recertification_due.is_none());
    }

    #[test]
    fn test_recertification_rejects_partial_evidence() {
        let now = chrono::Utc::now();
        for missing_guard in 0..7 {
            let mut evidence = authoritative_evidence(now);
            match missing_guard {
                0 => evidence.group_access_reviewed = false,
                1 => evidence.ntfs_acl_reviewed = false,
                2 => evidence.share_permissions_reviewed = false,
                3 => evidence.stale_access_reviewed = false,
                4 => evidence.owner_evidence_ref = None,
                5 => evidence.acl_evidence_ref = None,
                6 => evidence.reviewer_evidence_ref = None,
                _ => unreachable!(),
            }
            let result = evaluate_share_recertification(
                &recertification_subject(),
                Some(&evidence),
                "acl.reviewer",
                now,
            );
            assert_eq!(result.status, RecertificationDecisionStatus::Indeterminate);
            assert_ne!(result.reason, "authoritative-evidence-accepted");
        }
    }

    #[test]
    fn test_recertification_rejects_stale_evidence() {
        let now = chrono::Utc::now();
        let mut evidence = authoritative_evidence(now);
        evidence.observed_at = Some((now - chrono::Duration::hours(25)).to_rfc3339());
        evidence.valid_until = Some((now + chrono::Duration::hours(1)).to_rfc3339());
        let result = evaluate_share_recertification(
            &recertification_subject(),
            Some(&evidence),
            "acl.reviewer",
            now,
        );
        assert_eq!(result.status, RecertificationDecisionStatus::Indeterminate);
        assert_eq!(result.reason, "recertification-evidence-stale");
    }

    #[test]
    fn test_recertification_rejects_missing_acl_snapshot_binding() {
        let now = chrono::Utc::now();
        let mut evidence = authoritative_evidence(now);
        evidence.acl_snapshot_digest = Some("not-a-sha256-digest".to_string());
        let result = evaluate_share_recertification(
            &recertification_subject(),
            Some(&evidence),
            "acl.reviewer",
            now,
        );
        assert_eq!(result.status, RecertificationDecisionStatus::Indeterminate);
        assert_eq!(result.reason, "acl-snapshot-digest-missing-or-invalid");
    }

    #[test]
    fn test_recertification_keeps_unresolved_findings_indeterminate() {
        let now = chrono::Utc::now();
        let mut evidence = authoritative_evidence(now);
        evidence.unresolved_findings = Some(1);
        let result = evaluate_share_recertification(
            &recertification_subject(),
            Some(&evidence),
            "acl.reviewer",
            now,
        );
        assert_eq!(result.status, RecertificationDecisionStatus::Indeterminate);
        assert_eq!(result.reason, "unresolved-findings-remain");
    }

    #[test]
    fn test_recertification_rejects_foreign_or_stale_snapshot_bindings() {
        let now = chrono::Utc::now();
        let subject = recertification_subject();

        let mut foreign_share = authoritative_evidence(now);
        foreign_share.share_id = "share-2".to_string();
        assert_eq!(
            evaluate_share_recertification(&subject, Some(&foreign_share), "acl.reviewer", now,)
                .reason,
            "evidence-share-mismatch"
        );

        let mut foreign_scope = authoritative_evidence(now);
        foreign_scope.site = "GBLON".to_string();
        assert_eq!(
            evaluate_share_recertification(&subject, Some(&foreign_scope), "acl.reviewer", now,)
                .reason,
            "evidence-scope-mismatch"
        );

        let mut stale_version = authoritative_evidence(now);
        stale_version.share_version -= 1;
        assert_eq!(
            evaluate_share_recertification(&subject, Some(&stale_version), "acl.reviewer", now,)
                .reason,
            "evidence-share-version-stale"
        );
    }

    #[test]
    fn test_recertification_rejects_unbound_reviewer_and_maker_checker_reuse() {
        let now = chrono::Utc::now();
        let subject = recertification_subject();
        let evidence = authoritative_evidence(now);
        assert_eq!(
            evaluate_share_recertification(&subject, Some(&evidence), "foreign.reviewer", now,)
                .reason,
            "evidence-reviewer-mismatch"
        );

        let mut reused = authoritative_evidence(now);
        reused.approver = Some("acl.reviewer".to_string());
        assert_eq!(
            evaluate_share_recertification(&subject, Some(&reused), "acl.reviewer", now,).reason,
            "recertification-maker-checker-not-separated"
        );
    }

    #[test]
    fn test_static_fixture_never_claims_live_compliance() {
        let now = chrono::Utc::now();
        let mut evidence = authoritative_evidence(now);
        evidence.source = RecertificationEvidenceSource::StaticFixture;
        let result = evaluate_share_recertification(
            &recertification_subject(),
            Some(&evidence),
            "acl.reviewer",
            now,
        );
        assert_eq!(result.status, RecertificationDecisionStatus::Indeterminate);
        assert_eq!(
            result.reason,
            "static-fixture-is-not-live-compliance-evidence"
        );
    }

    #[test]
    fn test_complete_authoritative_evidence_is_compliant() {
        let now = chrono::Utc::now();
        let result = evaluate_share_recertification(
            &recertification_subject(),
            Some(&authoritative_evidence(now)),
            "acl.reviewer",
            now,
        );
        assert_eq!(result.status, RecertificationDecisionStatus::Compliant);
        assert_eq!(result.reason, "authoritative-evidence-accepted");
        assert!(result.recertification_due.is_some());
    }

    #[test]
    fn test_detect_open_access_finds_everyone_fullcontrol() {
        let (shares, perms) = make_store();
        let eng = shares.iter().find(|s| s.site == "GBLON").unwrap();
        let open = detect_open_access(&perms, &eng.id);
        assert!(!open.is_empty());
        assert_eq!(open[0].ad_group, "Domain Users");
        assert_eq!(open[0].permission_type, PermissionType::FullControl);
    }

    #[test]
    fn test_get_owner_stale_detects_old_recertifications() {
        let (shares, _) = make_store();
        let now = chrono::Utc::now();
        let stale = get_owner_stale(&shares, "", now);
        assert!(!stale.is_empty());
    }

    #[test]
    fn test_get_permission_report_risk_critical() {
        let (shares, perms) = make_store();
        let eng = shares.iter().find(|s| s.site == "GBLON").unwrap();
        let report = get_permission_report(&shares, &perms, &eng.id);
        assert!(report.is_ok());
        let r = report.unwrap();
        let criticals: Vec<_> = r.iter().filter(|p| p.risk_level == "Critical").collect();
        assert!(!criticals.is_empty());
    }

    #[test]
    fn test_revoke_permission_removes_entry() {
        let (shares, perms) = make_store();
        let defra = shares
            .iter()
            .find(|s| s.unc_path.contains("Finance"))
            .unwrap();
        let result = revoke_permission(&perms, &defra.id, "Everyone");
        assert!(result.is_ok());
        let updated_perms = result.unwrap();
        let everyone_left = updated_perms.iter().any(|p| p.ad_group == "Everyone");
        assert!(!everyone_left);
    }

    #[test]
    fn test_get_permission_report_share_not_found() {
        let (shares, perms) = make_store();
        assert!(get_permission_report(&shares, &perms, "nonexistent").is_err());
    }
}
