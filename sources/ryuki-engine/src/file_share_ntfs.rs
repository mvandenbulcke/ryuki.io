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
            status: ShareStatus::Compliant,
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

/// Return a new `FileShare` with `last_recertification = now`, `recertification_due =
/// now + 365 days`, and `status = Compliant`. Returns `Err` if `share_id` is not found.
pub fn recertify_share(
    shares: &[FileShare],
    share_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<FileShare, String> {
    let share = shares
        .iter()
        .find(|s| s.id == share_id)
        .ok_or_else(|| format!("Share {share_id} not found"))?;
    Ok(FileShare {
        last_recertification: now.to_rfc3339(),
        recertification_due: (now + chrono::Duration::days(365)).to_rfc3339(),
        status: ShareStatus::Compliant,
        ..share.clone()
    })
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
    fn test_recertify_share_updates_status() {
        let (shares, _) = make_store();
        let now = chrono::Utc::now();
        let due = check_recertification_due(&shares, "", now);
        assert!(!due.is_empty());
        let share = due
            .iter()
            .find(|s| s.status == ShareStatus::Overdue)
            .unwrap();
        let result = recertify_share(&shares, &share.id, now);
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.status, ShareStatus::Compliant);
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

    #[test]
    fn test_recertify_share_not_found() {
        let (shares, _) = make_store();
        let now = chrono::Utc::now();
        assert!(recertify_share(&shares, "nonexistent", now).is_err());
    }
}
