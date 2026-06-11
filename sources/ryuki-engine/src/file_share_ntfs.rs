use serde::{Deserialize, Serialize};
use std::sync::Mutex;
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

fn seed_shares() -> Vec<FileShare> {
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

fn seed_permissions(shares: &[FileShare]) -> Vec<NTFSFolder> {
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

static SHARE_STORE: std::sync::LazyLock<Mutex<(Vec<FileShare>, Vec<NTFSFolder>)>> =
    std::sync::LazyLock::new(|| {
        let shares = seed_shares();
        let perms = seed_permissions(&shares);
        Mutex::new((shares, perms))
    });

pub fn get_shares(site: &str) -> Vec<FileShare> {
    let store = SHARE_STORE.lock().unwrap();
    if site.is_empty() {
        store.0.clone()
    } else {
        store
            .0
            .iter()
            .filter(|s| s.site == site)
            .cloned()
            .collect()
    }
}

pub fn get_share_detail(share_id: &str) -> Option<ShareDetail> {
    let store = SHARE_STORE.lock().unwrap();
    let share = store.0.iter().find(|s| s.id == share_id).cloned()?;
    let permissions: Vec<NTFSFolder> = store
        .1
        .iter()
        .filter(|p| p.file_share_id == share_id)
        .cloned()
        .collect();
    Some(ShareDetail {
        share,
        permissions,
    })
}

pub fn check_recertification_due(site: &str) -> Vec<FileShare> {
    let now = chrono::Utc::now();
    let store = SHARE_STORE.lock().unwrap();
    store
        .0
        .iter()
        .filter(|s| {
            if !site.is_empty() && s.site != site {
                return false;
            }
            if let Ok(due) = chrono::DateTime::parse_from_rfc3339(&s.recertification_due) {
                let due_utc = due.with_timezone(&chrono::Utc);
                due_utc <= now
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn recertify_share(share_id: &str, _reviewer: &str) -> Result<FileShare, String> {
    let mut store = SHARE_STORE.lock().unwrap();
    let share = store
        .0
        .iter_mut()
        .find(|s| s.id == share_id)
        .ok_or_else(|| format!("Share {share_id} not found"))?;
    let now = chrono::Utc::now();
    share.last_recertification = now.to_rfc3339();
    share.recertification_due = (now + chrono::Duration::days(365)).to_rfc3339();
    share.status = ShareStatus::Compliant;
    Ok(share.clone())
}

pub fn detect_open_access(share_id: &str) -> Vec<NTFSFolder> {
    let store = SHARE_STORE.lock().unwrap();
    store
        .1
        .iter()
        .filter(|p| {
            p.file_share_id == share_id
                && p.permission_type == PermissionType::FullControl
                && (p.ad_group == "Everyone" || p.ad_group == "Domain Users")
        })
        .cloned()
        .collect()
}

pub fn get_owner_stale(site: &str) -> Vec<FileShare> {
    let now = chrono::Utc::now();
    let threshold = now - chrono::Duration::days(365);
    let store = SHARE_STORE.lock().unwrap();
    store
        .0
        .iter()
        .filter(|s| {
            if !site.is_empty() && s.site != site {
                return false;
            }
            if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&s.last_recertification) {
                let last_utc = last.with_timezone(&chrono::Utc);
                last_utc < threshold
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn get_permission_report(share_id: &str) -> Result<Vec<PermissionReport>, String> {
    let store = SHARE_STORE.lock().unwrap();
    if !store.0.iter().any(|s| s.id == share_id) {
        return Err(format!("Share {share_id} not found"));
    }
    let report: Vec<PermissionReport> = store
        .1
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

pub fn revoke_permission(share_id: &str, ad_group: &str) -> Result<String, String> {
    let mut store = SHARE_STORE.lock().unwrap();
    let pos = store
        .1
        .iter()
        .position(|p| p.file_share_id == share_id && p.ad_group == ad_group)
        .ok_or_else(|| {
            format!("Permission not found for share {share_id} and group {ad_group}")
        })?;
    store.1.remove(pos);
    Ok(format!(
        "Revoked {ad_group} from share {share_id} (dry-run: no live AD changes)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_shares_returns_all_for_empty_site() {
        let shares = get_shares("");
        assert_eq!(shares.len(), 3);
    }

    #[test]
    fn test_get_shares_filters_by_site() {
        let shares = get_shares("DEFRA");
        assert_eq!(shares.len(), 2);
        assert!(shares.iter().all(|s| s.site == "DEFRA"));
    }

    #[test]
    fn test_get_share_detail_includes_permissions() {
        let all = get_shares("");
        let detail = get_share_detail(&all[0].id);
        assert!(detail.is_some());
        let d = detail.unwrap();
        assert_eq!(d.share.id, all[0].id);
        assert!(!d.permissions.is_empty());
    }

    #[test]
    fn test_check_recertification_due_finds_overdue() {
        let due = check_recertification_due("");
        // At least one share is past its recertification date
        assert!(!due.is_empty());
        let non_compliant: Vec<_> = due
            .iter()
            .filter(|s| s.status != ShareStatus::Compliant)
            .collect();
        assert!(!non_compliant.is_empty());
    }

    #[test]
    fn test_recertify_share_updates_status() {
        let due = check_recertification_due("");
        assert!(!due.is_empty());
        let share = due.iter().find(|s| s.status == ShareStatus::Overdue).unwrap();
        let result = recertify_share(&share.id, "auditor");
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.status, ShareStatus::Compliant);
    }

    #[test]
    fn test_detect_open_access_finds_everyone_fullcontrol() {
        let all = get_shares("");
        let eng = all.iter().find(|s| s.site == "GBLON").unwrap();
        let open = detect_open_access(&eng.id);
        assert!(!open.is_empty());
        assert_eq!(open[0].ad_group, "Domain Users");
        assert_eq!(open[0].permission_type, PermissionType::FullControl);
    }

    #[test]
    fn test_get_owner_stale_detects_old_recertifications() {
        let stale = get_owner_stale("");
        assert!(!stale.is_empty());
    }

    #[test]
    fn test_get_permission_report_risk_critical() {
        let all = get_shares("");
        let eng = all.iter().find(|s| s.site == "GBLON").unwrap();
        let report = get_permission_report(&eng.id);
        assert!(report.is_ok());
        let r = report.unwrap();
        let criticals: Vec<_> = r.iter().filter(|p| p.risk_level == "Critical").collect();
        assert!(!criticals.is_empty());
    }

    #[test]
    fn test_revoke_permission_removes_entry() {
        let all = get_shares("");
        let defra = all.iter().find(|s| s.unc_path.contains("Finance")).unwrap();
        let result = revoke_permission(&defra.id, "Everyone");
        assert!(result.is_ok());
        let detail = get_share_detail(&defra.id).unwrap();
        let everyone_left = detail
            .permissions
            .iter()
            .any(|p| p.ad_group == "Everyone");
        assert!(!everyone_left);
    }

    #[test]
    fn test_get_permission_report_share_not_found() {
        assert!(get_permission_report("nonexistent").is_err());
    }

    #[test]
    fn test_recertify_share_not_found() {
        assert!(recertify_share("nonexistent", "auditor").is_err());
    }
}
