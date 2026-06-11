use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GMSAStatus {
    Active,
    Expiring,
    Expired,
    Revoked,
}

impl std::fmt::Display for GMSAStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GMSAStatus::Active => write!(f, "Active"),
            GMSAStatus::Expiring => write!(f, "Expiring"),
            GMSAStatus::Expired => write!(f, "Expired"),
            GMSAStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GMSAAccount {
    pub id: String,
    pub name: String,
    pub sam_account_name: String,
    pub dns_host_name: String,
    pub service_principal_names: Vec<String>,
    pub authorized_hosts: Vec<String>,
    pub site: String,
    pub status: GMSAStatus,
    pub managed_password_interval_days: u32,
    pub created_at: String,
    pub last_rotation_at: String,
}

fn seed_gmsa_accounts() -> Vec<GMSAAccount> {
    let now = chrono::Utc::now();
    vec![
        GMSAAccount {
            id: Uuid::new_v4().to_string(),
            name: "svc-webappool-bur1".into(),
            sam_account_name: "svc-webappool-bur1$".into(),
            dns_host_name: "svc-webappool-bur1.corp.local".into(),
            service_principal_names: vec![
                "HTTP/webapp01.corp.local".into(),
                "HTTP/webapp02.corp.local".into(),
            ],
            authorized_hosts: vec!["webapp01.corp.local".into(), "webapp02.corp.local".into()],
            site: "BUR1".into(),
            status: GMSAStatus::Active,
            managed_password_interval_days: 30,
            created_at: now.to_rfc3339(),
            last_rotation_at: (now - chrono::Duration::days(15)).to_rfc3339(),
        },
        GMSAAccount {
            id: Uuid::new_v4().to_string(),
            name: "svc-sqlagent-love".into(),
            sam_account_name: "svc-sqlagent-love$".into(),
            dns_host_name: "svc-sqlagent-love.corp.local".into(),
            service_principal_names: vec!["MSSQLSvc/sql01.corp.local:1433".into()],
            authorized_hosts: vec!["sql01.corp.local".into()],
            site: "LOVE".into(),
            status: GMSAStatus::Expiring,
            managed_password_interval_days: 60,
            created_at: (now - chrono::Duration::days(180)).to_rfc3339(),
            last_rotation_at: (now - chrono::Duration::days(55)).to_rfc3339(),
        },
        GMSAAccount {
            id: Uuid::new_v4().to_string(),
            name: "svc-iisworker-albi".into(),
            sam_account_name: "svc-iisworker-albi$".into(),
            dns_host_name: "svc-iisworker-albi.corp.local".into(),
            service_principal_names: vec!["HTTP/iis-albi.corp.local".into()],
            authorized_hosts: vec!["iis-albi.corp.local".into()],
            site: "ALBI".into(),
            status: GMSAStatus::Expired,
            managed_password_interval_days: 30,
            created_at: (now - chrono::Duration::days(400)).to_rfc3339(),
            last_rotation_at: (now - chrono::Duration::days(35)).to_rfc3339(),
        },
    ]
}

static GMSA_STORE: std::sync::LazyLock<Mutex<Vec<GMSAAccount>>> =
    std::sync::LazyLock::new(|| Mutex::new(seed_gmsa_accounts()));

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn create_gmsa(
    name: &str,
    hosts: Vec<String>,
    spns: Vec<String>,
    site: &str,
) -> Result<GMSAAccount, String> {
    if name.is_empty() {
        return Err("gMSA name cannot be empty".into());
    }
    if !name.starts_with("svc-") {
        return Err("gMSA name must start with 'svc-'".into());
    }
    if hosts.is_empty() {
        return Err("At least one authorized host is required".into());
    }
    if site.is_empty() {
        return Err("Site cannot be empty".into());
    }
    if spns.is_empty() {
        return Err("At least one SPN is required".into());
    }

    let account = GMSAAccount {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        sam_account_name: format!("{name}$"),
        dns_host_name: format!("{name}.corp.local"),
        service_principal_names: spns,
        authorized_hosts: hosts,
        site: site.to_string(),
        status: GMSAStatus::Active,
        managed_password_interval_days: 30,
        created_at: now_iso(),
        last_rotation_at: now_iso(),
    };

    GMSA_STORE.lock().unwrap().push(account.clone());
    Ok(account)
}

pub fn validate_gmsa(name: &str) -> Result<crate::models::ValidationResult, String> {
    if name.is_empty() {
        return Err("gMSA name cannot be empty".into());
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if !name.starts_with("svc-") {
        errors.push("gMSA name must start with 'svc-'".into());
        failed_rules.push("gmsa-naming-convention".into());
        remediation.push("Rename the gMSA to start with 'svc-' (e.g. svc-webappool-bur1)".into());
    }

    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() < 2 {
        errors.push(
            "gMSA name must have at least service and site parts (e.g. svc-webappool-bur1)".into(),
        );
        failed_rules.push("gmsa-name-structure".into());
        remediation.push("Use format svc-PURPOSE-SITE".into());
    }

    let store = GMSA_STORE.lock().unwrap();
    let existing = store.iter().find(|a| a.name == name);
    if let Some(account) = existing {
        if account.service_principal_names.is_empty() {
            errors.push("gMSA has no SPNs configured".into());
            failed_rules.push("gmsa-spn-required".into());
            remediation.push("Configure at least one valid SPN".into());
        }
        if account.authorized_hosts.is_empty() {
            errors.push("gMSA has no authorized hosts".into());
            failed_rules.push("gmsa-host-membership".into());
            remediation.push("Assign at least one host as authorized retrieval principal".into());
        }
    }

    warnings.push("DRY-RUN: No live AD gMSA validation performed".into());
    warnings.push("DRY-RUN: KDS root key readiness not verified".into());

    Ok(crate::models::ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn assign_to_host(gmsa_name: &str, host: &str) -> Result<GMSAAccount, String> {
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    let mut store = GMSA_STORE.lock().unwrap();
    let account = store
        .iter_mut()
        .find(|a| a.name == gmsa_name)
        .ok_or_else(|| format!("gMSA {gmsa_name} not found"))?;

    if account.status == GMSAStatus::Revoked {
        return Err(format!("Cannot assign hosts to revoked gMSA {gmsa_name}"));
    }

    if !account.authorized_hosts.contains(&host.to_string()) {
        account.authorized_hosts.push(host.to_string());
    }

    Ok(account.clone())
}

pub fn remove_from_host(gmsa_name: &str, host: &str) -> Result<GMSAAccount, String> {
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    let mut store = GMSA_STORE.lock().unwrap();
    let account = store
        .iter_mut()
        .find(|a| a.name == gmsa_name)
        .ok_or_else(|| format!("gMSA {gmsa_name} not found"))?;

    let before = account.authorized_hosts.len();
    account.authorized_hosts.retain(|h| h != host);

    if account.authorized_hosts.len() == before {
        return Err(format!(
            "Host {host} is not in the authorized list for {gmsa_name}"
        ));
    }

    if account.authorized_hosts.is_empty() {
        return Err(format!(
            "Cannot remove last host from {gmsa_name}. At least one authorized host required."
        ));
    }

    Ok(account.clone())
}

pub fn rotate_password(gmsa_name: &str) -> Result<GMSAAccount, String> {
    let mut store = GMSA_STORE.lock().unwrap();
    let account = store
        .iter_mut()
        .find(|a| a.name == gmsa_name)
        .ok_or_else(|| format!("gMSA {gmsa_name} not found"))?;

    if account.status == GMSAStatus::Revoked {
        return Err(format!(
            "Cannot rotate password for revoked gMSA {gmsa_name}"
        ));
    }

    account.last_rotation_at = now_iso();
    account.status = GMSAStatus::Active;

    Ok(account.clone())
}

pub fn test_retrieval(gmsa_name: &str, host: &str) -> Result<GMSAAccount, String> {
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    let store = GMSA_STORE.lock().unwrap();
    let account = store
        .iter()
        .find(|a| a.name == gmsa_name)
        .ok_or_else(|| format!("gMSA {gmsa_name} not found"))?;

    if account.status == GMSAStatus::Revoked {
        return Err(format!(
            "Cannot test retrieval for revoked gMSA {gmsa_name}"
        ));
    }

    if !account.authorized_hosts.contains(&host.to_string()) {
        return Err(format!(
            "Host {host} is not authorized to retrieve password for {gmsa_name}"
        ));
    }

    Ok(account.clone())
}

pub fn get_gmsa_inventory(site: &str) -> Vec<GMSAAccount> {
    let store = GMSA_STORE.lock().unwrap();
    if site.is_empty() {
        store.clone()
    } else {
        store.iter().filter(|a| a.site == site).cloned().collect()
    }
}

pub fn get_expiring() -> Vec<GMSAAccount> {
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(7);
    let store = GMSA_STORE.lock().unwrap();
    store
        .iter()
        .filter(|a| {
            if a.status == GMSAStatus::Expiring || a.status == GMSAStatus::Expired {
                return true;
            }
            if let Ok(last_rotation) = chrono::DateTime::parse_from_rfc3339(&a.last_rotation_at) {
                let rotation = last_rotation.with_timezone(&chrono::Utc);
                let next_rotation =
                    rotation + chrono::Duration::days(a.managed_password_interval_days as i64);
                next_rotation <= threshold
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn get_gmsa(name: &str) -> Option<GMSAAccount> {
    GMSA_STORE
        .lock()
        .unwrap()
        .iter()
        .find(|a| a.name == name)
        .cloned()
}

pub fn seed_examples() -> Vec<GMSAAccount> {
    GMSA_STORE.lock().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_gmsa_succeeds() {
        let account = create_gmsa(
            "svc-testapp-bur1",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "BUR1",
        );
        assert!(account.is_ok());
        let record = account.unwrap();
        assert_eq!(record.name, "svc-testapp-bur1");
        assert_eq!(record.sam_account_name, "svc-testapp-bur1$");
        assert_eq!(record.dns_host_name, "svc-testapp-bur1.corp.local");
        assert_eq!(record.status, GMSAStatus::Active);
        assert_eq!(record.site, "BUR1");
        assert_eq!(record.authorized_hosts.len(), 1);
    }

    #[test]
    fn test_create_gmsa_invalid_name() {
        let result = create_gmsa(
            "bad-name",
            vec!["host.corp.local".into()],
            vec!["HTTP/host.corp.local".into()],
            "BUR1",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_gmsa_empty_hosts() {
        let result = create_gmsa(
            "svc-testapp-bur1",
            vec![],
            vec!["HTTP/host.corp.local".into()],
            "BUR1",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_gmsa_valid() {
        let result = validate_gmsa("svc-webappool-bur1").unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_gmsa_invalid_prefix() {
        let result = validate_gmsa("bad-webappool-bur1").unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("svc-")));
    }

    #[test]
    fn test_assign_to_host_succeeds() {
        let result = assign_to_host("svc-webappool-bur1", "new-host.corp.local");
        assert!(result.is_ok());
        let account = result.unwrap();
        assert!(
            account
                .authorized_hosts
                .contains(&"new-host.corp.local".to_string())
        );
    }

    #[test]
    fn test_assign_to_host_revoked_fails() {
        let mut store = GMSA_STORE.lock().unwrap();
        if let Some(account) = store.iter_mut().find(|a| a.name == "svc-webappool-bur1") {
            account.status = GMSAStatus::Revoked;
        }
        drop(store);

        let result = assign_to_host("svc-webappool-bur1", "new-host.corp.local");
        assert!(result.is_err());

        let mut store = GMSA_STORE.lock().unwrap();
        if let Some(account) = store.iter_mut().find(|a| a.name == "svc-webappool-bur1") {
            account.status = GMSAStatus::Active;
        }
    }

    #[test]
    fn test_remove_from_host_succeeds() {
        let result = remove_from_host("svc-webappool-bur1", "webapp01.corp.local");
        assert!(result.is_ok());
        let account = result.unwrap();
        assert!(
            !account
                .authorized_hosts
                .contains(&"webapp01.corp.local".to_string())
        );

        let _ = assign_to_host("svc-webappool-bur1", "webapp01.corp.local");
    }

    #[test]
    fn test_rotate_password_succeeds() {
        let result = rotate_password("svc-webappool-bur1");
        assert!(result.is_ok());
        let account = result.unwrap();
        assert_eq!(account.status, GMSAStatus::Active);
    }

    #[test]
    fn test_test_retrieval_succeeds() {
        let result = test_retrieval("svc-webappool-bur1", "webapp01.corp.local");
        assert!(result.is_ok());
    }

    #[test]
    fn test_test_retrieval_unauthorized_host() {
        let result = test_retrieval("svc-webappool-bur1", "evil-host.corp.local");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_gmsa_inventory_seeded() {
        let inventory = get_gmsa_inventory("");
        assert!(inventory.len() >= 3);
        let names: Vec<&str> = inventory.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"svc-webappool-bur1"));
        assert!(names.contains(&"svc-sqlagent-love"));
        assert!(names.contains(&"svc-iisworker-albi"));
    }

    #[test]
    fn test_get_gmsa_inventory_by_site() {
        let bur1 = get_gmsa_inventory("BUR1");
        assert!(!bur1.is_empty());
        assert!(bur1.iter().all(|a| a.site == "BUR1"));

        let love = get_gmsa_inventory("LOVE");
        assert!(!love.is_empty());
        assert!(love.iter().all(|a| a.site == "LOVE"));
    }

    #[test]
    fn test_get_expiring_finds_expiring() {
        let results = get_expiring();
        let has_expiring = results
            .iter()
            .any(|a| a.status == GMSAStatus::Expiring || a.status == GMSAStatus::Expired);
        assert!(has_expiring);
    }

    #[test]
    fn test_get_gmsa_not_found() {
        assert!(get_gmsa("nonexistent-gmsa").is_none());
    }

    #[test]
    fn test_get_gmsa_found() {
        let found = get_gmsa("svc-webappool-bur1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "svc-webappool-bur1");
    }

    #[test]
    fn test_seed_examples() {
        let examples = seed_examples();
        assert!(examples.len() >= 3);
    }

    #[test]
    fn test_gmsa_status_display() {
        assert_eq!(GMSAStatus::Active.to_string(), "Active");
        assert_eq!(GMSAStatus::Expiring.to_string(), "Expiring");
        assert_eq!(GMSAStatus::Expired.to_string(), "Expired");
        assert_eq!(GMSAStatus::Revoked.to_string(), "Revoked");
    }
}
