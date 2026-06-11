use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertificateStatus {
    Active,
    Expiring,
    Expired,
    Revoked,
}

impl std::fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateStatus::Active => write!(f, "Active"),
            CertificateStatus::Expiring => write!(f, "Expiring"),
            CertificateStatus::Expired => write!(f, "Expired"),
            CertificateStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub id: String,
    pub common_name: String,
    pub subject: String,
    pub valid_from: String,
    pub valid_to: String,
    pub service_type: String,
    pub hostname: String,
    pub site: String,
    pub status: CertificateStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub common_name: String,
    pub subject: String,
    pub service_type: String,
    pub hostname: String,
    pub site: String,
    pub validity_days: u32,
}

fn seed_certificates() -> Vec<CertificateRecord> {
    let now = chrono::Utc::now();
    vec![
        CertificateRecord {
            id: Uuid::new_v4().to_string(),
            common_name: "*.corp.local".into(),
            subject: "CN=*.corp.local".into(),
            valid_from: (now - chrono::Duration::days(30)).to_rfc3339(),
            valid_to: (now + chrono::Duration::days(60)).to_rfc3339(),
            service_type: "IIS".into(),
            hostname: "web01.corp.local".into(),
            site: "GBLON".into(),
            status: CertificateStatus::Expiring,
            created_at: now.to_rfc3339(),
        },
        CertificateRecord {
            id: Uuid::new_v4().to_string(),
            common_name: "vcenter.corp.local".into(),
            subject: "CN=vcenter.corp.local".into(),
            valid_from: (now - chrono::Duration::days(180)).to_rfc3339(),
            valid_to: (now + chrono::Duration::days(185)).to_rfc3339(),
            service_type: "VMware".into(),
            hostname: "vcenter.corp.local".into(),
            site: "GBLON".into(),
            status: CertificateStatus::Active,
            created_at: now.to_rfc3339(),
        },
        CertificateRecord {
            id: Uuid::new_v4().to_string(),
            common_name: "esxi01.corp.local".into(),
            subject: "CN=esxi01.corp.local".into(),
            valid_from: (now - chrono::Duration::days(400)).to_rfc3339(),
            valid_to: (now - chrono::Duration::days(30)).to_rfc3339(),
            service_type: "ESXi".into(),
            hostname: "esxi01.corp.local".into(),
            site: "FRPAR".into(),
            status: CertificateStatus::Expired,
            created_at: now.to_rfc3339(),
        },
    ]
}

static CERTIFICATE_STORE: std::sync::LazyLock<Mutex<Vec<CertificateRecord>>> =
    std::sync::LazyLock::new(|| Mutex::new(seed_certificates()));

pub fn request_certificate(req: &CertificateRequest) -> Result<CertificateRecord, String> {
    validate_certificate_request(req)?;

    let now = chrono::Utc::now();
    let record = CertificateRecord {
        id: Uuid::new_v4().to_string(),
        common_name: req.common_name.clone(),
        subject: req.subject.clone(),
        valid_from: now.to_rfc3339(),
        valid_to: (now + chrono::Duration::days(req.validity_days as i64)).to_rfc3339(),
        service_type: req.service_type.clone(),
        hostname: req.hostname.clone(),
        site: req.site.clone(),
        status: CertificateStatus::Active,
        created_at: now.to_rfc3339(),
    };

    CERTIFICATE_STORE.lock().unwrap().push(record.clone());
    Ok(record)
}

pub fn validate_certificate_request(req: &CertificateRequest) -> Result<(), String> {
    if req.common_name.is_empty() {
        return Err("common_name cannot be empty".into());
    }
    if req.subject.is_empty() {
        return Err("subject cannot be empty".into());
    }
    if req.service_type.is_empty() {
        return Err("service_type cannot be empty".into());
    }
    if req.hostname.is_empty() {
        return Err("hostname cannot be empty".into());
    }
    if req.site.is_empty() {
        return Err("site cannot be empty".into());
    }
    if req.validity_days == 0 {
        return Err("validity_days must be greater than 0".into());
    }
    Ok(())
}

pub fn approve_certificate(id: &str) -> Result<CertificateRecord, String> {
    let mut store = CERTIFICATE_STORE.lock().unwrap();
    let cert = store
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| format!("Certificate {id} not found"))?;
    Ok(cert.clone())
}

pub fn install_certificate(id: &str) -> Result<CertificateRecord, String> {
    let store = CERTIFICATE_STORE.lock().unwrap();
    let cert = store
        .iter()
        .find(|c| c.id == id)
        .cloned()
        .ok_or_else(|| format!("Certificate {id} not found"))?;
    Ok(cert)
}

pub fn verify_certificate(id: &str) -> Result<CertificateRecord, String> {
    let store = CERTIFICATE_STORE.lock().unwrap();
    let cert = store
        .iter()
        .find(|c| c.id == id)
        .cloned()
        .ok_or_else(|| format!("Certificate {id} not found"))?;
    Ok(cert)
}

pub fn check_expiry(site: &str, days: i64) -> Vec<CertificateRecord> {
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(days);
    let store = CERTIFICATE_STORE.lock().unwrap();
    store
        .iter()
        .filter(|c| {
            if !site.is_empty() && c.site != site {
                return false;
            }
            if let Ok(valid_to) = chrono::DateTime::parse_from_rfc3339(&c.valid_to) {
                let valid_to_utc = valid_to.with_timezone(&chrono::Utc);
                valid_to_utc <= threshold
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn renew_certificate(id: &str, validity_days: u32) -> Result<CertificateRecord, String> {
    if validity_days == 0 {
        return Err("validity_days must be greater than 0".into());
    }
    let mut store = CERTIFICATE_STORE.lock().unwrap();
    let cert = store
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| format!("Certificate {id} not found"))?;

    let now = chrono::Utc::now();
    cert.valid_from = now.to_rfc3339();
    cert.valid_to = (now + chrono::Duration::days(validity_days as i64)).to_rfc3339();
    cert.status = CertificateStatus::Active;
    cert.created_at = now.to_rfc3339();

    Ok(cert.clone())
}

pub fn revoke_certificate(id: &str) -> Result<CertificateRecord, String> {
    let mut store = CERTIFICATE_STORE.lock().unwrap();
    let cert = store
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| format!("Certificate {id} not found"))?;
    cert.status = CertificateStatus::Revoked;
    Ok(cert.clone())
}

pub fn get_inventory() -> Vec<CertificateRecord> {
    CERTIFICATE_STORE.lock().unwrap().clone()
}

pub fn get_certificate(id: &str) -> Option<CertificateRecord> {
    CERTIFICATE_STORE
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.id == id)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    static CERTIFICATE_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn fresh_certificate_store() -> MutexGuard<'static, ()> {
        let guard = CERTIFICATE_TEST_LOCK.lock().unwrap();
        *CERTIFICATE_STORE.lock().unwrap() = seed_certificates();
        guard
    }

    fn valid_request() -> CertificateRequest {
        CertificateRequest {
            common_name: "test.local".into(),
            subject: "CN=test.local".into(),
            service_type: "IIS".into(),
            hostname: "web02.corp.local".into(),
            site: "GBLON".into(),
            validity_days: 365,
        }
    }

    #[test]
    fn test_validate_certificate_request_succeeds() {
        let req = valid_request();
        assert!(validate_certificate_request(&req).is_ok());
    }

    #[test]
    fn test_validate_certificate_request_empty_common_name() {
        let mut req = valid_request();
        req.common_name = "".into();
        assert!(validate_certificate_request(&req).is_err());
    }

    #[test]
    fn test_validate_certificate_request_empty_site() {
        let mut req = valid_request();
        req.site = "".into();
        assert!(validate_certificate_request(&req).is_err());
    }

    #[test]
    fn test_validate_certificate_request_zero_validity() {
        let mut req = valid_request();
        req.validity_days = 0;
        assert!(validate_certificate_request(&req).is_err());
    }

    #[test]
    fn test_request_certificate_creates_record() {
        let _guard = fresh_certificate_store();
        let req = valid_request();
        let result = request_certificate(&req);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.common_name, "test.local");
        assert_eq!(record.status, CertificateStatus::Active);
        assert_eq!(record.site, "GBLON");
    }

    #[test]
    fn test_get_inventory_returns_seeded_certs() {
        let _guard = fresh_certificate_store();
        let inventory = get_inventory();
        assert!(inventory.len() >= 3);
        let names: Vec<&str> = inventory.iter().map(|c| c.common_name.as_str()).collect();
        assert!(names.contains(&"*.corp.local"));
        assert!(names.contains(&"vcenter.corp.local"));
        assert!(names.contains(&"esxi01.corp.local"));
    }

    #[test]
    fn test_check_expiry_finds_expiring() {
        let _guard = fresh_certificate_store();
        let results = check_expiry("GBLON", 90);
        assert!(!results.is_empty());
        let expiring: Vec<&CertificateRecord> = results
            .iter()
            .filter(|c| c.status == CertificateStatus::Expiring)
            .collect();
        assert!(!expiring.is_empty());
    }

    #[test]
    fn test_check_expiry_empty_site_returns_all() {
        let _guard = fresh_certificate_store();
        let results = check_expiry("", 365);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_renew_certificate_updates_dates() {
        let _guard = fresh_certificate_store();
        let inventory = get_inventory();
        let cert = inventory.first().unwrap();
        let result = renew_certificate(&cert.id, 180);
        assert!(result.is_ok());
        let renewed = result.unwrap();
        assert_eq!(renewed.status, CertificateStatus::Active);
    }

    #[test]
    fn test_revoke_certificate_sets_status() {
        let _guard = fresh_certificate_store();
        let inventory = get_inventory();
        let cert = inventory.first().unwrap();
        let result = revoke_certificate(&cert.id);
        assert!(result.is_ok());
        let revoked = result.unwrap();
        assert_eq!(revoked.status, CertificateStatus::Revoked);
    }

    #[test]
    fn test_get_certificate_not_found() {
        assert!(get_certificate("nonexistent-id").is_none());
    }

    #[test]
    fn test_get_certificate_found() {
        let _guard = fresh_certificate_store();
        let inventory = get_inventory();
        let cert = inventory.first().unwrap();
        let found = get_certificate(&cert.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().common_name, cert.common_name);
    }
}
