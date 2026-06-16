use serde::{Deserialize, Serialize};
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

/// Validate the fields of a certificate request. Pure; no I/O.
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

/// Build a new `CertificateRecord` from a validated request. Pure; no I/O.
/// The caller (handler) inserts the returned record into the DB.
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

    Ok(record)
}

/// Produce a renewed copy of an existing certificate. Pure; no I/O.
/// The caller loads the record from the DB, passes it here, then persists the
/// returned record via a CAS transition.
pub fn renew_certificate(
    cert: &CertificateRecord,
    validity_days: u32,
) -> Result<CertificateRecord, String> {
    if validity_days == 0 {
        return Err("validity_days must be greater than 0".into());
    }
    if cert.status == CertificateStatus::Revoked {
        return Err("Cannot renew a revoked certificate".into());
    }

    let now = chrono::Utc::now();
    let mut renewed = cert.clone();
    renewed.valid_from = now.to_rfc3339();
    renewed.valid_to = (now + chrono::Duration::days(validity_days as i64)).to_rfc3339();
    renewed.status = CertificateStatus::Active;
    // created_at is immutable — it records when the certificate record was first
    // created, not when it was last renewed.

    Ok(renewed)
}

/// Produce a revoked copy of an existing certificate. Pure; no I/O.
/// The caller loads the record from the DB, passes it here, then persists the
/// returned record via a CAS transition.
pub fn revoke_certificate(cert: &CertificateRecord) -> Result<CertificateRecord, String> {
    if cert.status == CertificateStatus::Revoked {
        return Err("Certificate is already revoked".into());
    }

    let mut revoked = cert.clone();
    revoked.status = CertificateStatus::Revoked;

    Ok(revoked)
}

/// Return all certificates from `certs` that expire within `days` days for the
/// given `site` (empty string = all sites). Pure; no I/O.
pub fn check_expiry(certs: &[CertificateRecord], site: &str, days: i64) -> Vec<CertificateRecord> {
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(days);
    certs
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

#[cfg(test)]
mod tests {
    use super::*;

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

    fn active_cert() -> CertificateRecord {
        let now = chrono::Utc::now();
        CertificateRecord {
            id: Uuid::new_v4().to_string(),
            common_name: "test.local".into(),
            subject: "CN=test.local".into(),
            valid_from: now.to_rfc3339(),
            valid_to: (now + chrono::Duration::days(90)).to_rfc3339(),
            service_type: "IIS".into(),
            hostname: "web02.corp.local".into(),
            site: "GBLON".into(),
            status: CertificateStatus::Active,
            created_at: now.to_rfc3339(),
        }
    }

    fn revoked_cert() -> CertificateRecord {
        CertificateRecord {
            status: CertificateStatus::Revoked,
            ..active_cert()
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
        let req = valid_request();
        let result = request_certificate(&req);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.common_name, "test.local");
        assert_eq!(record.status, CertificateStatus::Active);
        assert_eq!(record.site, "GBLON");
    }

    #[test]
    fn test_check_expiry_finds_expiring() {
        let now = chrono::Utc::now();
        let expiring = CertificateRecord {
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
        };
        let not_expiring = CertificateRecord {
            id: Uuid::new_v4().to_string(),
            valid_to: (now + chrono::Duration::days(200)).to_rfc3339(),
            site: "GBLON".into(),
            ..expiring.clone()
        };
        let certs = vec![expiring.clone(), not_expiring];

        let results = check_expiry(&certs, "GBLON", 90);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, expiring.id);
    }

    #[test]
    fn test_check_expiry_empty_site_returns_matching() {
        let now = chrono::Utc::now();
        let cert_a = CertificateRecord {
            id: Uuid::new_v4().to_string(),
            common_name: "a.local".into(),
            subject: "CN=a.local".into(),
            valid_from: now.to_rfc3339(),
            valid_to: (now + chrono::Duration::days(30)).to_rfc3339(),
            service_type: "IIS".into(),
            hostname: "host-a".into(),
            site: "GBLON".into(),
            status: CertificateStatus::Expiring,
            created_at: now.to_rfc3339(),
        };
        let cert_b = CertificateRecord {
            id: Uuid::new_v4().to_string(),
            site: "FRPAR".into(),
            ..cert_a.clone()
        };
        let certs = vec![cert_a, cert_b];

        let results = check_expiry(&certs, "", 365);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_renew_certificate_updates_dates() {
        let cert = active_cert();
        let result = renew_certificate(&cert, 180);
        assert!(result.is_ok());
        let renewed = result.unwrap();
        assert_eq!(renewed.status, CertificateStatus::Active);
        assert_ne!(renewed.valid_to, cert.valid_to);
    }

    #[test]
    fn test_renew_certificate_rejects_zero_days() {
        let cert = active_cert();
        let result = renew_certificate(&cert, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_renew_rejects_revoked() {
        let cert = revoked_cert();
        let result = renew_certificate(&cert, 180);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("revoked"));
    }

    #[test]
    fn test_revoke_certificate_sets_status() {
        let cert = active_cert();
        let result = revoke_certificate(&cert);
        assert!(result.is_ok());
        let revoked = result.unwrap();
        assert_eq!(revoked.status, CertificateStatus::Revoked);
    }

    #[test]
    fn test_revoke_rejects_already_revoked() {
        let cert = revoked_cert();
        let result = revoke_certificate(&cert);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already revoked"));
    }
}
