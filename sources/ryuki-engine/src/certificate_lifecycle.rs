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

/// Upper bound on a certificate's requested validity (100 years). An UNBOUNDED
/// `validity_days` flows into `now + Duration::days(validity_days)`, which PANICS
/// on `DateTime` overflow — so the value MUST be capped at the validation boundary
/// (a panic on attacker-chosen in-range u32 input is a DoS; see
/// `validate_certificate_request` / `renew_certificate`).
pub const MAX_CERTIFICATE_VALIDITY_DAYS: u32 = 36_500;

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
    // Bounded BELOW and ABOVE: 0 is meaningless and an unbounded value overflows
    // the `now + Duration::days(...)` below into a panic (DoS).
    if !(1..=MAX_CERTIFICATE_VALIDITY_DAYS).contains(&req.validity_days) {
        return Err(format!(
            "validity_days must be between 1 and {MAX_CERTIFICATE_VALIDITY_DAYS}"
        ));
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
    // Same bound as request (see MAX_CERTIFICATE_VALIDITY_DAYS): an unbounded
    // value overflows the `now + Duration::days(...)` below into a panic.
    if !(1..=MAX_CERTIFICATE_VALIDITY_DAYS).contains(&validity_days) {
        return Err(format!(
            "validity_days must be between 1 and {MAX_CERTIFICATE_VALIDITY_DAYS}"
        ));
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

// ---------------------------------------------------------------------------
// Certificate expiry classification (durable-scheduler scan)
// ---------------------------------------------------------------------------

/// How close a certificate is to (or past) its `valid_to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateExpiry {
    /// `valid_to` is in the past — an outage NOW.
    Expired,
    /// Within the soon-window of `valid_to` — renew before it lapses.
    ExpiringSoon,
    /// Not yet within the window — not actionable.
    Valid,
}

impl CertificateExpiry {
    /// Only `Expired` / `ExpiringSoon` become queue work. Used as the post-SQL
    /// clock-skew guard (the scan re-checks with the CP clock).
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            CertificateExpiry::Expired | CertificateExpiry::ExpiringSoon
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateExpiry::Expired => "expired",
            CertificateExpiry::ExpiringSoon => "expiring-soon",
            CertificateExpiry::Valid => "valid",
        }
    }
}

/// Pure: classify a certificate by its `valid_to` relative to `now` and a
/// `soon_window`. Mirrors `legal_hold::classify_legal_hold_expiry` exactly
/// (inclusive boundaries: `now == valid_to` is Expired).
pub fn classify_certificate_expiry(
    valid_to_unix_ms: i64,
    now_unix_ms: i64,
    soon_window_ms: i64,
) -> CertificateExpiry {
    if now_unix_ms >= valid_to_unix_ms {
        CertificateExpiry::Expired
    } else if valid_to_unix_ms <= now_unix_ms.saturating_add(soon_window_ms) {
        CertificateExpiry::ExpiringSoon
    } else {
        CertificateExpiry::Valid
    }
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
    fn classify_certificate_expiry_boundaries() {
        const DAY_MS: i64 = 86_400_000;
        let now = 1_000_000_000_000_i64;
        let soon = 30 * DAY_MS;
        // Past valid_to → Expired (actionable).
        let exp = classify_certificate_expiry(now - DAY_MS, now, soon);
        assert_eq!(exp, CertificateExpiry::Expired);
        assert!(exp.is_actionable());
        assert_eq!(exp.as_str(), "expired");
        // Exactly now → Expired (inclusive >=).
        assert_eq!(
            classify_certificate_expiry(now, now, soon),
            CertificateExpiry::Expired
        );
        // Within the soon window → ExpiringSoon (actionable).
        let soon_v = classify_certificate_expiry(now + 10 * DAY_MS, now, soon);
        assert_eq!(soon_v, CertificateExpiry::ExpiringSoon);
        assert!(soon_v.is_actionable());
        assert_eq!(soon_v.as_str(), "expiring-soon");
        // Far future → Valid (non-actionable; the scan skips it).
        let valid = classify_certificate_expiry(now + 60 * DAY_MS, now, soon);
        assert_eq!(valid, CertificateExpiry::Valid);
        assert!(!valid.is_actionable());
        assert_eq!(valid.as_str(), "valid");
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
    fn validity_days_is_bounded_above_no_overflow_panic() {
        // An unbounded validity_days overflows `now + Duration::days(...)` into a
        // panic (a DoS reachable by an execute-tier caller). The validation now
        // caps it, so request_certificate/renew_certificate return Err — NOT panic.
        for bad in [MAX_CERTIFICATE_VALIDITY_DAYS + 1, 100_000_000, u32::MAX] {
            let mut req = valid_request();
            req.validity_days = bad;
            assert!(
                validate_certificate_request(&req).is_err(),
                "validity_days {bad} must be rejected"
            );
            // The handler entry point returns Err rather than panicking.
            assert!(
                request_certificate(&req).is_err(),
                "request_certificate({bad}) must not panic"
            );
            assert!(
                renew_certificate(&active_cert(), bad).is_err(),
                "renew_certificate({bad}) must not panic"
            );
        }
        // The boundary (exactly MAX) is accepted and does NOT overflow.
        let mut ok = valid_request();
        ok.validity_days = MAX_CERTIFICATE_VALIDITY_DAYS;
        assert!(request_certificate(&ok).is_ok(), "MAX validity is accepted");
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
