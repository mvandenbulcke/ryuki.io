use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceType {
    Server,
    Switch,
    PDU,
    CRAC,
    Firewall,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Server => write!(f, "Server"),
            DeviceType::Switch => write!(f, "Switch"),
            DeviceType::PDU => write!(f, "PDU"),
            DeviceType::CRAC => write!(f, "CRAC"),
            DeviceType::Firewall => write!(f, "Firewall"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    EOL,
    Exception,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStatus::Compliant => write!(f, "Compliant"),
            ComplianceStatus::NonCompliant => write!(f, "NonCompliant"),
            ComplianceStatus::EOL => write!(f, "EOL"),
            ComplianceStatus::Exception => write!(f, "Exception"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareRecord {
    pub id: String,
    pub device_type: DeviceType,
    pub vendor: String,
    pub model: String,
    pub current_version: String,
    pub minimum_version: String,
    pub latest_version: String,
    pub eol_date: String,
    pub site: String,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareException {
    pub id: String,
    pub device_id: String,
    pub reason: String,
    pub approved_by: String,
    pub expiry_date: String,
}

pub fn parse_date(date: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

pub fn is_eol(record: &FirmwareRecord) -> bool {
    parse_date(&record.eol_date).is_some_and(|date| date < Utc::now().date_naive())
}

pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let left_parts: Vec<u64> = left
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect();
    let right_parts: Vec<u64> = right
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect();
    let len = left_parts.len().max(right_parts.len());

    for index in 0..len {
        let left_value = *left_parts.get(index).unwrap_or(&0);
        let right_value = *right_parts.get(index).unwrap_or(&0);
        match left_value.cmp(&right_value) {
            Ordering::Equal => continue,
            ordering => return ordering,
        }
    }

    Ordering::Equal
}

pub fn calculated_status(record: &FirmwareRecord) -> ComplianceStatus {
    if record.compliance_status == ComplianceStatus::Exception {
        return ComplianceStatus::Exception;
    }
    if is_eol(record) {
        return ComplianceStatus::EOL;
    }
    if compare_versions(&record.current_version, &record.minimum_version) == Ordering::Less {
        ComplianceStatus::NonCompliant
    } else {
        ComplianceStatus::Compliant
    }
}

pub fn active_exception(exception: &FirmwareException) -> bool {
    parse_date(&exception.expiry_date).is_some_and(|date| date >= Utc::now().date_naive())
}

/// Validate inputs for an exception request.
/// Returns `Err` with a human-readable message when validation fails.
pub fn validate_exception_request(
    reason: &str,
    approved_by: &str,
    expiry_days: i64,
) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    if approved_by.trim().is_empty() {
        return Err("approved_by cannot be empty".into());
    }
    if expiry_days <= 0 {
        return Err("expiry_days must be greater than zero".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(
        current_version: &str,
        minimum_version: &str,
        eol_date: &str,
        status: ComplianceStatus,
    ) -> FirmwareRecord {
        FirmwareRecord {
            id: "test-id".into(),
            device_type: DeviceType::Server,
            vendor: "TestVendor".into(),
            model: "TestModel".into(),
            current_version: current_version.into(),
            minimum_version: minimum_version.into(),
            latest_version: "99.99".into(),
            eol_date: eol_date.into(),
            site: "TEST".into(),
            compliance_status: status,
        }
    }

    #[test]
    fn test_compare_versions_less() {
        assert_eq!(compare_versions("2.90", "2.94"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_compare_versions_equal() {
        assert_eq!(compare_versions("10.2.1", "10.2.1"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_greater() {
        assert_eq!(compare_versions("4.25.7", "4.24.0"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_is_eol_past_date() {
        let rec = make_record("1.0", "1.0", "2020-01-01", ComplianceStatus::Compliant);
        assert!(is_eol(&rec), "past eol_date must be EOL");
    }

    #[test]
    fn test_is_eol_future_date() {
        let rec = make_record("1.0", "1.0", "2099-01-01", ComplianceStatus::Compliant);
        assert!(!is_eol(&rec), "future eol_date must not be EOL");
    }

    #[test]
    fn test_calculated_status_exception_preserved() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        assert_eq!(calculated_status(&rec), ComplianceStatus::Exception);
    }

    #[test]
    fn test_calculated_status_eol() {
        let rec = make_record("1.0", "1.0", "2020-01-01", ComplianceStatus::Compliant);
        assert_eq!(calculated_status(&rec), ComplianceStatus::EOL);
    }

    #[test]
    fn test_calculated_status_noncompliant() {
        let rec = make_record("2.90", "2.94", "2099-01-01", ComplianceStatus::Compliant);
        assert_eq!(calculated_status(&rec), ComplianceStatus::NonCompliant);
    }

    #[test]
    fn test_calculated_status_compliant() {
        let rec = make_record("2.94", "2.90", "2099-01-01", ComplianceStatus::Compliant);
        assert_eq!(calculated_status(&rec), ComplianceStatus::Compliant);
    }

    #[test]
    fn test_active_exception_future_expiry() {
        let exc = FirmwareException {
            id: "ex-1".into(),
            device_id: "dev-1".into(),
            reason: "test".into(),
            approved_by: "ops".into(),
            expiry_date: "2099-12-31".into(),
        };
        assert!(active_exception(&exc));
    }

    #[test]
    fn test_active_exception_past_expiry() {
        let exc = FirmwareException {
            id: "ex-2".into(),
            device_id: "dev-2".into(),
            reason: "test".into(),
            approved_by: "ops".into(),
            expiry_date: "2020-01-01".into(),
        };
        assert!(!active_exception(&exc));
    }

    #[test]
    fn test_validate_exception_request_ok() {
        assert!(validate_exception_request("good reason", "approver", 7).is_ok());
    }

    #[test]
    fn test_validate_exception_request_empty_reason() {
        assert!(validate_exception_request("", "approver", 7).is_err());
    }

    #[test]
    fn test_validate_exception_request_empty_approved_by() {
        assert!(validate_exception_request("reason", "", 7).is_err());
    }

    #[test]
    fn test_validate_exception_request_zero_expiry() {
        assert!(validate_exception_request("reason", "approver", 0).is_err());
    }

    #[test]
    fn test_validate_exception_request_negative_expiry() {
        assert!(validate_exception_request("reason", "approver", -1).is_err());
    }
}
