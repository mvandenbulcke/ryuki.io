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
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub expiry_date: String,
    pub status: FirmwareExceptionStatus,
    pub version: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirmwareExceptionStatus {
    Pending,
    Approved,
    Expired,
    Revoked,
    Legacy,
}

impl std::fmt::Display for FirmwareExceptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Approved => write!(f, "Approved"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked => write!(f, "Revoked"),
            Self::Legacy => write!(f, "Legacy"),
        }
    }
}

impl TryFrom<&str> for FirmwareExceptionStatus {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Pending" => Ok(Self::Pending),
            "Approved" => Ok(Self::Approved),
            "Expired" => Ok(Self::Expired),
            "Revoked" => Ok(Self::Revoked),
            "Legacy" => Ok(Self::Legacy),
            other => Err(format!("unknown firmware exception status '{other}'")),
        }
    }
}

pub const MAX_FIRMWARE_EXCEPTION_DAYS: i64 = 365;

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
    calculated_status_without_exception_at(record, Utc::now().date_naive())
}

pub fn active_exception(exception: &FirmwareException) -> bool {
    active_exception_at(exception, Utc::now().date_naive())
}

/// Evaluate exception expiry against an explicit calendar date. Keeping the
/// clock outside the pure rule lets persistence code use the authoritative
/// database date for both row selection and compliance calculation.
pub fn active_exception_at(exception: &FirmwareException, today: NaiveDate) -> bool {
    exception.status == FirmwareExceptionStatus::Approved
        && exception.approved_by.as_deref().is_some_and(|approver| {
            !approver.trim().is_empty() && approver.trim() != exception.requested_by.trim()
        })
        && parse_date(&exception.expiry_date).is_some_and(|date| date >= today)
}

fn calculated_status_without_exception_at(
    record: &FirmwareRecord,
    today: NaiveDate,
) -> ComplianceStatus {
    if parse_date(&record.eol_date).is_some_and(|date| date < today) {
        return ComplianceStatus::EOL;
    }
    if compare_versions(&record.current_version, &record.minimum_version) == Ordering::Less {
        ComplianceStatus::NonCompliant
    } else {
        ComplianceStatus::Compliant
    }
}

/// Calculate compliance from an authoritative exception fact and explicit
/// calendar date. Stored `Exception` status is never accepted as proof by
/// itself: the supplied exception must belong to the device, have a valid date,
/// and still be active. When no active exception exists, the underlying
/// EOL/version rule is applied.
pub fn calculated_status_with_exception_at(
    record: &FirmwareRecord,
    exception: Option<&FirmwareException>,
    today: NaiveDate,
) -> Result<ComplianceStatus, String> {
    if let Some(exception) = exception {
        if exception.device_id != record.id {
            return Err(format!(
                "Firmware exception '{}' does not belong to device '{}'",
                exception.id, record.id
            ));
        }
        if exception.status == FirmwareExceptionStatus::Approved {
            let approved_by = exception
                .approved_by
                .as_deref()
                .map(str::trim)
                .filter(|approver| !approver.is_empty())
                .ok_or_else(|| {
                    format!(
                        "Firmware exception '{}' has no verified approver",
                        exception.id
                    )
                })?;
            if approved_by == exception.requested_by.trim() {
                return Err(format!(
                    "Firmware exception '{}' violates maker/checker separation",
                    exception.id
                ));
            }
            let expiry = parse_date(&exception.expiry_date).ok_or_else(|| {
                format!(
                    "Firmware exception '{}' has an invalid expiry date",
                    exception.id
                )
            })?;
            if expiry >= today {
                return Ok(ComplianceStatus::Exception);
            }
        }
    }

    Ok(calculated_status_without_exception_at(record, today))
}

/// Current-date wrapper for [`calculated_status_with_exception_at`].
pub fn calculated_status_with_exception(
    record: &FirmwareRecord,
    exception: Option<&FirmwareException>,
) -> Result<ComplianceStatus, String> {
    calculated_status_with_exception_at(record, exception, Utc::now().date_naive())
}

/// Validate structural inputs for an exception request.
///
/// This function does not establish maker/checker separation because its
/// legacy call contract carries only one actor. Call
/// [`validate_approved_exception_request`] at an authenticated boundary that
/// can supply both canonical identities.
pub fn validate_exception_request(
    reason: &str,
    requested_by: &str,
    expiry_days: i64,
) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    if requested_by.trim().is_empty() {
        return Err("requested_by cannot be empty".into());
    }
    if expiry_days <= 0 {
        return Err("expiry_days must be greater than zero".into());
    }
    if expiry_days > MAX_FIRMWARE_EXCEPTION_DAYS {
        return Err(format!(
            "expiry_days cannot exceed {MAX_FIRMWARE_EXCEPTION_DAYS}"
        ));
    }
    Ok(())
}

/// Validate a firmware exception after authentication has established both
/// canonical actor identities. The requester (maker) and approver (checker)
/// must be distinct; callers must not populate either identity from client
/// input.
pub fn validate_approved_exception_request(
    reason: &str,
    requested_by: &str,
    approved_by: &str,
    expiry_days: i64,
) -> Result<(), String> {
    validate_exception_request(reason, requested_by, expiry_days)?;

    let requested_by = requested_by.trim();
    let approved_by = approved_by.trim();
    if requested_by.is_empty() {
        return Err("requested_by cannot be empty".into());
    }
    if approved_by.is_empty() {
        return Err("approved_by cannot be empty".into());
    }
    if requested_by == approved_by {
        return Err("firmware exception requester and approver must be distinct".into());
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

    fn make_exception(
        id: &str,
        device_id: &str,
        expiry_date: &str,
        status: FirmwareExceptionStatus,
    ) -> FirmwareException {
        FirmwareException {
            id: id.into(),
            device_id: device_id.into(),
            reason: "Temporary compatibility review".into(),
            requested_by: "maker".into(),
            approved_by: (status == FirmwareExceptionStatus::Approved).then(|| "checker".into()),
            expiry_date: expiry_date.into(),
            status,
            version: 1,
        }
    }

    #[test]
    fn test_compare_versions_less() {
        assert_eq!(compare_versions("2.90", "2.94"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_compare_versions_equal() {
        assert_eq!(
            compare_versions("10.2.1", "10.2.1"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_greater() {
        assert_eq!(
            compare_versions("4.25.7", "4.24.0"),
            std::cmp::Ordering::Greater
        );
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
    fn test_calculated_status_never_trusts_stored_exception_without_authority() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        assert_eq!(calculated_status(&rec), ComplianceStatus::NonCompliant);
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
        let exc = make_exception(
            "ex-1",
            "dev-1",
            "2099-12-31",
            FirmwareExceptionStatus::Approved,
        );
        assert!(active_exception(&exc));
    }

    #[test]
    fn test_active_exception_past_expiry() {
        let exc = make_exception(
            "ex-2",
            "dev-2",
            "2020-01-01",
            FirmwareExceptionStatus::Approved,
        );
        assert!(!active_exception(&exc));
    }

    #[test]
    fn test_pending_and_legacy_exceptions_never_grant_authority() {
        let today = NaiveDate::from_ymd_opt(2030, 1, 31).unwrap();
        for status in [
            FirmwareExceptionStatus::Pending,
            FirmwareExceptionStatus::Legacy,
            FirmwareExceptionStatus::Revoked,
            FirmwareExceptionStatus::Expired,
        ] {
            let exception = make_exception("ex-inactive", "test-id", "2099-01-01", status);
            assert!(!active_exception_at(&exception, today));
        }
    }

    #[test]
    fn test_calculated_status_with_active_matching_exception() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        let exception = make_exception(
            "ex-active",
            &rec.id,
            "2030-01-31",
            FirmwareExceptionStatus::Approved,
        );

        let status = calculated_status_with_exception_at(
            &rec,
            Some(&exception),
            NaiveDate::from_ymd_opt(2030, 1, 31).unwrap(),
        )
        .unwrap();

        assert_eq!(status, ComplianceStatus::Exception);
    }

    #[test]
    fn test_calculated_status_expired_exception_restores_underlying_status() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        let exception = make_exception(
            "ex-expired",
            &rec.id,
            "2030-01-30",
            FirmwareExceptionStatus::Approved,
        );

        let status = calculated_status_with_exception_at(
            &rec,
            Some(&exception),
            NaiveDate::from_ymd_opt(2030, 1, 31).unwrap(),
        )
        .unwrap();

        assert_eq!(status, ComplianceStatus::NonCompliant);
    }

    #[test]
    fn test_calculated_status_rejects_exception_for_another_device() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        let exception = make_exception(
            "ex-wrong-device",
            "another-device",
            "2099-01-01",
            FirmwareExceptionStatus::Approved,
        );

        let error = calculated_status_with_exception_at(
            &rec,
            Some(&exception),
            NaiveDate::from_ymd_opt(2030, 1, 31).unwrap(),
        )
        .expect_err("an exception for another device must not grant authority");

        assert!(error.contains("does not belong"));
    }

    #[test]
    fn test_calculated_status_rejects_malformed_exception_expiry() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        let exception = make_exception(
            "ex-invalid-expiry",
            &rec.id,
            "not-a-date",
            FirmwareExceptionStatus::Approved,
        );

        let error = calculated_status_with_exception_at(
            &rec,
            Some(&exception),
            NaiveDate::from_ymd_opt(2030, 1, 31).unwrap(),
        )
        .expect_err("malformed expiry must not grant exception authority");

        assert!(error.contains("invalid expiry date"));
    }

    #[test]
    fn test_calculated_status_rejects_self_approved_exception() {
        let rec = make_record("1.0", "2.0", "2099-01-01", ComplianceStatus::Exception);
        let mut exception = make_exception(
            "ex-self-approved",
            &rec.id,
            "2099-01-01",
            FirmwareExceptionStatus::Approved,
        );
        exception.approved_by = Some(exception.requested_by.clone());

        let error = calculated_status_with_exception_at(
            &rec,
            Some(&exception),
            NaiveDate::from_ymd_opt(2030, 1, 31).unwrap(),
        )
        .expect_err("self-approved exception must not grant authority");
        assert!(error.contains("maker/checker"));
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
    fn test_validate_exception_request_empty_requester() {
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

    #[test]
    fn test_validate_exception_request_rejects_unbounded_expiry() {
        assert!(
            validate_exception_request("reason", "requester", MAX_FIRMWARE_EXCEPTION_DAYS + 1,)
                .is_err()
        );
    }

    #[test]
    fn test_validate_approved_exception_request_requires_distinct_actors() {
        let error = validate_approved_exception_request("reason", "operator-1", "operator-1", 7)
            .expect_err("maker and checker must be distinct");

        assert!(error.contains("must be distinct"));
    }

    #[test]
    fn test_validate_approved_exception_request_accepts_distinct_actors() {
        assert!(
            validate_approved_exception_request("reason", "operator-1", "approver-2", 7).is_ok()
        );
    }

    #[test]
    fn test_validate_approved_exception_request_rejects_blank_requester() {
        assert!(validate_approved_exception_request("reason", " ", "approver-2", 7).is_err());
    }

    #[test]
    fn test_validate_approved_exception_request_rejects_blank_approver() {
        assert!(validate_approved_exception_request("reason", "operator-1", " ", 7).is_err());
    }
}
