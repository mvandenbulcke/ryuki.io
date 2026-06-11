use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

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

type FirmwareStore = (Vec<FirmwareRecord>, Vec<FirmwareException>);

static FIRMWARE_STORE: OnceLock<Mutex<FirmwareStore>> = OnceLock::new();

fn store() -> &'static Mutex<FirmwareStore> {
    FIRMWARE_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> FirmwareStore {
    (
        vec![
            FirmwareRecord {
                id: "fw-defra-srv-001".into(),
                device_type: DeviceType::Server,
                vendor: "HPE".into(),
                model: "DL360 Gen10".into(),
                current_version: "2.94".into(),
                minimum_version: "2.90".into(),
                latest_version: "2.96".into(),
                eol_date: "2028-12-31".into(),
                site: "DEFRA".into(),
                compliance_status: ComplianceStatus::Compliant,
            },
            FirmwareRecord {
                id: "fw-defra-sw-001".into(),
                device_type: DeviceType::Switch,
                vendor: "Cisco".into(),
                model: "Nexus 93180YC-FX".into(),
                current_version: "10.2.1".into(),
                minimum_version: "10.2.5".into(),
                latest_version: "10.4.3".into(),
                eol_date: "2027-09-30".into(),
                site: "DEFRA".into(),
                compliance_status: ComplianceStatus::NonCompliant,
            },
            FirmwareRecord {
                id: "fw-defra-pdu-001".into(),
                device_type: DeviceType::PDU,
                vendor: "APC".into(),
                model: "AP8941".into(),
                current_version: "6.9.4".into(),
                minimum_version: "6.8.0".into(),
                latest_version: "7.1.2".into(),
                eol_date: "2029-03-31".into(),
                site: "DEFRA".into(),
                compliance_status: ComplianceStatus::Compliant,
            },
            FirmwareRecord {
                id: "fw-gblon-srv-001".into(),
                device_type: DeviceType::Server,
                vendor: "Lenovo".into(),
                model: "SR635".into(),
                current_version: "3.10".into(),
                minimum_version: "3.20".into(),
                latest_version: "3.24".into(),
                eol_date: "2028-06-30".into(),
                site: "GBLON".into(),
                compliance_status: ComplianceStatus::NonCompliant,
            },
            FirmwareRecord {
                id: "fw-gblon-sw-001".into(),
                device_type: DeviceType::Switch,
                vendor: "Arista".into(),
                model: "7050SX3".into(),
                current_version: "4.25.7".into(),
                minimum_version: "4.29.1".into(),
                latest_version: "4.31.2".into(),
                eol_date: "2025-09-30".into(),
                site: "GBLON".into(),
                compliance_status: ComplianceStatus::EOL,
            },
            FirmwareRecord {
                id: "fw-gblon-crac-001".into(),
                device_type: DeviceType::CRAC,
                vendor: "Vertiv".into(),
                model: "Liebert iCOM".into(),
                current_version: "8.1".into(),
                minimum_version: "8.0".into(),
                latest_version: "8.4".into(),
                eol_date: "2027-12-31".into(),
                site: "GBLON".into(),
                compliance_status: ComplianceStatus::Exception,
            },
            FirmwareRecord {
                id: "fw-deber-fw-001".into(),
                device_type: DeviceType::Firewall,
                vendor: "Palo Alto".into(),
                model: "PA-3220".into(),
                current_version: "10.1.11".into(),
                minimum_version: "10.2.8".into(),
                latest_version: "11.1.4".into(),
                eol_date: "2026-12-31".into(),
                site: "DEBER".into(),
                compliance_status: ComplianceStatus::NonCompliant,
            },
            FirmwareRecord {
                id: "fw-deber-srv-001".into(),
                device_type: DeviceType::Server,
                vendor: "Dell".into(),
                model: "PowerEdge R750".into(),
                current_version: "6.10".into(),
                minimum_version: "6.8".into(),
                latest_version: "7.1".into(),
                eol_date: "2030-01-31".into(),
                site: "DEBER".into(),
                compliance_status: ComplianceStatus::Compliant,
            },
            FirmwareRecord {
                id: "fw-deber-pdu-001".into(),
                device_type: DeviceType::PDU,
                vendor: "Eaton".into(),
                model: "ePDU G3".into(),
                current_version: "2.5.0".into(),
                minimum_version: "2.8.0".into(),
                latest_version: "3.0.1".into(),
                eol_date: "2024-12-31".into(),
                site: "DEBER".into(),
                compliance_status: ComplianceStatus::EOL,
            },
        ],
        vec![FirmwareException {
            id: "fwex-gblon-crac-001".into(),
            device_id: "fw-gblon-crac-001".into(),
            reason: "Awaiting maintenance window for CRAC controller upgrade".into(),
            approved_by: "facilities.lead".into(),
            expiry_date: (Utc::now() + Duration::days(21)).date_naive().to_string(),
        }],
    )
}

fn parse_date(date: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

fn is_eol(record: &FirmwareRecord) -> bool {
    parse_date(&record.eol_date).is_some_and(|date| date < Utc::now().date_naive())
}

fn compare_versions(left: &str, right: &str) -> Ordering {
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

fn calculated_status(record: &FirmwareRecord) -> ComplianceStatus {
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

fn active_exception(exception: &FirmwareException) -> bool {
    parse_date(&exception.expiry_date).is_some_and(|date| date >= Utc::now().date_naive())
}

pub fn list_devices(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let devices: Vec<FirmwareRecord> = store
        .0
        .iter()
        .filter(|device| site.is_empty() || device.site == site)
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { Value::Null } else { json!(site) },
        "count": devices.len(),
        "devices": devices
    }))
}

pub fn get_device(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let device = store
        .0
        .iter()
        .find(|device| device.id == id)
        .ok_or_else(|| format!("Firmware device '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "device": device
    }))
}

pub fn check_compliance(id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let device = store
        .0
        .iter_mut()
        .find(|device| device.id == id)
        .ok_or_else(|| format!("Firmware device '{}' not found", id))?;
    let status = calculated_status(device);
    device.compliance_status = status.clone();

    Ok(json!({
        "source": "dry-run",
        "device_id": device.id,
        "site": device.site,
        "vendor": device.vendor,
        "model": device.model,
        "current_version": device.current_version,
        "minimum_version": device.minimum_version,
        "latest_version": device.latest_version,
        "eol_date": device.eol_date,
        "compliance_status": status.to_string(),
        "meets_minimum": compare_versions(&device.current_version, &device.minimum_version) != Ordering::Less,
        "latest_available": device.current_version == device.latest_version,
        "dry_run": true
    }))
}

pub fn get_noncompliant() -> Result<Value, String> {
    let store = store().lock().unwrap();
    let devices: Vec<FirmwareRecord> = store
        .0
        .iter()
        .filter(|device| {
            matches!(
                device.compliance_status,
                ComplianceStatus::NonCompliant | ComplianceStatus::EOL
            )
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": devices.len(),
        "devices": devices
    }))
}

pub fn get_eol_devices() -> Result<Value, String> {
    let store = store().lock().unwrap();
    let devices: Vec<FirmwareRecord> = store
        .0
        .iter()
        .filter(|device| is_eol(device))
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": devices.len(),
        "devices": devices
    }))
}

pub fn request_exception(
    device_id: &str,
    reason: &str,
    approved_by: &str,
    expiry_days: i64,
) -> Result<Value, String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    if approved_by.trim().is_empty() {
        return Err("approved_by cannot be empty".into());
    }
    if expiry_days <= 0 {
        return Err("expiry_days must be greater than zero".into());
    }

    let mut store = store().lock().unwrap();
    let device = store
        .0
        .iter_mut()
        .find(|device| device.id == device_id)
        .ok_or_else(|| format!("Firmware device '{}' not found", device_id))?;
    device.compliance_status = ComplianceStatus::Exception;

    let exception = FirmwareException {
        id: format!(
            "fwex-{}",
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        device_id: device_id.to_string(),
        reason: reason.to_string(),
        approved_by: approved_by.to_string(),
        expiry_date: (Utc::now() + Duration::days(expiry_days))
            .date_naive()
            .to_string(),
    };
    store.1.push(exception.clone());

    Ok(json!({
        "source": "dry-run",
        "exception": exception,
        "device_status": ComplianceStatus::Exception.to_string()
    }))
}

pub fn list_exceptions() -> Result<Value, String> {
    let store = store().lock().unwrap();
    let exceptions: Vec<FirmwareException> = store
        .1
        .iter()
        .filter(|exception| active_exception(exception))
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": exceptions.len(),
        "exceptions": exceptions
    }))
}

pub fn revoke_exception(exception_id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let index = store
        .1
        .iter()
        .position(|exception| exception.id == exception_id)
        .ok_or_else(|| format!("Firmware exception '{}' not found", exception_id))?;
    let exception = store.1.remove(index);

    if let Some(device) = store
        .0
        .iter_mut()
        .find(|device| device.id == exception.device_id)
    {
        device.compliance_status = ComplianceStatus::NonCompliant;
    }

    Ok(json!({
        "source": "dry-run",
        "revoked_exception_id": exception_id,
        "device_id": exception.device_id,
        "device_status": ComplianceStatus::NonCompliant.to_string()
    }))
}

pub fn get_compliance_report() -> Result<Value, String> {
    let store = store().lock().unwrap();
    let total = store.0.len();
    let compliant = store
        .0
        .iter()
        .filter(|device| device.compliance_status == ComplianceStatus::Compliant)
        .count();
    let noncompliant = store
        .0
        .iter()
        .filter(|device| device.compliance_status == ComplianceStatus::NonCompliant)
        .count();
    let eol = store
        .0
        .iter()
        .filter(|device| device.compliance_status == ComplianceStatus::EOL)
        .count();
    let exception = store
        .0
        .iter()
        .filter(|device| device.compliance_status == ComplianceStatus::Exception)
        .count();

    Ok(json!({
        "source": "dry-run",
        "total": total,
        "compliant": compliant,
        "noncompliant": noncompliant,
        "eol": eol,
        "exception": exception,
        "dry_run": true
    }))
}

pub fn get_vendor_summary() -> Result<Value, String> {
    let store = store().lock().unwrap();
    let mut vendors: BTreeMap<String, (usize, usize, usize, usize, usize)> = BTreeMap::new();

    for device in &store.0 {
        let entry = vendors
            .entry(device.vendor.clone())
            .or_insert((0, 0, 0, 0, 0));
        entry.0 += 1;
        match device.compliance_status {
            ComplianceStatus::Compliant => entry.1 += 1,
            ComplianceStatus::NonCompliant => entry.2 += 1,
            ComplianceStatus::EOL => entry.3 += 1,
            ComplianceStatus::Exception => entry.4 += 1,
        }
    }

    let summary: Vec<Value> = vendors
        .into_iter()
        .map(
            |(vendor, (total, compliant, noncompliant, eol, exception))| {
                let compliance_percentage = if total == 0 {
                    0.0
                } else {
                    (compliant as f64 / total as f64) * 100.0
                };
                json!({
                    "vendor": vendor,
                    "total": total,
                    "compliant": compliant,
                    "noncompliant": noncompliant,
                    "eol": eol,
                    "exception": exception,
                    "compliance_percentage": compliance_percentage
                })
            },
        )
        .collect();

    Ok(json!({
        "source": "dry-run",
        "vendors": summary
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices_returns_seed_entries() {
        let result = list_devices("").unwrap();

        assert_eq!(result["source"], "dry-run");
        assert!(result["devices"].as_array().unwrap().len() >= 8);
    }

    #[test]
    fn test_list_devices_filters_by_site() {
        let result = list_devices("DEFRA").unwrap();
        let devices = result["devices"].as_array().unwrap();

        assert!(!devices.is_empty());
        assert!(devices.iter().all(|device| device["site"] == "DEFRA"));
    }

    #[test]
    fn test_get_noncompliant_finds_noncompliant_devices() {
        let result = get_noncompliant().unwrap();
        let devices = result["devices"].as_array().unwrap();

        assert!(
            devices
                .iter()
                .any(|device| device["compliance_status"] == "NonCompliant")
        );
    }

    #[test]
    fn test_get_eol_devices_finds_eol_devices() {
        let result = get_eol_devices().unwrap();
        let devices = result["devices"].as_array().unwrap();

        assert!(
            devices
                .iter()
                .any(|device| device["compliance_status"] == "EOL")
        );
    }

    #[test]
    fn test_request_and_list_exceptions() {
        let request = request_exception(
            "fw-defra-sw-001",
            "Vendor image pending staged validation",
            "netops.lead",
            14,
        )
        .unwrap();
        let exception_id = request["exception"]["id"].as_str().unwrap();
        let exceptions = list_exceptions().unwrap();

        assert!(
            exceptions["exceptions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|exception| exception["id"] == exception_id)
        );
    }

    #[test]
    fn test_revoke_exception_restores_noncompliant_status() {
        let request = request_exception(
            "fw-gblon-srv-001",
            "Rollback validation required",
            "platform.owner",
            7,
        )
        .unwrap();
        let exception_id = request["exception"]["id"].as_str().unwrap();

        revoke_exception(exception_id).unwrap();
        let device = get_device("fw-gblon-srv-001").unwrap();

        assert_eq!(device["device"]["compliance_status"], "NonCompliant");
    }
}
