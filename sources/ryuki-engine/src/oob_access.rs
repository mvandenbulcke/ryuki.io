use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};

type OobStore = Vec<OOBEndpoint>;

static OOB_STORE: OnceLock<Mutex<OobStore>> = OnceLock::new();

fn oob_store() -> &'static Mutex<OobStore> {
    OOB_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> OobStore {
    let now = chrono::Utc::now();
    vec![
        OOBEndpoint {
            id: "oob-defra-001".into(),
            endpoint_type: "iLO".into(),
            hostname: "idefra01.corp.local".into(),
            ip_address: "10.1.100.11".into(),
            site: "DEFRA".into(),
            firmware_version: "2.78".into(),
            certificate_valid: true,
            cert_expiry: (now + chrono::Duration::days(180)).to_rfc3339(),
            last_tested: now.to_rfc3339(),
            reachable: true,
            default_credentials_changed: true,
        },
        OOBEndpoint {
            id: "oob-defra-002".into(),
            endpoint_type: "iDRAC".into(),
            hostname: "idrac02.corp.local".into(),
            ip_address: "10.1.100.12".into(),
            site: "DEFRA".into(),
            firmware_version: "6.10.30.00".into(),
            certificate_valid: false,
            cert_expiry: (now - chrono::Duration::days(15)).to_rfc3339(),
            last_tested: (now - chrono::Duration::hours(4)).to_rfc3339(),
            reachable: false,
            default_credentials_changed: false,
        },
        OOBEndpoint {
            id: "oob-defra-003".into(),
            endpoint_type: "IPMI".into(),
            hostname: "ipmi03.corp.local".into(),
            ip_address: "10.1.100.13".into(),
            site: "DEFRA".into(),
            firmware_version: "1.94".into(),
            certificate_valid: true,
            cert_expiry: (now + chrono::Duration::days(20)).to_rfc3339(),
            last_tested: now.to_rfc3339(),
            reachable: true,
            default_credentials_changed: true,
        },
        OOBEndpoint {
            id: "oob-gblon-001".into(),
            endpoint_type: "iLO".into(),
            hostname: "ilocur101.corp.local".into(),
            ip_address: "10.2.100.11".into(),
            site: "GBLON".into(),
            firmware_version: "2.80".into(),
            certificate_valid: true,
            cert_expiry: (now + chrono::Duration::days(365)).to_rfc3339(),
            last_tested: (now - chrono::Duration::days(2)).to_rfc3339(),
            reachable: true,
            default_credentials_changed: true,
        },
        OOBEndpoint {
            id: "oob-gblon-002".into(),
            endpoint_type: "XCC".into(),
            hostname: "xccgblon02.corp.local".into(),
            ip_address: "10.2.100.12".into(),
            site: "GBLON".into(),
            firmware_version: "4.20".into(),
            certificate_valid: true,
            cert_expiry: (now + chrono::Duration::days(10)).to_rfc3339(),
            last_tested: (now - chrono::Duration::days(1)).to_rfc3339(),
            reachable: false,
            default_credentials_changed: false,
        },
        OOBEndpoint {
            id: "oob-gblon-003".into(),
            endpoint_type: "iDRAC".into(),
            hostname: "idracgblon03.corp.local".into(),
            ip_address: "10.2.100.13".into(),
            site: "GBLON".into(),
            firmware_version: "6.00.00.00".into(),
            certificate_valid: false,
            cert_expiry: (now - chrono::Duration::days(45)).to_rfc3339(),
            last_tested: (now - chrono::Duration::hours(12)).to_rfc3339(),
            reachable: true,
            default_credentials_changed: true,
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OOBEndpoint {
    pub id: String,
    pub endpoint_type: String,
    pub hostname: String,
    pub ip_address: String,
    pub site: String,
    pub firmware_version: String,
    pub certificate_valid: bool,
    pub cert_expiry: String,
    pub last_tested: String,
    pub reachable: bool,
    pub default_credentials_changed: bool,
}

pub fn test_endpoint(endpoint_id: &str) -> Result<Value, String> {
    let store = oob_store().lock().unwrap();
    let _endpoint = store
        .iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| format!("OOB endpoint {} not found", endpoint_id))?;

    let now = chrono::Utc::now();
    drop(store);

    let mut store = oob_store().lock().unwrap();
    let endpoint = store.iter_mut().find(|e| e.id == endpoint_id).unwrap();

    endpoint.last_tested = now.to_rfc3339();
    endpoint.reachable = true;

    Ok(json!({
        "source": "dry-run",
        "endpoint_id": endpoint_id,
        "endpoint_type": endpoint.endpoint_type,
        "hostname": endpoint.hostname,
        "reachable": true,
        "tested_at": now.to_rfc3339(),
        "dry_run": true
    }))
}

pub fn validate_certificate(endpoint_id: &str) -> Result<Value, String> {
    let store = oob_store().lock().unwrap();
    let endpoint = store
        .iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| format!("OOB endpoint {} not found", endpoint_id))?;

    let now = chrono::Utc::now();
    let cert_expiry = chrono::DateTime::parse_from_rfc3339(&endpoint.cert_expiry)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(now);

    let days_remaining = (cert_expiry - now).num_days();
    let valid = endpoint.certificate_valid && days_remaining > 0;

    Ok(json!({
        "source": "dry-run",
        "endpoint_id": endpoint_id,
        "hostname": endpoint.hostname,
        "certificate_valid": valid,
        "cert_expiry": endpoint.cert_expiry,
        "days_remaining": days_remaining.max(0),
        "dry_run": true
    }))
}

pub fn check_default_credentials(endpoint_id: &str) -> Result<Value, String> {
    let store = oob_store().lock().unwrap();
    let endpoint = store
        .iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| format!("OOB endpoint {} not found", endpoint_id))?;

    Ok(json!({
        "source": "dry-run",
        "endpoint_id": endpoint_id,
        "hostname": endpoint.hostname,
        "default_credentials_changed": endpoint.default_credentials_changed,
        "status": if endpoint.default_credentials_changed { "compliant" } else { "non_compliant" },
        "dry_run": true
    }))
}

pub fn get_inventory(site: &str) -> Result<Value, String> {
    let store = oob_store().lock().unwrap();
    let endpoints: Vec<&OOBEndpoint> = if site.is_empty() {
        store.iter().collect()
    } else {
        store.iter().filter(|e| e.site == site).collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "total": endpoints.len(),
        "endpoints": endpoints.iter().map(|e| json!({
            "id": e.id,
            "endpoint_type": e.endpoint_type,
            "hostname": e.hostname,
            "ip_address": e.ip_address,
            "site": e.site,
            "firmware_version": e.firmware_version,
            "certificate_valid": e.certificate_valid,
            "cert_expiry": e.cert_expiry,
            "last_tested": e.last_tested,
            "reachable": e.reachable,
            "default_credentials_changed": e.default_credentials_changed,
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn get_failing(site: &str) -> Result<Value, String> {
    let store = oob_store().lock().unwrap();
    let endpoints: Vec<&OOBEndpoint> = store
        .iter()
        .filter(|e| {
            let site_match = site.is_empty() || e.site == site;
            site_match && !e.reachable
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "failing_count": endpoints.len(),
        "endpoints": endpoints.iter().map(|e| json!({
            "id": e.id,
            "endpoint_type": e.endpoint_type,
            "hostname": e.hostname,
            "site": e.site,
            "last_tested": e.last_tested,
            "reachable": e.reachable,
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn get_cert_expiring() -> Result<Value, String> {
    let store = oob_store().lock().unwrap();
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(30);

    let expiring: Vec<&OOBEndpoint> = store
        .iter()
        .filter(|e| {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&e.cert_expiry) {
                !e.certificate_valid || expiry.with_timezone(&chrono::Utc) <= threshold
            } else {
                false
            }
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "threshold_days": 30,
        "expiring_count": expiring.len(),
        "endpoints": expiring.iter().map(|e| {
            let days_remaining = chrono::DateTime::parse_from_rfc3339(&e.cert_expiry)
                .map(|dt| {
                    let remaining = (dt.with_timezone(&chrono::Utc) - now).num_days();
                    remaining.max(0)
                })
                .unwrap_or(0);
            json!({
                "id": e.id,
                "endpoint_type": e.endpoint_type,
                "hostname": e.hostname,
                "site": e.site,
                "certificate_valid": e.certificate_valid,
                "cert_expiry": e.cert_expiry,
                "days_remaining": days_remaining,
            })
        }).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn get_firmware_outdated() -> Result<Value, String> {
    let baseline: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
        ("iLO", "2.80"),
        ("iDRAC", "6.10.30.00"),
        ("XCC", "4.21"),
        ("IPMI", "2.00"),
    ]);

    let store = oob_store().lock().unwrap();
    let outdated: Vec<&OOBEndpoint> = store
        .iter()
        .filter(|e| {
            if let Some(&baseline_ver) = baseline.get(e.endpoint_type.as_str()) {
                e.firmware_version.as_str() != baseline_ver
            } else {
                false
            }
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "firmware_baseline": baseline,
        "outdated_count": outdated.len(),
        "endpoints": outdated.iter().map(|e| json!({
            "id": e.id,
            "endpoint_type": e.endpoint_type,
            "hostname": e.hostname,
            "site": e.site,
            "firmware_version": e.firmware_version,
            "baseline": baseline.get(e.endpoint_type.as_str()),
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn run_site_validation(site: &str) -> Result<Value, String> {
    let now = chrono::Utc::now();
    let store = oob_store().lock().unwrap();

    let endpoints: Vec<&OOBEndpoint> = store.iter().filter(|e| e.site == site).collect();

    if endpoints.is_empty() {
        return Err(format!("No OOB endpoints found for site {}", site));
    }

    let total = endpoints.len();
    let reachable = endpoints.iter().filter(|e| e.reachable).count();
    let cert_valid = endpoints.iter().filter(|e| e.certificate_valid).count();
    let defaults_changed = endpoints
        .iter()
        .filter(|e| e.default_credentials_changed)
        .count();

    drop(store);

    let mut store = oob_store().lock().unwrap();
    for endpoint in store.iter_mut().filter(|e| e.site == site) {
        endpoint.last_tested = now.to_rfc3339();
    }

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "validated_at": now.to_rfc3339(),
        "total_endpoints": total,
        "reachable": reachable,
        "unreachable": total - reachable,
        "certificates_valid": cert_valid,
        "certificates_invalid": total - cert_valid,
        "defaults_changed": defaults_changed,
        "defaults_unchanged": total - defaults_changed,
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_data_has_six_endpoints() {
        let store = oob_store().lock().unwrap();
        assert_eq!(store.len(), 6);
    }

    #[test]
    fn test_get_inventory_all() {
        let result = get_inventory("").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["total"], 6);
        assert_eq!(result["site"], "all");
    }

    #[test]
    fn test_get_inventory_by_site() {
        let result = get_inventory("DEFRA").unwrap();
        assert_eq!(result["site"], "DEFRA");
        assert_eq!(result["total"], 3);
    }

    #[test]
    fn test_get_inventory_gblon() {
        let result = get_inventory("GBLON").unwrap();
        assert_eq!(result["total"], 3);
    }

    #[test]
    fn test_test_endpoint_success() {
        let result = test_endpoint("oob-defra-001").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["endpoint_id"], "oob-defra-001");
        assert_eq!(result["reachable"], true);
        assert!(result["dry_run"].as_bool().unwrap());
    }

    #[test]
    fn test_test_endpoint_not_found() {
        assert!(test_endpoint("nonexistent").is_err());
    }

    #[test]
    fn test_validate_certificate_valid() {
        let result = validate_certificate("oob-defra-001").unwrap();
        assert_eq!(result["certificate_valid"], true);
        assert!(result["days_remaining"].as_i64().unwrap() > 0);
    }

    #[test]
    fn test_validate_certificate_expired() {
        let result = validate_certificate("oob-defra-002").unwrap();
        assert_eq!(result["certificate_valid"], false);
    }

    #[test]
    fn test_check_default_credentials_compliant() {
        let result = check_default_credentials("oob-defra-001").unwrap();
        assert_eq!(result["default_credentials_changed"], true);
        assert_eq!(result["status"], "compliant");
    }

    #[test]
    fn test_check_default_credentials_non_compliant() {
        let result = check_default_credentials("oob-defra-002").unwrap();
        assert_eq!(result["default_credentials_changed"], false);
        assert_eq!(result["status"], "non_compliant");
    }

    #[test]
    fn test_get_failing() {
        let result = get_failing("").unwrap();
        assert_eq!(result["source"], "dry-run");
        let count = result["failing_count"].as_u64().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_get_failing_by_site() {
        let result = get_failing("DEFRA").unwrap();
        let count = result["failing_count"].as_u64().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_get_cert_expiring() {
        let result = get_cert_expiring().unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["threshold_days"], 30);
        let count = result["expiring_count"].as_u64().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_get_firmware_outdated() {
        let result = get_firmware_outdated().unwrap();
        assert_eq!(result["source"], "dry-run");
        let count = result["outdated_count"].as_u64().unwrap();
        assert!(count > 0);
        let endpoints = result["endpoints"].as_array().unwrap();
        assert!(!endpoints.is_empty());
    }

    #[test]
    fn test_run_site_validation_defra() {
        let result = run_site_validation("DEFRA").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["site"], "DEFRA");
        assert_eq!(result["total_endpoints"], 3);
        assert!(result["reachable"].as_u64().unwrap() > 0);
        assert!(result["dry_run"].as_bool().unwrap());
    }

    #[test]
    fn test_run_site_validation_unknown() {
        assert!(run_site_validation("UNKNOWN").is_err());
    }

    #[test]
    fn test_get_failing_for_site_no_failures() {
        let mut store = oob_store().lock().unwrap();
        for ep in store.iter_mut().filter(|e| e.site == "GBLON") {
            ep.reachable = true;
        }
        drop(store);

        let result = get_failing("GBLON").unwrap();
        assert_eq!(result["failing_count"], 0);
    }
}
