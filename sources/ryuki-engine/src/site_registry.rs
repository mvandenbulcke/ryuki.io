use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteEntry {
    pub unlocode: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub timezone: String,
    pub active: bool,
}

fn reference_sites() -> Vec<SiteEntry> {
    vec![
        SiteEntry { unlocode: "DEBER".into(), name: "Berlin".into(), country: "Germany".into(), country_code: "DE".into(), timezone: "Europe/Berlin".into(), active: true },
        SiteEntry { unlocode: "DEFRA".into(), name: "Frankfurt".into(), country: "Germany".into(), country_code: "DE".into(), timezone: "Europe/Berlin".into(), active: true },
        SiteEntry { unlocode: "DEMUC".into(), name: "München".into(), country: "Germany".into(), country_code: "DE".into(), timezone: "Europe/Berlin".into(), active: false },
        SiteEntry { unlocode: "DEDUS".into(), name: "Düsseldorf".into(), country: "Germany".into(), country_code: "DE".into(), timezone: "Europe/Berlin".into(), active: false },
        SiteEntry { unlocode: "FRPAR".into(), name: "Paris".into(), country: "France".into(), country_code: "FR".into(), timezone: "Europe/Paris".into(), active: true },
        SiteEntry { unlocode: "FRMRS".into(), name: "Marseille".into(), country: "France".into(), country_code: "FR".into(), timezone: "Europe/Paris".into(), active: false },
        SiteEntry { unlocode: "GBLON".into(), name: "London".into(), country: "United Kingdom".into(), country_code: "GB".into(), timezone: "Europe/London".into(), active: true },
        SiteEntry { unlocode: "GBMAN".into(), name: "Manchester".into(), country: "United Kingdom".into(), country_code: "GB".into(), timezone: "Europe/London".into(), active: false },
        SiteEntry { unlocode: "NLAMS".into(), name: "Amsterdam".into(), country: "Netherlands".into(), country_code: "NL".into(), timezone: "Europe/Amsterdam".into(), active: true },
        SiteEntry { unlocode: "NLEIN".into(), name: "Eindhoven".into(), country: "Netherlands".into(), country_code: "NL".into(), timezone: "Europe/Amsterdam".into(), active: false },
        SiteEntry { unlocode: "ESMAD".into(), name: "Madrid".into(), country: "Spain".into(), country_code: "ES".into(), timezone: "Europe/Madrid".into(), active: false },
        SiteEntry { unlocode: "ESBCN".into(), name: "Barcelona".into(), country: "Spain".into(), country_code: "ES".into(), timezone: "Europe/Madrid".into(), active: false },
        SiteEntry { unlocode: "ITMIL".into(), name: "Milano".into(), country: "Italy".into(), country_code: "IT".into(), timezone: "Europe/Rome".into(), active: false },
        SiteEntry { unlocode: "ITROM".into(), name: "Roma".into(), country: "Italy".into(), country_code: "IT".into(), timezone: "Europe/Rome".into(), active: false },
        SiteEntry { unlocode: "CHZRH".into(), name: "Zürich".into(), country: "Switzerland".into(), country_code: "CH".into(), timezone: "Europe/Zurich".into(), active: false },
        SiteEntry { unlocode: "ATVIE".into(), name: "Wien".into(), country: "Austria".into(), country_code: "AT".into(), timezone: "Europe/Vienna".into(), active: false },
        SiteEntry { unlocode: "BEBRU".into(), name: "Brussels".into(), country: "Belgium".into(), country_code: "BE".into(), timezone: "Europe/Brussels".into(), active: false },
        SiteEntry { unlocode: "SE STO".into(), name: "Stockholm".into(), country: "Sweden".into(), country_code: "SE".into(), timezone: "Europe/Stockholm".into(), active: false },
        SiteEntry { unlocode: "DKCPH".into(), name: "København".into(), country: "Denmark".into(), country_code: "DK".into(), timezone: "Europe/Copenhagen".into(), active: false },
        SiteEntry { unlocode: "IE DUB".into(), name: "Dublin".into(), country: "Ireland".into(), country_code: "IE".into(), timezone: "Europe/Dublin".into(), active: false },
    ]
}

static SITE_STORE: std::sync::LazyLock<Mutex<Vec<SiteEntry>>> =
    std::sync::LazyLock::new(|| Mutex::new(reference_sites()));

fn site_store() -> &'static Mutex<Vec<SiteEntry>> {
    &SITE_STORE
}

pub fn list_sites(active_only: bool) -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let sites: Vec<Value> = store
        .iter()
        .filter(|s| !active_only || s.active)
        .map(|s| {
            json!({
                "unlocode": s.unlocode,
                "name": s.name,
                "country": s.country,
                "country_code": s.country_code,
                "timezone": s.timezone,
                "active": s.active
            })
        })
        .collect();
    Ok(json!({"source": "dry-run", "count": sites.len(), "sites": sites}))
}

pub fn get_site(unlocode: &str) -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let site = store
        .iter()
        .find(|s| s.unlocode == unlocode)
        .ok_or_else(|| format!("Site '{}' not found", unlocode))?;
    Ok(json!({
        "source": "dry-run",
        "unlocode": site.unlocode,
        "name": site.name,
        "country": site.country,
        "country_code": site.country_code,
        "timezone": site.timezone,
        "active": site.active
    }))
}

pub fn activate_site(unlocode: &str) -> Result<Value, String> {
    let mut store = site_store().lock().map_err(|e| e.to_string())?;
    let site = store
        .iter_mut()
        .find(|s| s.unlocode == unlocode)
        .ok_or_else(|| format!("Site '{}' not found in reference list", unlocode))?;
    site.active = true;
    Ok(json!({
        "source": "dry-run",
        "unlocode": site.unlocode,
        "name": site.name,
        "active": true,
        "message": format!("Site {} ({}) activated", site.unlocode, site.name)
    }))
}

pub fn deactivate_site(unlocode: &str) -> Result<Value, String> {
    let mut store = site_store().lock().map_err(|e| e.to_string())?;
    let site = store
        .iter_mut()
        .find(|s| s.unlocode == unlocode)
        .ok_or_else(|| format!("Site '{}' not found", unlocode))?;
    site.active = false;
    Ok(json!({
        "source": "dry-run",
        "unlocode": site.unlocode,
        "name": site.name,
        "active": false,
        "message": format!("Site {} ({}) deactivated", site.unlocode, site.name)
    }))
}

pub fn search_sites(query: &str) -> Result<Value, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    let q = query.to_lowercase();
    let matches: Vec<Value> = store
        .iter()
        .filter(|s| {
            s.unlocode.to_lowercase().contains(&q)
                || s.name.to_lowercase().contains(&q)
                || s.country.to_lowercase().contains(&q)
                || s.country_code.to_lowercase() == q
        })
        .map(|s| {
            json!({
                "unlocode": s.unlocode,
                "name": s.name,
                "country": s.country,
                "country_code": s.country_code,
                "timezone": s.timezone,
                "active": s.active
            })
        })
        .collect();
    Ok(json!({"source": "dry-run", "query": query, "count": matches.len(), "matches": matches}))
}

pub fn get_active_site_codes() -> Result<Vec<String>, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    Ok(store.iter().filter(|s| s.active).map(|s| s.unlocode.clone()).collect())
}

pub fn get_active_site_names() -> Result<Vec<String>, String> {
    let store = site_store().lock().map_err(|e| e.to_string())?;
    Ok(store.iter().filter(|s| s.active).map(|s| s.name.clone()).collect())
}

pub fn is_valid_site(unlocode: &str) -> bool {
    site_store()
        .lock()
        .map(|store| store.iter().any(|s| s.unlocode == unlocode && s.active))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_all_sites() {
        let result = list_sites(false).unwrap();
        assert!(result["count"].as_u64().unwrap() >= 20);
    }

    #[test]
    fn test_list_active_only() {
        let result = list_sites(true).unwrap();
        let sites = result["sites"].as_array().unwrap();
        for s in sites {
            assert!(s["active"].as_bool().unwrap());
        }
    }

    #[test]
    fn test_get_site_found() {
        let result = get_site("DEFRA").unwrap();
        assert_eq!(result["name"], "Frankfurt");
        assert_eq!(result["country_code"], "DE");
    }

    #[test]
    fn test_get_site_not_found() {
        assert!(get_site("NONEXISTENT").is_err());
    }

    #[test]
    fn test_activate_deactivate() {
        let activate_result = activate_site("ESMAD").unwrap();
        assert!(activate_result["active"].as_bool().unwrap());
        let deactivate_result = deactivate_site("ESMAD").unwrap();
        assert!(!deactivate_result["active"].as_bool().unwrap());
        // restore
        let _ = deactivate_site("ESMAD");
    }

    #[test]
    fn test_search_by_city() {
        let result = search_sites("Frankfurt").unwrap();
        assert_eq!(result["count"].as_u64().unwrap(), 1);
        assert_eq!(result["matches"][0]["unlocode"], "DEFRA");
    }

    #[test]
    fn test_search_by_country() {
        let result = search_sites("Netherlands").unwrap();
        assert!(result["count"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn test_search_by_country_code() {
        let result = search_sites("DE").unwrap();
        assert!(result["count"].as_u64().unwrap() >= 3);
    }

    #[test]
    fn test_get_active_site_codes() {
        let codes = get_active_site_codes().unwrap();
        assert!(codes.contains(&"DEFRA".to_string()));
        assert!(codes.contains(&"GBLON".to_string()));
    }

    #[test]
    fn test_is_valid_site() {
        assert!(is_valid_site("DEFRA"));
        assert!(!is_valid_site("NONEXISTENT"));
        assert!(!is_valid_site("ESMAD")); // not active by default
    }
}
