use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

type NetworkStore = (Vec<SwitchPort>, Vec<VLAN>, Vec<PortReservation>);

static NETWORK_STORE: OnceLock<Mutex<NetworkStore>> = OnceLock::new();

fn network_store() -> &'static Mutex<NetworkStore> {
    NETWORK_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> NetworkStore {
    let mut ports = Vec::new();
    let mut vlans = Vec::new();

    for (site_idx, site) in ["LOVE", "BUR1"].iter().enumerate() {
        for sw_idx in 0..3 {
            let switch_name = format!("{}-sw-{:02}", site.to_lowercase(), sw_idx + 1);
            for p in 0..8 {
                let port_number = (p + 1) as u32;
                let status = if sw_idx == 0 && p < 2 {
                    "InUse"
                } else if sw_idx == 2 && p >= 6 {
                    "Disabled"
                } else {
                    "Available"
                };
                let vlan_id = match (sw_idx, p) {
                    (0, 0..=1) => 100 + (site_idx * 10) as u32,
                    (0, 2..=3) => 200 + (site_idx * 10) as u32,
                    (1, 0..=3) => 300 + (site_idx * 10) as u32,
                    _ => 1,
                };
                let vlan_name = match (sw_idx, p) {
                    (0, 0..=1) => format!("{}-mgmt", site.to_lowercase()),
                    (0, 2..=3) => format!("{}-prod", site.to_lowercase()),
                    (1, 0..=3) => format!("{}-dmz", site.to_lowercase()),
                    _ => "default".into(),
                };
                ports.push(SwitchPort {
                    id: format!(
                        "port-{}-{}-{}",
                        site.to_lowercase(),
                        switch_name,
                        port_number
                    ),
                    switch_name: switch_name.clone(),
                    port_number,
                    vlan_id,
                    vlan_name,
                    status: status.to_string(),
                    connected_device: if status == "InUse" {
                        Some(format!("{}-srv-{:02}", site.to_lowercase(), p + 1))
                    } else {
                        None
                    },
                    site: site.to_string(),
                });
            }
        }

        vlans.push(VLAN {
            id: format!("vlan-{}-mgmt", site.to_lowercase()),
            vlan_id: 100 + (site_idx * 10) as u32,
            vlan_name: format!("{}-mgmt", site.to_lowercase()),
            subnet: format!("10.{}.1.0/24", site_idx + 1),
            gateway: format!("10.{}.1.1", site_idx + 1),
            site: site.to_string(),
            purpose: "Management".into(),
            available_ips: 200,
        });
        vlans.push(VLAN {
            id: format!("vlan-{}-prod", site.to_lowercase()),
            vlan_id: 200 + (site_idx * 10) as u32,
            vlan_name: format!("{}-prod", site.to_lowercase()),
            subnet: format!("10.{}.2.0/24", site_idx + 1),
            gateway: format!("10.{}.2.1", site_idx + 1),
            site: site.to_string(),
            purpose: "Production".into(),
            available_ips: 180,
        });
        vlans.push(VLAN {
            id: format!("vlan-{}-dmz", site.to_lowercase()),
            vlan_id: 300 + (site_idx * 10) as u32,
            vlan_name: format!("{}-dmz", site.to_lowercase()),
            subnet: format!("10.{}.3.0/24", site_idx + 1),
            gateway: format!("10.{}.3.1", site_idx + 1),
            site: site.to_string(),
            purpose: "DMZ".into(),
            available_ips: 50,
        });
    }

    (ports, vlans, Vec::new())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwitchPort {
    pub id: String,
    pub switch_name: String,
    pub port_number: u32,
    pub vlan_id: u32,
    pub vlan_name: String,
    pub status: String,
    pub connected_device: Option<String>,
    pub site: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VLAN {
    pub id: String,
    pub vlan_id: u32,
    pub vlan_name: String,
    pub subnet: String,
    pub gateway: String,
    pub site: String,
    pub purpose: String,
    pub available_ips: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortReservation {
    pub reservation_id: String,
    pub site: String,
    pub resource_type: String,
    pub vlan_id: Option<u32>,
    pub port_ids: Vec<String>,
    pub ip_count: u32,
    pub purpose: String,
    pub status: String,
    pub created_at: String,
}

pub fn check_port_readiness(site: &str, port_count_needed: u32) -> Result<Value, String> {
    let store = network_store().lock().unwrap();
    let available: Vec<&SwitchPort> = store
        .0
        .iter()
        .filter(|p| p.site == site && p.status == "Available")
        .collect();

    let satisfied = available.len() as u32 >= port_count_needed;

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "port_count_needed": port_count_needed,
        "available_ports": available.len(),
        "satisfied": satisfied,
        "dry_run": true
    }))
}

pub fn check_vlan_readiness(
    site: &str,
    vlan_id_: u32,
    ip_count_needed: u32,
) -> Result<Value, String> {
    let store = network_store().lock().unwrap();
    let vlan = store
        .1
        .iter()
        .find(|v| v.site == site && v.vlan_id == vlan_id_)
        .ok_or_else(|| format!("VLAN {} not found at site {}", vlan_id_, site))?;

    let satisfied = vlan.available_ips >= ip_count_needed;

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "vlan_id": vlan_id_,
        "vlan_name": vlan.vlan_name,
        "available_ips": vlan.available_ips,
        "ip_count_needed": ip_count_needed,
        "satisfied": satisfied,
        "dry_run": true
    }))
}

pub fn reserve_ports(site: &str, count: u32, purpose: &str) -> Result<Value, String> {
    let mut store = network_store().lock().unwrap();

    let available_indices: Vec<usize> = store
        .0
        .iter()
        .enumerate()
        .filter(|(_, p)| p.site == site && p.status == "Available")
        .map(|(i, _)| i)
        .take(count as usize)
        .collect();

    if available_indices.len() < count as usize {
        return Err(format!(
            "Not enough available ports at site {}: needed {}, available {}",
            site,
            count,
            available_indices.len()
        ));
    }

    let reservation_id = format!(
        "presv-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let mut port_ids = Vec::new();
    for idx in &available_indices {
        store.0[*idx].status = "Reserved".to_string();
        port_ids.push(store.0[*idx].id.clone());
    }

    let reservation = PortReservation {
        reservation_id: reservation_id.clone(),
        site: site.to_string(),
        resource_type: "ports".into(),
        vlan_id: None,
        port_ids: port_ids.clone(),
        ip_count: 0,
        purpose: purpose.to_string(),
        status: "reserved".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    store.2.push(reservation);

    Ok(json!({
        "source": "dry-run",
        "reservation_id": reservation_id,
        "site": site,
        "resource_type": "ports",
        "reserved_count": port_ids.len(),
        "port_ids": port_ids,
        "purpose": purpose,
        "status": "reserved",
        "dry_run": true
    }))
}

pub fn reserve_ips(site: &str, vlan_id_: u32, count: u32, purpose: &str) -> Result<Value, String> {
    let mut store = network_store().lock().unwrap();

    let vlan_idx = store
        .1
        .iter()
        .position(|v| v.site == site && v.vlan_id == vlan_id_);

    let reservation_id = format!(
        "presv-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let satisfied = match vlan_idx {
        Some(idx) => {
            if store.1[idx].available_ips >= count {
                store.1[idx].available_ips -= count;
                true
            } else {
                false
            }
        }
        None => return Err(format!("VLAN {} not found at site {}", vlan_id_, site)),
    };

    if !satisfied {
        return Err(format!(
            "Not enough IPs available on VLAN {} at site {}: needed {}, available {}",
            store.1[vlan_idx.unwrap()].vlan_id,
            site,
            count,
            store.1[vlan_idx.unwrap()].available_ips
        ));
    }

    let reservation = PortReservation {
        reservation_id: reservation_id.clone(),
        site: site.to_string(),
        resource_type: "ips".into(),
        vlan_id: Some(vlan_id_),
        port_ids: Vec::new(),
        ip_count: count,
        purpose: purpose.to_string(),
        status: "reserved".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    store.2.push(reservation);

    Ok(json!({
        "source": "dry-run",
        "reservation_id": reservation_id,
        "site": site,
        "resource_type": "ips",
        "vlan_id": vlan_id_,
        "reserved_ip_count": count,
        "purpose": purpose,
        "status": "reserved",
        "dry_run": true
    }))
}

pub fn release_reservation(reservation_id: &str) -> Result<Value, String> {
    let mut store = network_store().lock().unwrap();

    let resv_idx = store
        .2
        .iter()
        .position(|r| r.reservation_id == reservation_id)
        .ok_or_else(|| format!("Reservation not found: {}", reservation_id))?;

    if store.2[resv_idx].status != "reserved" {
        return Err(format!(
            "Reservation {} is not in reserved state",
            reservation_id
        ));
    }

    let resv = store.2[resv_idx].clone();

    if resv.resource_type == "ports" {
        for port_id in &resv.port_ids {
            if let Some(port) = store.0.iter_mut().find(|p| p.id == *port_id)
                && port.status == "Reserved"
            {
                port.status = "Available".to_string();
            }
        }
    } else if resv.resource_type == "ips"
        && let Some(vlan) = store
            .1
            .iter_mut()
            .find(|v| v.site == resv.site && Some(v.vlan_id) == resv.vlan_id)
    {
        vlan.available_ips += resv.ip_count;
    }

    store.2[resv_idx].status = "released".to_string();

    Ok(json!({
        "source": "dry-run",
        "reservation_id": reservation_id,
        "status": "released",
        "dry_run": true
    }))
}

pub fn get_site_capacity(site: &str) -> Result<Value, String> {
    let store = network_store().lock().unwrap();

    let ports = &store.0;
    let vlans = &store.1;

    let total_ports = ports.iter().filter(|p| p.site == site).count();
    let available_ports = ports
        .iter()
        .filter(|p| p.site == site && p.status == "Available")
        .count();
    let reserved_ports = ports
        .iter()
        .filter(|p| p.site == site && p.status == "Reserved")
        .count();
    let in_use_ports = ports
        .iter()
        .filter(|p| p.site == site && p.status == "InUse")
        .count();
    let disabled_ports = ports
        .iter()
        .filter(|p| p.site == site && p.status == "Disabled")
        .count();

    let vlan_summaries: Vec<Value> = vlans
        .iter()
        .filter(|v| v.site == site)
        .map(|v| {
            json!({
                "vlan_id": v.vlan_id,
                "vlan_name": v.vlan_name,
                "subnet": v.subnet,
                "gateway": v.gateway,
                "purpose": v.purpose,
                "available_ips": v.available_ips,
            })
        })
        .collect();

    let switches: Vec<&str> = ports
        .iter()
        .filter(|p| p.site == site)
        .map(|p| p.switch_name.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "switches": switches,
        "ports": {
            "total": total_ports,
            "available": available_ports,
            "reserved": reserved_ports,
            "in_use": in_use_ports,
            "disabled": disabled_ports
        },
        "vlans": vlan_summaries,
        "dry_run": true
    }))
}

pub fn get_port_inventory(switch_name: &str) -> Result<Value, String> {
    let store = network_store().lock().unwrap();

    let matching: Vec<&SwitchPort> = store
        .0
        .iter()
        .filter(|p| p.switch_name == switch_name)
        .collect();

    if matching.is_empty() {
        return Err(format!("Switch not found: {}", switch_name));
    }

    Ok(json!({
        "source": "dry-run",
        "switch_name": switch_name,
        "total_ports": matching.len(),
        "ports": matching.iter().map(|p| json!({
            "id": p.id,
            "port_number": p.port_number,
            "vlan_id": p.vlan_id,
            "vlan_name": p.vlan_name,
            "status": p.status,
            "connected_device": p.connected_device,
            "site": p.site,
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn get_vlan_inventory(site: &str) -> Result<Value, String> {
    let store = network_store().lock().unwrap();

    let matching: Vec<&VLAN> = store.1.iter().filter(|v| v.site == site).collect();

    if matching.is_empty() {
        return Err(format!("No VLANs found for site: {}", site));
    }

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_vlans": matching.len(),
        "vlans": matching.iter().map(|v| json!({
            "id": v.id,
            "vlan_id": v.vlan_id,
            "vlan_name": v.vlan_name,
            "subnet": v.subnet,
            "gateway": v.gateway,
            "purpose": v.purpose,
            "available_ips": v.available_ips,
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_port_readiness_love() {
        let result = check_port_readiness("LOVE", 10).unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["site"], "LOVE");
        assert!(result["available_ports"].as_u64().unwrap() > 0);
        assert!(result["dry_run"].as_bool().unwrap());
    }

    #[test]
    fn test_check_vlan_readiness_found() {
        let result = check_vlan_readiness("LOVE", 100, 5).unwrap();
        assert_eq!(result["vlan_id"], 100);
        assert_eq!(result["satisfied"], true);
        assert!(result["available_ips"].as_u64().unwrap() >= 5);
    }

    #[test]
    fn test_check_vlan_readiness_not_found() {
        assert!(check_vlan_readiness("LOVE", 999, 1).is_err());
    }

    #[test]
    fn test_reserve_ports_success() {
        let result = reserve_ports("BUR1", 3, "vm-deployment").unwrap();
        assert_eq!(result["reserved_count"], 3);
        assert_eq!(result["status"], "reserved");
        assert!(!result["reservation_id"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_reserve_ports_insufficient() {
        assert!(reserve_ports("LOVE", 50, "too-many").is_err());
    }

    #[test]
    fn test_reserve_ips_success() {
        let result = reserve_ips("LOVE", 100, 10, "server-deploy").unwrap();
        assert_eq!(result["resource_type"], "ips");
        assert_eq!(result["reserved_ip_count"], 10);
    }

    #[test]
    fn test_release_reservation_success() {
        let reserve = reserve_ports("BUR1", 2, "test-release").unwrap();
        let resv_id = reserve["reservation_id"].as_str().unwrap().to_string();
        let release = release_reservation(&resv_id).unwrap();
        assert_eq!(release["status"], "released");
    }

    #[test]
    fn test_release_reservation_not_found() {
        assert!(release_reservation("presv-nonexistent").is_err());
    }

    #[test]
    fn test_get_site_capacity() {
        let result = get_site_capacity("LOVE").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert!(result["ports"]["total"].as_u64().unwrap() > 0);
        assert!(!result["vlans"].as_array().unwrap().is_empty());
        assert!(!result["switches"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_port_inventory_found() {
        let result = get_port_inventory("love-sw-01").unwrap();
        assert_eq!(result["switch_name"], "love-sw-01");
        assert!(result["total_ports"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_get_port_inventory_not_found() {
        assert!(get_port_inventory("nonexistent-sw").is_err());
    }

    #[test]
    fn test_get_vlan_inventory() {
        let result = get_vlan_inventory("BUR1").unwrap();
        assert_eq!(result["site"], "BUR1");
        assert!(result["total_vlans"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_release_reservation_restores_ports() {
        let initial = get_site_capacity("LOVE").unwrap();
        let initial_available = initial["ports"]["available"].as_u64().unwrap();

        let reserve = reserve_ports("LOVE", 2, "restore-test").unwrap();
        let mid = get_site_capacity("LOVE").unwrap();
        let mid_available = mid["ports"]["available"].as_u64().unwrap();
        assert_eq!(mid_available, initial_available - 2);

        let resv_id = reserve["reservation_id"].as_str().unwrap().to_string();
        release_reservation(&resv_id).unwrap();
        let after = get_site_capacity("LOVE").unwrap();
        let after_available = after["ports"]["available"].as_u64().unwrap();
        assert_eq!(after_available, initial_available);
    }
}
