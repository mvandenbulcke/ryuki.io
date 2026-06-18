//! Pure network-readiness engine — no I/O, no interior-mutable state.
//!
//! All functions take data by reference and return values derived from the
//! inputs alone.  Persistence is owned by `ryuki-api/src/repos/network_readiness.rs`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

// ─── Domain types ─────────────────────────────────────────────────────────────

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

// ─── Read helpers (pure, no DB) ───────────────────────────────────────────────

/// Check whether `port_count_needed` Available ports exist at `site`.
/// Returns a readiness summary JSON value.
pub fn check_port_readiness(site: &str, port_count_needed: u32, ports: &[SwitchPort]) -> Value {
    let available = ports
        .iter()
        .filter(|p| p.site == site && p.status == "Available")
        .count();

    json!({
        "site": site,
        "port_count_needed": port_count_needed,
        "available_ports": available,
        "satisfied": available as u32 >= port_count_needed,
    })
}

/// Check whether a VLAN has enough available IPs.
/// Returns `Err` if the VLAN is not found.
pub fn check_vlan_readiness(
    site: &str,
    vlan_id_: u32,
    ip_count_needed: u32,
    vlans: &[VLAN],
) -> Result<Value, String> {
    let vlan = vlans
        .iter()
        .find(|v| v.site == site && v.vlan_id == vlan_id_)
        .ok_or_else(|| format!("VLAN {} not found at site {}", vlan_id_, site))?;

    Ok(json!({
        "site": site,
        "vlan_id": vlan_id_,
        "vlan_name": vlan.vlan_name,
        "available_ips": vlan.available_ips,
        "ip_count_needed": ip_count_needed,
        "satisfied": vlan.available_ips >= ip_count_needed,
    }))
}

/// Build the site-capacity summary from the provided slices (no DB access).
pub fn build_site_capacity(site: &str, ports: &[SwitchPort], vlans: &[VLAN]) -> Value {
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

    json!({
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
    })
}

/// Build the port-inventory JSON for a switch (no DB access).
/// Returns `Err` if no ports found for that switch.
pub fn build_port_inventory(switch_name: &str, ports: &[SwitchPort]) -> Result<Value, String> {
    let matching: Vec<&SwitchPort> = ports
        .iter()
        .filter(|p| p.switch_name == switch_name)
        .collect();

    if matching.is_empty() {
        return Err(format!("Switch not found: {}", switch_name));
    }

    Ok(json!({
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
    }))
}

/// Build the VLAN-inventory JSON for a site (no DB access).
/// Returns `Err` if no VLANs found.
pub fn build_vlan_inventory(site: &str, vlans: &[VLAN]) -> Result<Value, String> {
    let matching: Vec<&VLAN> = vlans.iter().filter(|v| v.site == site).collect();

    if matching.is_empty() {
        return Err(format!("No VLANs found for site: {}", site));
    }

    Ok(json!({
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
    }))
}

// ─── Mutation helpers (pure logic, used by repo to build request inputs) ──────

/// Generate a fresh `presv-<short-uuid>` reservation ID.
pub fn new_reservation_id() -> String {
    format!(
        "presv-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    )
}

// ─── Engine unit tests (pure logic — no DB, no store) ─────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_ports() -> Vec<SwitchPort> {
        vec![
            SwitchPort {
                id: "p1".into(), switch_name: "sw-01".into(), port_number: 1,
                vlan_id: 100, vlan_name: "mgmt".into(), status: "Available".into(),
                connected_device: None, site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p2".into(), switch_name: "sw-01".into(), port_number: 2,
                vlan_id: 100, vlan_name: "mgmt".into(), status: "Available".into(),
                connected_device: None, site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p3".into(), switch_name: "sw-01".into(), port_number: 3,
                vlan_id: 100, vlan_name: "mgmt".into(), status: "InUse".into(),
                connected_device: Some("srv-01".into()), site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p4".into(), switch_name: "sw-02".into(), port_number: 1,
                vlan_id: 200, vlan_name: "prod".into(), status: "Reserved".into(),
                connected_device: None, site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p5".into(), switch_name: "sw-02".into(), port_number: 2,
                vlan_id: 200, vlan_name: "prod".into(), status: "Disabled".into(),
                connected_device: None, site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p6".into(), switch_name: "sw-03".into(), port_number: 1,
                vlan_id: 300, vlan_name: "dmz".into(), status: "Available".into(),
                connected_device: None, site: "GBLON".into(),
            },
        ]
    }

    fn make_vlans() -> Vec<VLAN> {
        vec![
            VLAN {
                id: "v1".into(), vlan_id: 100, vlan_name: "mgmt".into(),
                subnet: "10.1.1.0/24".into(), gateway: "10.1.1.1".into(),
                site: "DEFRA".into(), purpose: "Management".into(), available_ips: 200,
            },
            VLAN {
                id: "v2".into(), vlan_id: 200, vlan_name: "prod".into(),
                subnet: "10.1.2.0/24".into(), gateway: "10.1.2.1".into(),
                site: "DEFRA".into(), purpose: "Production".into(), available_ips: 10,
            },
            VLAN {
                id: "v3".into(), vlan_id: 300, vlan_name: "dmz".into(),
                subnet: "10.2.3.0/24".into(), gateway: "10.2.3.1".into(),
                site: "GBLON".into(), purpose: "DMZ".into(), available_ips: 5,
            },
        ]
    }

    // ── check_port_readiness ──

    #[test]
    fn port_readiness_satisfied() {
        let ports = make_ports();
        let result = check_port_readiness("DEFRA", 2, &ports);
        assert_eq!(result["satisfied"], true);
        assert_eq!(result["available_ports"], 2u64);
    }

    #[test]
    fn port_readiness_not_satisfied() {
        let ports = make_ports();
        let result = check_port_readiness("DEFRA", 10, &ports);
        assert_eq!(result["satisfied"], false);
    }

    #[test]
    fn port_readiness_empty_site() {
        let ports = make_ports();
        let result = check_port_readiness("NOWHERE", 1, &ports);
        assert_eq!(result["satisfied"], false);
        assert_eq!(result["available_ports"], 0u64);
    }

    // ── check_vlan_readiness ──

    #[test]
    fn vlan_readiness_satisfied() {
        let vlans = make_vlans();
        let r = check_vlan_readiness("DEFRA", 100, 5, &vlans).unwrap();
        assert_eq!(r["satisfied"], true);
        assert_eq!(r["available_ips"], 200u64);
    }

    #[test]
    fn vlan_readiness_insufficient() {
        let vlans = make_vlans();
        let r = check_vlan_readiness("DEFRA", 200, 100, &vlans).unwrap();
        assert_eq!(r["satisfied"], false);
    }

    #[test]
    fn vlan_readiness_not_found() {
        let vlans = make_vlans();
        assert!(check_vlan_readiness("DEFRA", 999, 1, &vlans).is_err());
    }

    // ── build_site_capacity ──

    #[test]
    fn site_capacity_counts() {
        let ports = make_ports();
        let vlans = make_vlans();
        let r = build_site_capacity("DEFRA", &ports, &vlans);
        assert_eq!(r["ports"]["available"], 2u64);
        assert_eq!(r["ports"]["in_use"], 1u64);
        assert_eq!(r["ports"]["reserved"], 1u64);
        assert_eq!(r["ports"]["disabled"], 1u64);
        assert_eq!(r["ports"]["total"], 5u64);
        let vlan_arr = r["vlans"].as_array().unwrap();
        assert_eq!(vlan_arr.len(), 2); // DEFRA has 2 vlans
    }

    #[test]
    fn site_capacity_different_site() {
        let ports = make_ports();
        let vlans = make_vlans();
        let r = build_site_capacity("GBLON", &ports, &vlans);
        assert_eq!(r["ports"]["total"], 1u64);
        assert_eq!(r["ports"]["available"], 1u64);
    }

    // ── build_port_inventory ──

    #[test]
    fn port_inventory_found() {
        let ports = make_ports();
        let r = build_port_inventory("sw-01", &ports).unwrap();
        assert_eq!(r["total_ports"], 3u64);
        assert_eq!(r["switch_name"], "sw-01");
    }

    #[test]
    fn port_inventory_not_found() {
        let ports = make_ports();
        assert!(build_port_inventory("nonexistent", &ports).is_err());
    }

    // ── build_vlan_inventory ──

    #[test]
    fn vlan_inventory_found() {
        let vlans = make_vlans();
        let r = build_vlan_inventory("DEFRA", &vlans).unwrap();
        assert_eq!(r["total_vlans"], 2u64);
        assert_eq!(r["site"], "DEFRA");
    }

    #[test]
    fn vlan_inventory_not_found() {
        let vlans = make_vlans();
        assert!(build_vlan_inventory("NOWHERE", &vlans).is_err());
    }

    // ── capacity math / reservation logic ──

    // NOTE: the insufficient-capacity and release-idempotency GUARDS are
    // enforced at the SQL layer in repos/network_readiness.rs (the FOR UPDATE
    // SKIP LOCKED count check, the atomic `available_ips >= $count` decrement,
    // and the `status = 'released'` short-circuit) and are covered by
    // network_readiness_db_tests. They are deliberately NOT asserted here with
    // tautological in-test re-implementations that would pass even if the
    // production logic were deleted.

    #[test]
    fn release_restore_arithmetic_ports() {
        // Simulate: 2 Available ports are reserved, then released → count back to 2.
        // We track the ids that were flipped so the restore step only touches them
        // (other ports may already be Reserved in the test data and must not be affected).
        let mut ports = make_ports();
        let initially_available = ports.iter().filter(|p| p.site == "DEFRA" && p.status == "Available").count();
        assert_eq!(initially_available, 2, "test data: 2 Available DEFRA ports");

        // Collect the ids of Available ports before mutating.
        let to_reserve: Vec<String> = ports
            .iter()
            .filter(|p| p.site == "DEFRA" && p.status == "Available")
            .map(|p| p.id.clone())
            .collect();

        // "reserve" exactly those ports
        for p in ports.iter_mut().filter(|p| to_reserve.contains(&p.id)) {
            p.status = "Reserved".into();
        }

        let after_reserve = ports.iter().filter(|p| p.site == "DEFRA" && p.status == "Available").count();
        assert_eq!(after_reserve, 0, "no Available DEFRA ports after reservation");

        // "release" — restore only the ports we reserved
        for p in ports.iter_mut().filter(|p| to_reserve.contains(&p.id)) {
            p.status = "Available".into();
        }
        let after_release = ports.iter().filter(|p| p.site == "DEFRA" && p.status == "Available").count();
        assert_eq!(after_release, initially_available, "count restored to initial");
    }

    #[test]
    fn release_restore_arithmetic_ips() {
        let mut vlans = make_vlans();
        let vlan = vlans.iter_mut().find(|v| v.site == "DEFRA" && v.vlan_id == 100).unwrap();
        let initial = vlan.available_ips;
        // reserve 5
        vlan.available_ips -= 5;
        assert_eq!(vlan.available_ips, initial - 5);
        // release 5
        vlan.available_ips += 5;
        assert_eq!(vlan.available_ips, initial);
    }

    #[test]
    fn new_reservation_id_format() {
        let id = new_reservation_id();
        assert!(id.starts_with("presv-"), "must start with presv-");
        assert!(id.len() > 6, "must have content after prefix");
    }
}
