//! Pure network-readiness engine — no I/O, no interior-mutable state.
//!
//! All functions take data by reference and return values derived from the
//! inputs alone.  Persistence is owned by `ryuki-api/src/repos/network_readiness.rs`.

use serde::{Deserialize, Serialize};
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

/// A minimized readiness decision. It intentionally carries no site, switch,
/// port, VLAN, subnet, gateway, device, or exact-capacity fields.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessProjection {
    pub satisfied: bool,
    pub capacity_band: String,
    pub review_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

/// Combined minimized response for the readiness endpoint.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkReadinessProjection {
    pub port_readiness: ReadinessProjection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_readiness: Option<ReadinessProjection>,
}

/// Coarse site-capacity response. Exact counts and topology are deliberately
/// unavailable through this DTO.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteCapacityProjection {
    pub port_capacity_band: String,
    pub vlan_capacity_band: String,
    pub review_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

/// Redacted response shared by the former raw inventory endpoints.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryProjection {
    pub inventory_present: bool,
    pub availability_band: String,
    pub review_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

fn requested_capacity_band(available: u32, requested: u32) -> &'static str {
    if requested == 0 || available >= requested {
        "sufficient"
    } else if available == 0 {
        "none"
    } else {
        "limited"
    }
}

fn inventory_availability_band(total: usize, available: usize) -> &'static str {
    if total == 0 {
        "unknown"
    } else if available == 0 {
        "exhausted"
    } else {
        "available"
    }
}

fn readiness_projection(available: u32, requested: u32) -> ReadinessProjection {
    let satisfied = available >= requested;
    ReadinessProjection {
        satisfied,
        capacity_band: requested_capacity_band(available, requested).to_string(),
        review_required: !satisfied,
        blocked_reason: (!satisfied).then(|| "insufficient-capacity".to_string()),
    }
}

/// Check whether `port_count_needed` Available ports exist at `site`.
/// Returns only a coarse decision projection, never the exact count.
pub fn check_port_readiness(
    site: &str,
    port_count_needed: u32,
    ports: &[SwitchPort],
) -> ReadinessProjection {
    let available = ports
        .iter()
        .filter(|p| p.site == site && p.status == "Available")
        .count() as u32;

    readiness_projection(available, port_count_needed)
}

/// Check whether a VLAN has enough available IPs.
/// Returns a generic error if the resource is not found, without echoing a
/// network identifier or site value.
pub fn check_vlan_readiness(
    site: &str,
    vlan_id_: u32,
    ip_count_needed: u32,
    vlans: &[VLAN],
) -> Result<ReadinessProjection, String> {
    let vlan = vlans
        .iter()
        .find(|v| v.site == site && v.vlan_id == vlan_id_)
        .ok_or_else(|| "network inventory unavailable".to_string())?;

    Ok(readiness_projection(vlan.available_ips, ip_count_needed))
}

/// Build the complete minimized readiness response.
pub fn build_network_readiness(
    site: &str,
    port_count_needed: u32,
    vlan_id: Option<u32>,
    ip_count_needed: u32,
    ports: &[SwitchPort],
    vlans: &[VLAN],
) -> NetworkReadinessProjection {
    let port_readiness = check_port_readiness(site, port_count_needed, ports);
    let vlan_readiness = vlan_id.map(|id| {
        check_vlan_readiness(site, id, ip_count_needed, vlans).unwrap_or_else(|_| {
            ReadinessProjection {
                satisfied: false,
                capacity_band: "unknown".to_string(),
                review_required: true,
                blocked_reason: Some("inventory-unavailable".to_string()),
            }
        })
    });
    NetworkReadinessProjection {
        port_readiness,
        vlan_readiness,
    }
}

/// Build a coarse site-capacity policy projection (no DB access).
pub fn build_site_capacity(
    site: &str,
    ports: &[SwitchPort],
    vlans: &[VLAN],
) -> SiteCapacityProjection {
    let total_ports = ports.iter().filter(|p| p.site == site).count();
    let available_ports = ports
        .iter()
        .filter(|p| p.site == site && p.status == "Available")
        .count();

    let total_vlans = vlans.iter().filter(|v| v.site == site).count();
    let available_vlans = vlans
        .iter()
        .filter(|v| v.site == site && v.available_ips > 0)
        .count();
    let review_required =
        total_ports == 0 || available_ports == 0 || total_vlans == 0 || available_vlans == 0;

    SiteCapacityProjection {
        port_capacity_band: inventory_availability_band(total_ports, available_ports).to_string(),
        vlan_capacity_band: inventory_availability_band(total_vlans, available_vlans).to_string(),
        review_required,
        blocked_reason: review_required.then(|| "capacity-review-required".to_string()),
    }
}

/// Build a redacted port-inventory projection (no DB access).
/// Returns a generic error if no scoped rows exist for the requested switch.
pub fn build_port_inventory(
    switch_name: &str,
    ports: &[SwitchPort],
) -> Result<InventoryProjection, String> {
    let total = ports
        .iter()
        .filter(|p| p.switch_name == switch_name)
        .count();

    if total == 0 {
        return Err("network inventory unavailable".to_string());
    }
    let available = ports
        .iter()
        .filter(|p| p.switch_name == switch_name && p.status == "Available")
        .count();
    let review_required = available == 0;

    Ok(InventoryProjection {
        inventory_present: true,
        availability_band: inventory_availability_band(total, available).to_string(),
        review_required,
        blocked_reason: review_required.then(|| "capacity-review-required".to_string()),
    })
}

/// Build a redacted VLAN-inventory projection (no DB access).
/// Returns a generic error if no scoped rows exist for the requested site.
pub fn build_vlan_inventory(site: &str, vlans: &[VLAN]) -> Result<InventoryProjection, String> {
    let total = vlans.iter().filter(|v| v.site == site).count();

    if total == 0 {
        return Err("network inventory unavailable".to_string());
    }
    let available = vlans
        .iter()
        .filter(|v| v.site == site && v.available_ips > 0)
        .count();
    let review_required = available == 0;

    Ok(InventoryProjection {
        inventory_present: true,
        availability_band: inventory_availability_band(total, available).to_string(),
        review_required,
        blocked_reason: review_required.then(|| "capacity-review-required".to_string()),
    })
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
                id: "p1".into(),
                switch_name: "sw-01".into(),
                port_number: 1,
                vlan_id: 100,
                vlan_name: "mgmt".into(),
                status: "Available".into(),
                connected_device: None,
                site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p2".into(),
                switch_name: "sw-01".into(),
                port_number: 2,
                vlan_id: 100,
                vlan_name: "mgmt".into(),
                status: "Available".into(),
                connected_device: None,
                site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p3".into(),
                switch_name: "sw-01".into(),
                port_number: 3,
                vlan_id: 100,
                vlan_name: "mgmt".into(),
                status: "InUse".into(),
                connected_device: Some("srv-01".into()),
                site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p4".into(),
                switch_name: "sw-02".into(),
                port_number: 1,
                vlan_id: 200,
                vlan_name: "prod".into(),
                status: "Reserved".into(),
                connected_device: None,
                site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p5".into(),
                switch_name: "sw-02".into(),
                port_number: 2,
                vlan_id: 200,
                vlan_name: "prod".into(),
                status: "Disabled".into(),
                connected_device: None,
                site: "DEFRA".into(),
            },
            SwitchPort {
                id: "p6".into(),
                switch_name: "sw-03".into(),
                port_number: 1,
                vlan_id: 300,
                vlan_name: "dmz".into(),
                status: "Available".into(),
                connected_device: None,
                site: "GBLON".into(),
            },
        ]
    }

    fn make_vlans() -> Vec<VLAN> {
        vec![
            VLAN {
                id: "v1".into(),
                vlan_id: 100,
                vlan_name: "mgmt".into(),
                subnet: "10.1.1.0/24".into(),
                gateway: "10.1.1.1".into(),
                site: "DEFRA".into(),
                purpose: "Management".into(),
                available_ips: 200,
            },
            VLAN {
                id: "v2".into(),
                vlan_id: 200,
                vlan_name: "prod".into(),
                subnet: "10.1.2.0/24".into(),
                gateway: "10.1.2.1".into(),
                site: "DEFRA".into(),
                purpose: "Production".into(),
                available_ips: 10,
            },
            VLAN {
                id: "v3".into(),
                vlan_id: 300,
                vlan_name: "dmz".into(),
                subnet: "10.2.3.0/24".into(),
                gateway: "10.2.3.1".into(),
                site: "GBLON".into(),
                purpose: "DMZ".into(),
                available_ips: 5,
            },
        ]
    }

    // ── check_port_readiness ──

    #[test]
    fn port_readiness_satisfied() {
        let ports = make_ports();
        let result = check_port_readiness("DEFRA", 2, &ports);
        assert!(result.satisfied);
        assert_eq!(result.capacity_band, "sufficient");
        assert!(!result.review_required);
    }

    #[test]
    fn port_readiness_not_satisfied() {
        let ports = make_ports();
        let result = check_port_readiness("DEFRA", 10, &ports);
        assert!(!result.satisfied);
        assert_eq!(result.capacity_band, "limited");
        assert!(result.review_required);
    }

    #[test]
    fn port_readiness_empty_site() {
        let ports = make_ports();
        let result = check_port_readiness("NOWHERE", 1, &ports);
        assert!(!result.satisfied);
        assert_eq!(result.capacity_band, "none");
    }

    // ── check_vlan_readiness ──

    #[test]
    fn vlan_readiness_satisfied() {
        let vlans = make_vlans();
        let r = check_vlan_readiness("DEFRA", 100, 5, &vlans).unwrap();
        assert!(r.satisfied);
        assert_eq!(r.capacity_band, "sufficient");
    }

    #[test]
    fn vlan_readiness_insufficient() {
        let vlans = make_vlans();
        let r = check_vlan_readiness("DEFRA", 200, 100, &vlans).unwrap();
        assert!(!r.satisfied);
        assert_eq!(r.capacity_band, "limited");
    }

    #[test]
    fn vlan_readiness_not_found() {
        let vlans = make_vlans();
        let error = check_vlan_readiness("DEFRA", 999, 1, &vlans).unwrap_err();
        assert_eq!(error, "network inventory unavailable");
        assert!(!error.contains("DEFRA"));
        assert!(!error.contains("999"));
    }

    // ── build_site_capacity ──

    #[test]
    fn site_capacity_is_coarse() {
        let ports = make_ports();
        let vlans = make_vlans();
        let r = build_site_capacity("DEFRA", &ports, &vlans);
        assert_eq!(r.port_capacity_band, "available");
        assert_eq!(r.vlan_capacity_band, "available");
        assert!(!r.review_required);
    }

    #[test]
    fn site_capacity_different_site() {
        let ports = make_ports();
        let vlans = make_vlans();
        let r = build_site_capacity("GBLON", &ports, &vlans);
        assert_eq!(r.port_capacity_band, "available");
        assert_eq!(r.vlan_capacity_band, "available");
    }

    // ── build_port_inventory ──

    #[test]
    fn port_inventory_found() {
        let ports = make_ports();
        let r = build_port_inventory("sw-01", &ports).unwrap();
        assert!(r.inventory_present);
        assert_eq!(r.availability_band, "available");
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
        assert!(r.inventory_present);
        assert_eq!(r.availability_band, "available");
    }

    #[test]
    fn vlan_inventory_not_found() {
        let vlans = make_vlans();
        assert!(build_vlan_inventory("NOWHERE", &vlans).is_err());
    }

    fn assert_no_forbidden_topology(value: &serde_json::Value) {
        const FORBIDDEN_KEYS: &[&str] = &[
            "id",
            "site",
            "switch_name",
            "switchName",
            "switches",
            "port_number",
            "portNumber",
            "ports",
            "total_ports",
            "totalPorts",
            "available_ports",
            "availablePorts",
            "vlan_id",
            "vlanId",
            "vlan_name",
            "vlanName",
            "vlans",
            "total_vlans",
            "totalVlans",
            "available_ips",
            "availableIps",
            "connected_device",
            "connectedDevice",
            "subnet",
            "gateway",
            "purpose",
        ];
        const FORBIDDEN_VALUES: &[&str] = &[
            "DEFRA",
            "sw-01",
            "mgmt",
            "srv-01",
            "10.1.1.0/24",
            "10.1.1.1",
            "Management",
        ];

        match value {
            serde_json::Value::Object(map) => {
                for (key, nested) in map {
                    assert!(
                        !FORBIDDEN_KEYS.contains(&key.as_str()),
                        "forbidden topology key serialized: {key} in {value}"
                    );
                    assert_no_forbidden_topology(nested);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_forbidden_topology(item);
                }
            }
            serde_json::Value::String(text) => assert!(
                !FORBIDDEN_VALUES.contains(&text.as_str()),
                "forbidden topology value serialized: {text} in {value}"
            ),
            _ => {}
        }
    }

    #[test]
    fn every_network_read_projection_rejects_raw_topology_keys_and_values() {
        let ports = make_ports();
        let vlans = make_vlans();
        let projections = [
            serde_json::to_value(build_network_readiness(
                "DEFRA",
                2,
                Some(100),
                5,
                &ports,
                &vlans,
            ))
            .unwrap(),
            serde_json::to_value(build_site_capacity("DEFRA", &ports, &vlans)).unwrap(),
            serde_json::to_value(build_port_inventory("sw-01", &ports).unwrap()).unwrap(),
            serde_json::to_value(build_vlan_inventory("DEFRA", &vlans).unwrap()).unwrap(),
        ];

        for projection in projections {
            assert_no_forbidden_topology(&projection);
        }
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
        let initially_available = ports
            .iter()
            .filter(|p| p.site == "DEFRA" && p.status == "Available")
            .count();
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

        let after_reserve = ports
            .iter()
            .filter(|p| p.site == "DEFRA" && p.status == "Available")
            .count();
        assert_eq!(
            after_reserve, 0,
            "no Available DEFRA ports after reservation"
        );

        // "release" — restore only the ports we reserved
        for p in ports.iter_mut().filter(|p| to_reserve.contains(&p.id)) {
            p.status = "Available".into();
        }
        let after_release = ports
            .iter()
            .filter(|p| p.site == "DEFRA" && p.status == "Available")
            .count();
        assert_eq!(
            after_release, initially_available,
            "count restored to initial"
        );
    }

    #[test]
    fn release_restore_arithmetic_ips() {
        let mut vlans = make_vlans();
        let vlan = vlans
            .iter_mut()
            .find(|v| v.site == "DEFRA" && v.vlan_id == 100)
            .unwrap();
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
