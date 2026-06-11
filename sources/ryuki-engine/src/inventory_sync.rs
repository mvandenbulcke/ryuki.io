use crate::models::*;
use chrono::Utc;
use std::collections::HashMap;

pub fn sync_inventory_sources() -> Result<Vec<InventoryItem>, String> {
    let mut items: Vec<InventoryItem> = Vec::new();

    let sources = vec![
        "vmware",
        "hyperv",
        "proxmox",
        "veeam",
        "zabbix",
        "cmdb-export",
    ];
    let now = Utc::now().to_rfc3339();

    for source in sources {
        items.extend(mock_inventory_for_source(source, &now));
    }

    Ok(items)
}

fn mock_inventory_for_source(source: &str, now: &str) -> Vec<InventoryItem> {
    let mut items: Vec<InventoryItem> = Vec::new();

    match source {
        "vmware" => {
            items.push(InventoryItem {
                id: "inv-vmware-001".to_string(),
                name: "vmware-cluster-gblon".into(),
                item_type: InventoryType::Cluster,
                owner: "vmware-team".into(),
                site: "GBLON".into(),
                environment: "production".into(),
                criticality: "critical".into(),
                last_synced: now.to_string(),
                source: "vmware".into(),
                stale: false,
                metadata: HashMap::from([
                    ("vcenter".into(), "vcenter-gblon (simulated)".into()),
                    ("ha_enabled".into(), "true".into()),
                ]),
            });
            items.push(InventoryItem {
                id: "inv-vmware-002".to_string(),
                name: "srv-gblon-web01".into(),
                item_type: InventoryType::Server,
                owner: "app-team".into(),
                site: "GBLON".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: now.to_string(),
                source: "vmware".into(),
                stale: false,
                metadata: HashMap::from([
                    ("cpu".into(), "4".into()),
                    ("memory_gb".into(), "16".into()),
                ]),
            });
        }
        "hyperv" => {
            items.push(InventoryItem {
                id: "inv-hyperv-001".to_string(),
                name: "hyperv-node-defra-01".into(),
                item_type: InventoryType::HypervisorHost,
                owner: "hyperv-team".into(),
                site: "DEFRA".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: now.to_string(),
                source: "hyperv".into(),
                stale: false,
                metadata: HashMap::new(),
            });
        }
        "proxmox" => {
            items.push(InventoryItem {
                id: "inv-proxmox-001".to_string(),
                name: "proxmox-node-frpar-01".into(),
                item_type: InventoryType::HypervisorHost,
                owner: "proxmox-team".into(),
                site: "FRPAR".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: now.to_string(),
                source: "proxmox".into(),
                stale: false,
                metadata: HashMap::new(),
            });
        }
        "veeam" => {
            items.push(InventoryItem {
                id: "inv-veeam-001".to_string(),
                name: "veeam-repo-gblon".into(),
                item_type: InventoryType::BackupRepository,
                owner: "backup-team".into(),
                site: "GBLON".into(),
                environment: "production".into(),
                criticality: "critical".into(),
                last_synced: now.to_string(),
                source: "veeam".into(),
                stale: false,
                metadata: HashMap::from([("capacity_tb".into(), "50".into())]),
            });
        }
        "zabbix" => {
            items.push(InventoryItem {
                id: "inv-zabbix-001".to_string(),
                name: "zabbix-server-main".into(),
                item_type: InventoryType::MonitoringHost,
                owner: "monitoring-team".into(),
                site: "GBLON".into(),
                environment: "production".into(),
                criticality: "critical".into(),
                last_synced: now.to_string(),
                source: "zabbix".into(),
                stale: false,
                metadata: HashMap::from([("version".into(), "7.4".into())]),
            });
        }
        "cmdb-export" => {
            items.push(InventoryItem {
                id: "inv-cmdb-001".to_string(),
                name: "ci-server-gblon-app01".into(),
                item_type: InventoryType::CmdbCi,
                owner: "service-owner".into(),
                site: "GBLON".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: now.to_string(),
                source: "cmdb-export".into(),
                stale: false,
                metadata: HashMap::from([("ci_class".into(), "Windows Server".into())]),
            });
        }
        _ => {}
    }

    items
}

pub fn reconcile_inventory(source: &str, items: &[InventoryItem]) -> Result<Vec<String>, String> {
    if items.is_empty() {
        return Ok(vec![format!(
            "DRY-RUN: No items to reconcile for source {}",
            source
        )]);
    }

    let mut gaps: Vec<String> = Vec::new();
    let source_items: Vec<&InventoryItem> = items.iter().filter(|i| i.source == source).collect();

    if source_items.is_empty() {
        gaps.push(format!(
            "DRY-RUN: Gap detected - no items from source {} in inventory",
            source
        ));
    }

    let source_len = source_items.len();
    for item in &source_items {
        if item.owner.is_empty() {
            gaps.push(format!(
                "DRY-RUN: Gap - inventory item {} has no owner",
                item.name
            ));
        }
        if item.stale {
            gaps.push(format!(
                "DRY-RUN: Gap - inventory item {} is stale (last synced: {})",
                item.name, item.last_synced
            ));
        }
    }

    if gaps.is_empty() {
        gaps.push(format!(
            "DRY-RUN: No gaps detected for source {} ({} items)",
            source, source_len
        ));
    }

    Ok(gaps)
}

pub fn detect_ownership_risks(items: &[InventoryItem]) -> Result<Vec<String>, String> {
    let mut risks: Vec<String> = Vec::new();

    for item in items {
        if item.owner.is_empty() {
            risks.push(format!(
                "RISK: {} (type: {}) has no owner assigned",
                item.name, item.item_type
            ));
        }
        if item.criticality == "critical" && item.stale {
            risks.push(format!(
                "RISK: Critical item {} is stale (last synced: {})",
                item.name, item.last_synced
            ));
        }
    }

    let unique_owners: std::collections::HashSet<&str> = items
        .iter()
        .filter_map(|i| {
            if i.owner.is_empty() {
                None
            } else {
                Some(i.owner.as_str())
            }
        })
        .collect();

    if unique_owners.len() == 1 {
        risks.push(format!(
            "DRY-RUN: Note - all {} inventory items share single owner {}, review for separation of duties",
            items.len(),
            unique_owners.iter().next().unwrap_or(&"unknown")
        ));
    }

    Ok(risks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_inventory_returns_items() {
        let items = sync_inventory_sources().unwrap();
        assert!(!items.is_empty());
        let sources: std::collections::HashSet<&str> =
            items.iter().map(|i| i.source.as_str()).collect();
        assert!(sources.contains("vmware"));
        assert!(sources.contains("hyperv"));
        assert!(sources.contains("proxmox"));
    }

    #[test]
    fn test_sync_inventory_all_static_dry_run() {
        let items = sync_inventory_sources().unwrap();
        for item in &items {
            assert!(!item.stale, "DRY-RUN items should start fresh");
            assert!(!item.last_synced.is_empty());
        }
    }

    #[test]
    fn test_reconcile_inventory_empty_items() {
        let empty: Vec<InventoryItem> = Vec::new();
        let result = reconcile_inventory("vmware", &empty).unwrap();
        assert!(result[0].contains("No items to reconcile"));
    }

    #[test]
    fn test_reconcile_inventory_detects_gaps() {
        let items = sync_inventory_sources().unwrap();
        let result = reconcile_inventory("vmware", &items).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_reconcile_inventory_unknown_source() {
        let items = sync_inventory_sources().unwrap();
        let result = reconcile_inventory("unknown-source", &items).unwrap();
        assert!(result.iter().any(|g| g.contains("no items from source")));
    }

    #[test]
    fn test_detect_ownership_risks_empty_owner() {
        let items = vec![InventoryItem {
            id: "inv-001".into(),
            name: "orphan-server".into(),
            item_type: InventoryType::Server,
            owner: "".into(),
            site: "DEFRA".into(),
            environment: "production".into(),
            criticality: "high".into(),
            last_synced: Utc::now().to_rfc3339(),
            source: "vmware".into(),
            stale: false,
            metadata: HashMap::new(),
        }];
        let risks = detect_ownership_risks(&items).unwrap();
        assert!(risks.iter().any(|r| r.contains("no owner")));
    }

    #[test]
    fn test_detect_ownership_risks_stale_critical() {
        let items = vec![InventoryItem {
            id: "inv-002".into(),
            name: "critical-server".into(),
            item_type: InventoryType::Server,
            owner: "team-a".into(),
            site: "GBLON".into(),
            environment: "production".into(),
            criticality: "critical".into(),
            last_synced: "2020-01-01T00:00:00Z".into(),
            source: "vmware".into(),
            stale: true,
            metadata: HashMap::new(),
        }];
        let risks = detect_ownership_risks(&items).unwrap();
        assert!(risks.iter().any(|r| r.contains("stale")));
    }

    #[test]
    fn test_sync_inventory_produces_mock_data_only() {
        let items = sync_inventory_sources().unwrap();
        for item in &items {
            assert!(item.name.contains("simulated") || !item.name.contains("real"));
            assert!(item.metadata.values().all(|v| !v.contains("credential")
                && !v.contains("password")
                && !v.contains("token")
                && !v.contains("secret")));
        }
    }
}
