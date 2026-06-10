use crate::models::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Returns a sanitized dry-run result summary that excludes raw parameter maps.
fn sanitized_dry_run_result(adapter_name: &str, operation: &str) -> String {
    format!("DRY-RUN: {adapter_name} operation '{operation}' simulated")
}

pub trait ProviderAdapter {
    fn connect(&self) -> Result<(), String>;
    fn health_check(&self) -> Result<AdapterStatus, String>;
    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String>;
    fn execute(&self, operation: &str, params: &HashMap<String, String>) -> Result<String, String>;
    fn disconnect(&self) -> Result<(), String>;
}

pub struct VMwareAdapter {
    pub config: AdapterConfig,
}

impl VMwareAdapter {
    pub fn static_dry_run() -> Self {
        VMwareAdapter {
            config: AdapterConfig {
                id: format!(
                    "ad-{}",
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("unknown")
                ),
                adapter_type: AdapterType::VMware,
                name: "vCenter SIMULATED".into(),
                endpoint: "https://vcenter.example.invalid (DRY-RUN)".into(),
                status: AdapterStatus::Configured,
                readiness: ReadinessState::Configured,
                api_version: "8.0.3 (simulated)".into(),
                health_check_at: None,
                stale: false,
                metadata: HashMap::from([("dry_run".into(), "true".into())]),
            },
        }
    }
}

impl ProviderAdapter for VMwareAdapter {
    fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterStatus, String> {
        Ok(AdapterStatus::Connected)
    }

    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String> {
        let now = Utc::now().to_rfc3339();
        Ok(vec![
            InventoryItem {
                id: "vmware-mock-001".into(),
                name: "vmware-cluster-mock".into(),
                item_type: InventoryType::Cluster,
                owner: "vmware-team".into(),
                site: "BUR1".into(),
                environment: "production".into(),
                criticality: "critical".into(),
                last_synced: now.clone(),
                source: "vmware".into(),
                stale: false,
                metadata: HashMap::from([("simulated".into(), "true".into())]),
            },
            InventoryItem {
                id: "vmware-mock-002".into(),
                name: "srv-mock-vm01".into(),
                item_type: InventoryType::Server,
                owner: "test-team".into(),
                site: "BUR1".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: now,
                source: "vmware".into(),
                stale: false,
                metadata: HashMap::from([("simulated".into(), "true".into())]),
            },
        ])
    }

    fn execute(
        &self,
        operation: &str,
        _params: &HashMap<String, String>,
    ) -> Result<String, String> {
        Ok(sanitized_dry_run_result("VMware", operation))
    }

    fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct HyperVAdapter {
    pub config: AdapterConfig,
}

impl HyperVAdapter {
    pub fn static_dry_run() -> Self {
        HyperVAdapter {
            config: AdapterConfig {
                id: format!(
                    "ad-{}",
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("unknown")
                ),
                adapter_type: AdapterType::HyperV,
                name: "Hyper-V SIMULATED".into(),
                endpoint: "https://hyperv-host.example.invalid (DRY-RUN)".into(),
                status: AdapterStatus::Configured,
                readiness: ReadinessState::Configured,
                api_version: "2022 (simulated)".into(),
                health_check_at: None,
                stale: false,
                metadata: HashMap::from([("dry_run".into(), "true".into())]),
            },
        }
    }
}

impl ProviderAdapter for HyperVAdapter {
    fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterStatus, String> {
        Ok(AdapterStatus::Connected)
    }

    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String> {
        let now = Utc::now().to_rfc3339();
        Ok(vec![InventoryItem {
            id: "hyperv-mock-001".into(),
            name: "hyperv-host-mock".into(),
            item_type: InventoryType::HypervisorHost,
            owner: "hyperv-team".into(),
            site: "LOVE".into(),
            environment: "production".into(),
            criticality: "high".into(),
            last_synced: now.clone(),
            source: "hyperv".into(),
            stale: false,
            metadata: HashMap::from([("simulated".into(), "true".into())]),
        }])
    }

    fn execute(
        &self,
        operation: &str,
        _params: &HashMap<String, String>,
    ) -> Result<String, String> {
        Ok(sanitized_dry_run_result("Hyper-V", operation))
    }

    fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct ProxmoxAdapter {
    pub config: AdapterConfig,
}

impl ProxmoxAdapter {
    pub fn static_dry_run() -> Self {
        ProxmoxAdapter {
            config: AdapterConfig {
                id: format!(
                    "ad-{}",
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("unknown")
                ),
                adapter_type: AdapterType::Proxmox,
                name: "Proxmox SIMULATED".into(),
                endpoint: "https://proxmox-node.example.invalid (DRY-RUN)".into(),
                status: AdapterStatus::Configured,
                readiness: ReadinessState::Configured,
                api_version: "8.2 (simulated)".into(),
                health_check_at: None,
                stale: false,
                metadata: HashMap::from([("dry_run".into(), "true".into())]),
            },
        }
    }
}

impl ProviderAdapter for ProxmoxAdapter {
    fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterStatus, String> {
        Ok(AdapterStatus::Connected)
    }

    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String> {
        let now = Utc::now().to_rfc3339();
        Ok(vec![InventoryItem {
            id: "proxmox-mock-001".into(),
            name: "proxmox-node-mock".into(),
            item_type: InventoryType::HypervisorHost,
            owner: "proxmox-team".into(),
            site: "ALBI".into(),
            environment: "production".into(),
            criticality: "high".into(),
            last_synced: now.clone(),
            source: "proxmox".into(),
            stale: false,
            metadata: HashMap::from([("simulated".into(), "true".into())]),
        }])
    }

    fn execute(
        &self,
        operation: &str,
        _params: &HashMap<String, String>,
    ) -> Result<String, String> {
        Ok(sanitized_dry_run_result("Proxmox", operation))
    }

    fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct VeeamAdapter {
    pub config: AdapterConfig,
}

impl VeeamAdapter {
    pub fn static_dry_run() -> Self {
        VeeamAdapter {
            config: AdapterConfig {
                id: format!(
                    "ad-{}",
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("unknown")
                ),
                adapter_type: AdapterType::Veeam,
                name: "Veeam B&R SIMULATED".into(),
                endpoint: "https://veeam-em.example.invalid (DRY-RUN)".into(),
                status: AdapterStatus::Configured,
                readiness: ReadinessState::Configured,
                api_version: "12.2 (simulated)".into(),
                health_check_at: None,
                stale: false,
                metadata: HashMap::from([("dry_run".into(), "true".into())]),
            },
        }
    }
}

impl ProviderAdapter for VeeamAdapter {
    fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterStatus, String> {
        Ok(AdapterStatus::Connected)
    }

    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String> {
        let now = Utc::now().to_rfc3339();
        Ok(vec![InventoryItem {
            id: "veeam-mock-001".into(),
            name: "veeam-repo-mock".into(),
            item_type: InventoryType::BackupRepository,
            owner: "backup-team".into(),
            site: "BUR1".into(),
            environment: "production".into(),
            criticality: "critical".into(),
            last_synced: now.clone(),
            source: "veeam".into(),
            stale: false,
            metadata: HashMap::from([
                ("simulated".into(), "true".into()),
                ("capacity_tb".into(), "50".into()),
            ]),
        }])
    }

    fn execute(
        &self,
        operation: &str,
        _params: &HashMap<String, String>,
    ) -> Result<String, String> {
        Ok(sanitized_dry_run_result("Veeam", operation))
    }

    fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct ZabbixAdapter {
    pub config: AdapterConfig,
}

impl ZabbixAdapter {
    pub fn static_dry_run() -> Self {
        ZabbixAdapter {
            config: AdapterConfig {
                id: format!(
                    "ad-{}",
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("unknown")
                ),
                adapter_type: AdapterType::Zabbix,
                name: "Zabbix SIMULATED".into(),
                endpoint: "https://zabbix.example.invalid (DRY-RUN)".into(),
                status: AdapterStatus::Configured,
                readiness: ReadinessState::Configured,
                api_version: "7.4 (simulated)".into(),
                health_check_at: None,
                stale: false,
                metadata: HashMap::from([("dry_run".into(), "true".into())]),
            },
        }
    }
}

impl ProviderAdapter for ZabbixAdapter {
    fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterStatus, String> {
        Ok(AdapterStatus::Connected)
    }

    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String> {
        let now = Utc::now().to_rfc3339();
        Ok(vec![InventoryItem {
            id: "zabbix-mock-001".into(),
            name: "zabbix-server-mock".into(),
            item_type: InventoryType::MonitoringHost,
            owner: "monitoring-team".into(),
            site: "BUR1".into(),
            environment: "production".into(),
            criticality: "critical".into(),
            last_synced: now.clone(),
            source: "zabbix".into(),
            stale: false,
            metadata: HashMap::from([
                ("simulated".into(), "true".into()),
                ("version".into(), "7.4".into()),
            ]),
        }])
    }

    fn execute(
        &self,
        operation: &str,
        _params: &HashMap<String, String>,
    ) -> Result<String, String> {
        Ok(sanitized_dry_run_result("Zabbix", operation))
    }

    fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct ServiceNowAdapter {
    pub config: AdapterConfig,
}

impl ServiceNowAdapter {
    pub fn static_dry_run() -> Self {
        ServiceNowAdapter {
            config: AdapterConfig {
                id: format!(
                    "ad-{}",
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("unknown")
                ),
                adapter_type: AdapterType::ServiceNow,
                name: "ServiceNow File Exchange SIMULATED".into(),
                endpoint: "https://servicenow.example.invalid (DRY-RUN)".into(),
                status: AdapterStatus::Configured,
                readiness: ReadinessState::Configured,
                api_version: "File-based (simulated)".into(),
                health_check_at: None,
                stale: false,
                metadata: HashMap::from([
                    ("dry_run".into(), "true".into()),
                    ("mode".into(), "file-exchange-only".into()),
                ]),
            },
        }
    }
}

impl ProviderAdapter for ServiceNowAdapter {
    fn connect(&self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterStatus, String> {
        Ok(AdapterStatus::Connected)
    }

    fn sync_inventory(&self) -> Result<Vec<InventoryItem>, String> {
        let now = Utc::now().to_rfc3339();
        Ok(vec![InventoryItem {
            id: "sn-mock-001".into(),
            name: "servicenow-cmdb-ci-mock".into(),
            item_type: InventoryType::CmdbCi,
            owner: "service-owner".into(),
            site: "BUR1".into(),
            environment: "production".into(),
            criticality: "high".into(),
            last_synced: now.clone(),
            source: "servicenow".into(),
            stale: false,
            metadata: HashMap::from([
                ("simulated".into(), "true".into()),
                ("mode".into(), "file-exchange".into()),
            ]),
        }])
    }

    fn execute(
        &self,
        operation: &str,
        _params: &HashMap<String, String>,
    ) -> Result<String, String> {
        Ok(format!(
            "DRY-RUN: ServiceNow operation '{}' simulated (file-exchange mode, no live API)",
            operation
        ))
    }

    fn disconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmware_adapter_dry_run_safe() {
        let adapter = VMwareAdapter::static_dry_run();
        assert_eq!(adapter.config.status, AdapterStatus::Configured);
        assert_eq!(adapter.config.readiness, ReadinessState::Configured);
        assert!(adapter.config.metadata.get("dry_run").unwrap() == "true");
    }

    #[test]
    fn test_vmware_adapter_health_check() {
        let adapter = VMwareAdapter::static_dry_run();
        let status = adapter.health_check().unwrap();
        assert_eq!(status, AdapterStatus::Connected);
    }

    #[test]
    fn test_vmware_adapter_sync_inventory_dry_run() {
        let adapter = VMwareAdapter::static_dry_run();
        let items = adapter.sync_inventory().unwrap();
        assert!(!items.is_empty());
        for item in &items {
            assert!(item.source == "vmware");
            assert!(item.metadata.contains_key("simulated"));
        }
    }

    #[test]
    fn test_vmware_adapter_execute_dry_run() {
        let adapter = VMwareAdapter::static_dry_run();
        let mut params = HashMap::new();
        params.insert("vm_name".into(), "test-vm".into());
        let result = adapter.execute("deploy-vm", &params).unwrap();
        assert!(result.contains("DRY-RUN"));
        assert!(result.contains("simulated"));
    }

    #[test]
    fn test_hyperv_adapter_all_dry_run() {
        let adapter = HyperVAdapter::static_dry_run();
        assert!(adapter.connect().is_ok());
        assert_eq!(adapter.health_check().unwrap(), AdapterStatus::Connected);
        let items = adapter.sync_inventory().unwrap();
        assert!(!items.is_empty());
        let result = adapter.execute("test-op", &HashMap::new()).unwrap();
        assert!(result.contains("DRY-RUN"));
        assert!(adapter.disconnect().is_ok());
    }

    #[test]
    fn test_proxmox_adapter_returns_mock_data() {
        let adapter = ProxmoxAdapter::static_dry_run();
        let items = adapter.sync_inventory().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_type, InventoryType::HypervisorHost);
    }

    #[test]
    fn test_veeam_adapter_repository_capacity_mock() {
        let adapter = VeeamAdapter::static_dry_run();
        let items = adapter.sync_inventory().unwrap();
        assert!(items[0].metadata.contains_key("capacity_tb"));
    }

    #[test]
    fn test_zabbix_adapter_version_field() {
        let adapter = ZabbixAdapter::static_dry_run();
        let items = adapter.sync_inventory().unwrap();
        assert_eq!(items[0].metadata.get("version").unwrap(), "7.4");
    }

    #[test]
    fn test_servicenow_adapter_file_exchange_mode() {
        let adapter = ServiceNowAdapter::static_dry_run();
        assert_eq!(adapter.config.readiness, ReadinessState::Configured);
        assert!(adapter.config.metadata.get("mode").unwrap() == "file-exchange-only");
        let result = adapter.execute("import-cmdb", &HashMap::new()).unwrap();
        assert!(result.contains("file-exchange"));
        assert!(result.contains("no live API"));
    }

    #[test]
    fn test_vmware_adapter_no_credentials_in_config() {
        let adapter = VMwareAdapter::static_dry_run();
        let metadata_str = format!("{:?}", adapter.config.metadata);
        assert!(!metadata_str.contains("password"));
        assert!(!metadata_str.contains("secret"));
        assert!(!metadata_str.contains("token"));
        assert!(!metadata_str.contains("credential"));
    }

    #[test]
    fn test_all_adapter_configs_are_safe() {
        let adapters: Vec<Box<dyn ProviderAdapter>> = vec![
            Box::new(VMwareAdapter::static_dry_run()),
            Box::new(HyperVAdapter::static_dry_run()),
            Box::new(ProxmoxAdapter::static_dry_run()),
            Box::new(VeeamAdapter::static_dry_run()),
            Box::new(ZabbixAdapter::static_dry_run()),
            Box::new(ServiceNowAdapter::static_dry_run()),
        ];

        for adapter in &adapters {
            assert!(adapter.connect().is_ok());
            assert!(adapter.health_check().is_ok());
            let items = adapter.sync_inventory().unwrap();
            assert!(!items.is_empty());
            let exec_result = adapter.execute("noop", &HashMap::new()).unwrap();
            assert!(exec_result.contains("DRY-RUN"));
            assert!(adapter.disconnect().is_ok());
        }
    }

    #[test]
    fn test_all_adapter_readiness_defaults_to_configured() {
        let vmware = VMwareAdapter::static_dry_run();
        let hyperv = HyperVAdapter::static_dry_run();
        let proxmox = ProxmoxAdapter::static_dry_run();
        let veeam = VeeamAdapter::static_dry_run();
        let zabbix = ZabbixAdapter::static_dry_run();
        let servicenow = ServiceNowAdapter::static_dry_run();

        assert_eq!(vmware.config.readiness, ReadinessState::Configured);
        assert_eq!(hyperv.config.readiness, ReadinessState::Configured);
        assert_eq!(proxmox.config.readiness, ReadinessState::Configured);
        assert_eq!(veeam.config.readiness, ReadinessState::Configured);
        assert_eq!(zabbix.config.readiness, ReadinessState::Configured);
        assert_eq!(servicenow.config.readiness, ReadinessState::Configured);
    }

    #[test]
    fn test_adapter_execute_excludes_raw_params() {
        // RED: current execute returns params via {:?} — must NOT appear
        let adapter = VMwareAdapter::static_dry_run();
        let mut params = HashMap::new();
        params.insert("api_key".into(), "secret-value-12345".into());
        params.insert("admin_password".into(), "p@ssw0rd!".into());
        let result = adapter.execute("deploy-vm", &params).unwrap();
        assert!(result.contains("deploy-vm"));
        assert!(result.contains("DRY-RUN"));
        assert!(!result.contains("secret-value-12345"));
        assert!(!result.contains("p@ssw0rd!"));
        assert!(!result.contains("api_key"));
        assert!(!result.contains("admin_password"));
    }

    #[test]
    fn test_all_adapters_execute_excludes_params() {
        // RED: every adapter execute must exclude raw params from result
        let adapters: Vec<Box<dyn ProviderAdapter>> = vec![
            Box::new(VMwareAdapter::static_dry_run()),
            Box::new(HyperVAdapter::static_dry_run()),
            Box::new(ProxmoxAdapter::static_dry_run()),
            Box::new(VeeamAdapter::static_dry_run()),
            Box::new(ZabbixAdapter::static_dry_run()),
            Box::new(ServiceNowAdapter::static_dry_run()),
        ];
        let mut params = HashMap::new();
        params.insert("credential".into(), "leaked-cred".into());
        for adapter in &adapters {
            let result = adapter.execute("test-op", &params).unwrap();
            assert!(result.contains("DRY-RUN"));
            assert!(!result.contains("leaked-cred"));
        }
    }
}
