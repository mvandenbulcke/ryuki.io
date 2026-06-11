use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeType {
    Lun,
    Nfs,
    Cifs,
    Object,
}

impl std::fmt::Display for VolumeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeType::Lun => write!(f, "LUN"),
            VolumeType::Nfs => write!(f, "NFS"),
            VolumeType::Cifs => write!(f, "CIFS"),
            VolumeType::Object => write!(f, "Object"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionType {
    Raid,
    None,
    Replicated,
}

impl std::fmt::Display for ProtectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionType::Raid => write!(f, "RAID"),
            ProtectionType::None => write!(f, "None"),
            ProtectionType::Replicated => write!(f, "Replicated"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeStatus {
    Creating,
    Available,
    Mounted,
    Expanding,
    Retiring,
}

impl std::fmt::Display for VolumeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeStatus::Creating => write!(f, "Creating"),
            VolumeStatus::Available => write!(f, "Available"),
            VolumeStatus::Mounted => write!(f, "Mounted"),
            VolumeStatus::Expanding => write!(f, "Expanding"),
            VolumeStatus::Retiring => write!(f, "Retiring"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StorageVendor {
    PureStorage,
    DellEmc,
    NetApp,
    Hpe,
}

impl std::fmt::Display for StorageVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageVendor::PureStorage => write!(f, "PureStorage"),
            StorageVendor::DellEmc => write!(f, "DellEMC"),
            StorageVendor::NetApp => write!(f, "NetApp"),
            StorageVendor::Hpe => write!(f, "HPE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArrayStatus {
    Healthy,
    Degraded,
    Critical,
}

impl std::fmt::Display for ArrayStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArrayStatus::Healthy => write!(f, "Healthy"),
            ArrayStatus::Degraded => write!(f, "Degraded"),
            ArrayStatus::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RequestStatus {
    Draft,
    Validated,
    Provisioned,
    Mounted,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageVolume {
    pub id: String,
    pub name: String,
    pub volume_type: VolumeType,
    pub size_gb: u64,
    pub storage_array: String,
    pub pool: String,
    pub site: String,
    pub host_mappings: Vec<String>,
    pub protection: ProtectionType,
    pub status: VolumeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageArray {
    pub id: String,
    pub name: String,
    pub vendor: StorageVendor,
    pub model: String,
    pub site: String,
    pub total_capacity_gb: u64,
    pub used_capacity_gb: u64,
    pub pool_count: u32,
    pub status: ArrayStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequest {
    pub id: String,
    pub requester: String,
    pub hostname: String,
    pub size_gb: u64,
    pub volume_type: VolumeType,
    pub storage_array: String,
    pub site: String,
    pub purpose: String,
    pub status: RequestStatus,
}

type StorageStore = (Vec<StorageVolume>, Vec<StorageArray>, Vec<StorageRequest>);

static STORAGE_STORE: OnceLock<Mutex<StorageStore>> = OnceLock::new();

fn storage_store() -> &'static Mutex<StorageStore> {
    STORAGE_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> StorageStore {
    let volumes = vec![
        StorageVolume {
            id: "vol-defra-001".into(),
            name: "defra-db-lun-01".into(),
            volume_type: VolumeType::Lun,
            size_gb: 2048,
            storage_array: "arr-defra-001".into(),
            pool: "gold".into(),
            site: "DEFRA".into(),
            host_mappings: vec!["defra-db-01".into(), "defra-db-02".into()],
            protection: ProtectionType::Raid,
            status: VolumeStatus::Mounted,
        },
        StorageVolume {
            id: "vol-defra-002".into(),
            name: "defra-app-nfs-01".into(),
            volume_type: VolumeType::Nfs,
            size_gb: 1024,
            storage_array: "arr-defra-001".into(),
            pool: "silver".into(),
            site: "DEFRA".into(),
            host_mappings: vec!["defra-app-01".into()],
            protection: ProtectionType::Replicated,
            status: VolumeStatus::Mounted,
        },
        StorageVolume {
            id: "vol-gblon-001".into(),
            name: "gblon-vm-cifs-01".into(),
            volume_type: VolumeType::Cifs,
            size_gb: 4096,
            storage_array: "arr-gblon-001".into(),
            pool: "shared".into(),
            site: "GBLON".into(),
            host_mappings: vec!["gblon-fs-01".into()],
            protection: ProtectionType::Raid,
            status: VolumeStatus::Mounted,
        },
        StorageVolume {
            id: "vol-gblon-002".into(),
            name: "gblon-logs-obj-01".into(),
            volume_type: VolumeType::Object,
            size_gb: 8192,
            storage_array: "arr-gblon-001".into(),
            pool: "archive".into(),
            site: "GBLON".into(),
            host_mappings: Vec::new(),
            protection: ProtectionType::None,
            status: VolumeStatus::Available,
        },
        StorageVolume {
            id: "vol-frpar-001".into(),
            name: "frpar-sql-lun-01".into(),
            volume_type: VolumeType::Lun,
            size_gb: 1536,
            storage_array: "arr-frpar-001".into(),
            pool: "gold".into(),
            site: "FRPAR".into(),
            host_mappings: vec!["frpar-sql-01".into()],
            protection: ProtectionType::Raid,
            status: VolumeStatus::Mounted,
        },
        StorageVolume {
            id: "vol-frpar-002".into(),
            name: "frpar-backup-nfs-01".into(),
            volume_type: VolumeType::Nfs,
            size_gb: 6144,
            storage_array: "arr-frpar-001".into(),
            pool: "backup".into(),
            site: "FRPAR".into(),
            host_mappings: Vec::new(),
            protection: ProtectionType::Replicated,
            status: VolumeStatus::Available,
        },
    ];

    let arrays = vec![
        StorageArray {
            id: "arr-defra-001".into(),
            name: "defra-pure-fa-01".into(),
            vendor: StorageVendor::PureStorage,
            model: "FlashArray//X70".into(),
            site: "DEFRA".into(),
            total_capacity_gb: 20_480,
            used_capacity_gb: 3_072,
            pool_count: 2,
            status: ArrayStatus::Healthy,
        },
        StorageArray {
            id: "arr-gblon-001".into(),
            name: "gblon-dellemc-pmax-01".into(),
            vendor: StorageVendor::DellEmc,
            model: "PowerMax 2500".into(),
            site: "GBLON".into(),
            total_capacity_gb: 32_768,
            used_capacity_gb: 12_288,
            pool_count: 3,
            status: ArrayStatus::Degraded,
        },
        StorageArray {
            id: "arr-frpar-001".into(),
            name: "frpar-netapp-a400-01".into(),
            vendor: StorageVendor::NetApp,
            model: "AFF A400".into(),
            site: "FRPAR".into(),
            total_capacity_gb: 24_576,
            used_capacity_gb: 7_680,
            pool_count: 2,
            status: ArrayStatus::Healthy,
        },
    ];

    let requests = vec![
        StorageRequest {
            id: "sr-defra-001".into(),
            requester: "alice.engineer".into(),
            hostname: "defra-web-03".into(),
            size_gb: 512,
            volume_type: VolumeType::Nfs,
            storage_array: "arr-defra-001".into(),
            site: "DEFRA".into(),
            purpose: "application content".into(),
            status: RequestStatus::Validated,
        },
        StorageRequest {
            id: "sr-gblon-001".into(),
            requester: "bob.engineer".into(),
            hostname: "gblon-db-03".into(),
            size_gb: 2048,
            volume_type: VolumeType::Lun,
            storage_array: "arr-gblon-001".into(),
            site: "GBLON".into(),
            purpose: "database expansion".into(),
            status: RequestStatus::Draft,
        },
        StorageRequest {
            id: "sr-frpar-001".into(),
            requester: "carol.engineer".into(),
            hostname: "frpar-ana-01".into(),
            size_gb: 1024,
            volume_type: VolumeType::Cifs,
            storage_array: "arr-frpar-001".into(),
            site: "FRPAR".into(),
            purpose: "analytics share".into(),
            status: RequestStatus::Provisioned,
        },
        StorageRequest {
            id: "sr-defra-002".into(),
            requester: "dave.engineer".into(),
            hostname: "defra-obj-01".into(),
            size_gb: 4096,
            volume_type: VolumeType::Object,
            storage_array: "arr-defra-001".into(),
            site: "DEFRA".into(),
            purpose: "audit archive".into(),
            status: RequestStatus::Completed,
        },
    ];

    (volumes, arrays, requests)
}

fn parse_volume_type(volume_type: &str) -> Result<VolumeType, String> {
    match volume_type {
        "LUN" => Ok(VolumeType::Lun),
        "NFS" => Ok(VolumeType::Nfs),
        "CIFS" => Ok(VolumeType::Cifs),
        "Object" => Ok(VolumeType::Object),
        other => Err(format!(
            "Invalid volume_type: {}. Must be LUN, NFS, CIFS, or Object",
            other
        )),
    }
}

fn default_pool(volume_type: &VolumeType) -> String {
    match volume_type {
        VolumeType::Lun => "gold".into(),
        VolumeType::Nfs | VolumeType::Cifs => "shared".into(),
        VolumeType::Object => "archive".into(),
    }
}

fn default_protection(volume_type: &VolumeType) -> ProtectionType {
    match volume_type {
        VolumeType::Object => ProtectionType::None,
        VolumeType::Nfs | VolumeType::Cifs => ProtectionType::Replicated,
        VolumeType::Lun => ProtectionType::Raid,
    }
}

fn available_capacity_gb(array: &StorageArray) -> u64 {
    array
        .total_capacity_gb
        .saturating_sub(array.used_capacity_gb)
}

pub fn list_volumes(site: &str) -> Result<Value, String> {
    let store = storage_store().lock().unwrap();
    let volumes: Vec<StorageVolume> = if site.is_empty() {
        store.0.clone()
    } else {
        store.0.iter().filter(|v| v.site == site).cloned().collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "count": volumes.len(),
        "volumes": volumes
    }))
}

pub fn get_volume(id: &str) -> Result<Value, String> {
    let store = storage_store().lock().unwrap();
    let volume = store
        .0
        .iter()
        .find(|v| v.id == id)
        .ok_or_else(|| format!("Volume '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "volume": volume,
        "host_mappings": volume.host_mappings
    }))
}

pub fn provision_volume(
    name: &str,
    size_gb: u64,
    volume_type: &str,
    array_id: &str,
    site: &str,
) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if size_gb == 0 {
        return Err("size_gb must be greater than 0".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let parsed_type = parse_volume_type(volume_type)?;
    let mut store = storage_store().lock().unwrap();
    let array = store
        .1
        .iter_mut()
        .find(|a| a.id == array_id)
        .ok_or_else(|| format!("Storage array '{}' not found", array_id))?;

    if array.site != site {
        return Err(format!(
            "Storage array '{}' belongs to site '{}' not '{}'",
            array_id, array.site, site
        ));
    }
    if available_capacity_gb(array) < size_gb {
        return Err(format!(
            "Insufficient capacity on '{}': requested {} GB, available {} GB",
            array_id,
            size_gb,
            available_capacity_gb(array)
        ));
    }

    array.used_capacity_gb += size_gb;

    let volume = StorageVolume {
        id: format!(
            "vol-{}-{}",
            site.to_lowercase(),
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        name: name.to_string(),
        volume_type: parsed_type.clone(),
        size_gb,
        storage_array: array_id.to_string(),
        pool: default_pool(&parsed_type),
        site: site.to_string(),
        host_mappings: Vec::new(),
        protection: default_protection(&parsed_type),
        status: VolumeStatus::Available,
    };

    store.0.push(volume.clone());

    Ok(json!({
        "source": "dry-run",
        "action": "provision-volume",
        "volume": volume
    }))
}

pub fn extend_volume(id: &str, additional_gb: u64) -> Result<Value, String> {
    if additional_gb == 0 {
        return Err("additional_gb must be greater than 0".into());
    }

    let mut store = storage_store().lock().unwrap();
    let volume_index = store
        .0
        .iter()
        .position(|v| v.id == id)
        .ok_or_else(|| format!("Volume '{}' not found", id))?;
    let array_id = store.0[volume_index].storage_array.clone();
    let array = store
        .1
        .iter_mut()
        .find(|a| a.id == array_id)
        .ok_or_else(|| format!("Storage array '{}' not found", array_id))?;

    if available_capacity_gb(array) < additional_gb {
        return Err(format!(
            "Insufficient capacity on '{}': requested {} GB, available {} GB",
            array_id,
            additional_gb,
            available_capacity_gb(array)
        ));
    }

    array.used_capacity_gb += additional_gb;
    let volume = &mut store.0[volume_index];
    volume.size_gb += additional_gb;
    volume.status = VolumeStatus::Expanding;
    volume.status = VolumeStatus::Available;

    Ok(json!({
        "source": "dry-run",
        "action": "extend-volume",
        "volume": volume
    }))
}

pub fn map_volume(id: &str, hostname: &str) -> Result<Value, String> {
    if hostname.trim().is_empty() {
        return Err("hostname cannot be empty".into());
    }

    let mut store = storage_store().lock().unwrap();
    let volume = store
        .0
        .iter_mut()
        .find(|v| v.id == id)
        .ok_or_else(|| format!("Volume '{}' not found", id))?;

    if !volume.host_mappings.iter().any(|h| h == hostname) {
        volume.host_mappings.push(hostname.to_string());
    }
    volume.status = VolumeStatus::Mounted;

    Ok(json!({
        "source": "dry-run",
        "action": "map-volume",
        "volume": volume
    }))
}

pub fn unmap_volume(id: &str, hostname: &str) -> Result<Value, String> {
    let mut store = storage_store().lock().unwrap();
    let volume = store
        .0
        .iter_mut()
        .find(|v| v.id == id)
        .ok_or_else(|| format!("Volume '{}' not found", id))?;

    volume.host_mappings.retain(|h| h != hostname);
    if volume.host_mappings.is_empty() {
        volume.status = VolumeStatus::Available;
    }

    Ok(json!({
        "source": "dry-run",
        "action": "unmap-volume",
        "volume": volume
    }))
}

pub fn retire_volume(id: &str) -> Result<Value, String> {
    let mut store = storage_store().lock().unwrap();
    let volume = store
        .0
        .iter_mut()
        .find(|v| v.id == id)
        .ok_or_else(|| format!("Volume '{}' not found", id))?;

    volume.status = VolumeStatus::Retiring;

    Ok(json!({
        "source": "dry-run",
        "action": "retire-volume",
        "volume": volume
    }))
}

pub fn list_arrays(site: &str) -> Result<Value, String> {
    let store = storage_store().lock().unwrap();
    let arrays: Vec<StorageArray> = if site.is_empty() {
        store.1.clone()
    } else {
        store.1.iter().filter(|a| a.site == site).cloned().collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "count": arrays.len(),
        "arrays": arrays
    }))
}

pub fn get_array(id: &str) -> Result<Value, String> {
    let store = storage_store().lock().unwrap();
    let array = store
        .1
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| format!("Storage array '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "array": array,
        "available_capacity_gb": available_capacity_gb(array)
    }))
}

pub fn check_capacity(array_id: &str, requested_gb: u64) -> Result<Value, String> {
    let store = storage_store().lock().unwrap();
    let array = store
        .1
        .iter()
        .find(|a| a.id == array_id)
        .ok_or_else(|| format!("Storage array '{}' not found", array_id))?;
    let available_gb = available_capacity_gb(array);

    Ok(json!({
        "source": "dry-run",
        "array_id": array_id,
        "requested_gb": requested_gb,
        "available_gb": available_gb,
        "can_provision": requested_gb <= available_gb
    }))
}

pub fn get_storage_report(site: &str) -> Result<Value, String> {
    let store = storage_store().lock().unwrap();
    let arrays: Vec<&StorageArray> = if site.is_empty() {
        store.1.iter().collect()
    } else {
        store.1.iter().filter(|a| a.site == site).collect()
    };
    let volume_count = if site.is_empty() {
        store.0.len()
    } else {
        store.0.iter().filter(|v| v.site == site).count()
    };
    let total_gb: u64 = arrays.iter().map(|a| a.total_capacity_gb).sum();
    let used_gb: u64 = arrays.iter().map(|a| a.used_capacity_gb).sum();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_gb": total_gb,
        "used_gb": used_gb,
        "available_gb": total_gb.saturating_sub(used_gb),
        "volume_count": volume_count,
        "array_count": arrays.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_volumes_by_site() {
        let result = list_volumes("DEFRA").unwrap();

        assert!(result["count"].as_u64().unwrap() >= 2);
        assert_eq!(result["volumes"][0]["site"], "DEFRA");
    }

    #[test]
    fn test_provision_and_extend_volume() {
        let provisioned = provision_volume(
            "defra-test-provision-extend",
            128,
            "LUN",
            "arr-defra-001",
            "DEFRA",
        )
        .unwrap();
        let id = provisioned["volume"]["id"].as_str().unwrap();

        let extended = extend_volume(id, 64).unwrap();

        assert_eq!(extended["volume"]["size_gb"], 192);
        assert_eq!(extended["volume"]["status"], "available");
    }

    #[test]
    fn test_map_and_unmap_volume() {
        let provisioned =
            provision_volume("gblon-test-map-unmap", 128, "NFS", "arr-gblon-001", "GBLON").unwrap();
        let id = provisioned["volume"]["id"].as_str().unwrap();

        let mapped = map_volume(id, "gblon-test-host-01").unwrap();
        assert_eq!(mapped["volume"]["status"], "mounted");
        assert_eq!(mapped["volume"]["host_mappings"][0], "gblon-test-host-01");

        let unmapped = unmap_volume(id, "gblon-test-host-01").unwrap();
        assert_eq!(unmapped["volume"]["status"], "available");
        assert_eq!(
            unmapped["volume"]["host_mappings"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_retire_volume() {
        let provisioned =
            provision_volume("frpar-test-retire", 128, "CIFS", "arr-frpar-001", "FRPAR").unwrap();
        let id = provisioned["volume"]["id"].as_str().unwrap();

        let retired = retire_volume(id).unwrap();

        assert_eq!(retired["volume"]["status"], "retiring");
    }

    #[test]
    fn test_check_capacity_on_array() {
        let result = check_capacity("arr-defra-001", 1024).unwrap();

        assert_eq!(result["array_id"], "arr-defra-001");
        assert_eq!(result["can_provision"], true);
        assert!(result["available_gb"].as_u64().unwrap() >= 1024);
    }

    #[test]
    fn test_storage_report() {
        let result = get_storage_report("FRPAR").unwrap();

        assert_eq!(result["site"], "FRPAR");
        assert_eq!(result["array_count"], 1);
        assert!(result["total_gb"].as_u64().unwrap() >= result["used_gb"].as_u64().unwrap());
        assert!(result["volume_count"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn test_provision_over_capacity_fails() {
        let result = provision_volume(
            "defra-test-over-capacity",
            999_999,
            "Object",
            "arr-defra-001",
            "DEFRA",
        );

        assert!(result.is_err());
    }
}
