use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

// ─── Pure helpers ─────────────────────────────────────────────────────────────

pub fn parse_volume_type(volume_type: &str) -> Result<VolumeType, String> {
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

pub fn default_pool(volume_type: &VolumeType) -> String {
    match volume_type {
        VolumeType::Lun => "gold".into(),
        VolumeType::Nfs | VolumeType::Cifs => "shared".into(),
        VolumeType::Object => "archive".into(),
    }
}

pub fn default_protection(volume_type: &VolumeType) -> ProtectionType {
    match volume_type {
        VolumeType::Object => ProtectionType::None,
        VolumeType::Nfs | VolumeType::Cifs => ProtectionType::Replicated,
        VolumeType::Lun => ProtectionType::Raid,
    }
}

pub fn available_capacity_gb(array: &StorageArray) -> u64 {
    array.total_capacity_gb.saturating_sub(array.used_capacity_gb)
}

/// Build a new StorageVolume without persisting. Called by the provision handler
/// before delegating to the repo layer.
pub fn build_volume(
    name: &str,
    size_gb: u64,
    volume_type: VolumeType,
    array_id: &str,
    site: &str,
) -> StorageVolume {
    let pool = default_pool(&volume_type);
    let protection = default_protection(&volume_type);
    StorageVolume {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        volume_type,
        size_gb,
        storage_array: array_id.to_string(),
        pool,
        site: site.to_string(),
        host_mappings: Vec::new(),
        protection,
        status: VolumeStatus::Available,
    }
}

// ─── Read helpers (return JSON for handlers) ──────────────────────────────────

pub fn list_volumes(site: &str, volumes: &[StorageVolume]) -> Value {
    let filtered: Vec<&StorageVolume> = if site.is_empty() {
        volumes.iter().collect()
    } else {
        volumes.iter().filter(|v| v.site == site).collect()
    };
    json!({
        "source": "db",
        "site": site,
        "count": filtered.len(),
        "volumes": filtered
    })
}

pub fn get_volume_response(volume: &StorageVolume) -> Value {
    json!({
        "source": "db",
        "volume": volume,
        "host_mappings": volume.host_mappings
    })
}

pub fn list_arrays(site: &str, arrays: &[StorageArray]) -> Value {
    let filtered: Vec<&StorageArray> = if site.is_empty() {
        arrays.iter().collect()
    } else {
        arrays.iter().filter(|a| a.site == site).collect()
    };
    json!({
        "source": "db",
        "site": site,
        "count": filtered.len(),
        "arrays": filtered
    })
}

pub fn get_array_response(array: &StorageArray) -> Value {
    json!({
        "source": "db",
        "array": array,
        "available_capacity_gb": available_capacity_gb(array)
    })
}

pub fn check_capacity(array: &StorageArray, requested_gb: u64) -> Value {
    let available_gb = available_capacity_gb(array);
    json!({
        "source": "db",
        "array_id": array.id,
        "requested_gb": requested_gb,
        "available_gb": available_gb,
        "can_provision": requested_gb <= available_gb
    })
}

pub fn get_storage_report(
    site: &str,
    total_gb: i64,
    used_gb: i64,
    volume_count: i64,
    array_count: i64,
) -> Value {
    let available_gb = total_gb.saturating_sub(used_gb);
    json!({
        "source": "db",
        "site": site,
        "total_gb": total_gb,
        "used_gb": used_gb,
        "available_gb": available_gb,
        "volume_count": volume_count,
        "array_count": array_count
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_volumes_by_site() {
        let volumes = vec![
            StorageVolume {
                id: "v1".into(),
                name: "vol-a".into(),
                volume_type: VolumeType::Lun,
                size_gb: 100,
                storage_array: "arr-1".into(),
                pool: "gold".into(),
                site: "DEFRA".into(),
                host_mappings: vec![],
                protection: ProtectionType::Raid,
                status: VolumeStatus::Available,
            },
            StorageVolume {
                id: "v2".into(),
                name: "vol-b".into(),
                volume_type: VolumeType::Nfs,
                size_gb: 200,
                storage_array: "arr-2".into(),
                pool: "silver".into(),
                site: "GBLON".into(),
                host_mappings: vec![],
                protection: ProtectionType::Replicated,
                status: VolumeStatus::Mounted,
            },
        ];
        let result = list_volumes("DEFRA", &volumes);
        assert_eq!(result["count"], 1);
        assert_eq!(result["volumes"][0]["site"], "DEFRA");
    }

    #[test]
    fn test_build_volume_defaults() {
        let v = build_volume("test-lun", 512, VolumeType::Lun, "arr-1", "DEFRA");
        assert_eq!(v.name, "test-lun");
        assert_eq!(v.size_gb, 512);
        assert_eq!(v.pool, "gold");
        assert_eq!(v.protection, ProtectionType::Raid);
        assert_eq!(v.status, VolumeStatus::Available);
        assert!(v.host_mappings.is_empty());
    }

    #[test]
    fn test_available_capacity_gb() {
        let array = StorageArray {
            id: "a".into(),
            name: "n".into(),
            vendor: StorageVendor::PureStorage,
            model: "m".into(),
            site: "S".into(),
            total_capacity_gb: 1000,
            used_capacity_gb: 300,
            pool_count: 1,
            status: ArrayStatus::Healthy,
        };
        assert_eq!(available_capacity_gb(&array), 700);
    }

    #[test]
    fn test_check_capacity_json() {
        let array = StorageArray {
            id: "arr-1".into(),
            name: "n".into(),
            vendor: StorageVendor::NetApp,
            model: "m".into(),
            site: "S".into(),
            total_capacity_gb: 1000,
            used_capacity_gb: 300,
            pool_count: 1,
            status: ArrayStatus::Healthy,
        };
        let result = check_capacity(&array, 500);
        assert_eq!(result["can_provision"], true);
        assert_eq!(result["available_gb"], 700);
    }

    #[test]
    fn test_storage_report_json() {
        let result = get_storage_report("FRPAR", 24576, 7680, 2, 1);
        assert_eq!(result["site"], "FRPAR");
        assert_eq!(result["total_gb"], 24576);
        assert_eq!(result["array_count"], 1);
        assert_eq!(result["volume_count"], 2);
        assert!(result["available_gb"].as_i64().unwrap() >= result["used_gb"].as_i64().unwrap());
    }

    #[test]
    fn test_parse_volume_type_valid_and_invalid() {
        assert_eq!(parse_volume_type("LUN").unwrap(), VolumeType::Lun);
        assert_eq!(parse_volume_type("NFS").unwrap(), VolumeType::Nfs);
        assert_eq!(parse_volume_type("CIFS").unwrap(), VolumeType::Cifs);
        assert_eq!(parse_volume_type("Object").unwrap(), VolumeType::Object);
        assert!(parse_volume_type("invalid").is_err());
    }
}
