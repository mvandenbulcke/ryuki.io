use crate::models::*;
use std::collections::{HashMap, HashSet};

pub fn import_cmdb_records(source: &str) -> Result<Vec<CmdbRecord>, String> {
    if source.is_empty() {
        return Err("Source reference cannot be empty".into());
    }

    match source {
        "cmdb-excel-export" => mock_excel_import(),
        "servicenow-export" => mock_servicenow_import(),
        _ => Err(format!(
            "DRY-RUN: Unknown CMDB source '{}'. Supported sources: cmdb-excel-export, servicenow-export",
            source
        )),
    }
}

fn mock_excel_import() -> Result<Vec<CmdbRecord>, String> {
    let records = vec![
        CmdbRecord {
            ci_id: "ci-001".into(),
            ci_name: "srv-defra-web01.corp.local".into(),
            ci_type: "Windows Server".into(),
            site: "DEFRA".into(),
            environment: "production".into(),
            owner: "app-team-web".into(),
            support_group: "Wintel-Operations".into(),
            criticality: "high".into(),
            attributes: HashMap::from([
                ("os_version".into(), "Windows Server 2022".into()),
                ("cpu_count".into(), "4".into()),
                ("memory_gb".into(), "16".into()),
            ]),
            relationships: vec![CmdbRelationship {
                target_ci_id: "ci-app-001".into(),
                relationship_type: "Runs on".into(),
                direction: "depends_on".into(),
            }],
            import_status: ImportStatus::Accepted,
            validation_errors: Vec::new(),
        },
        CmdbRecord {
            ci_id: "ci-002".into(),
            ci_name: "srv-gblon-db01.corp.local".into(),
            ci_type: "Database Server".into(),
            site: "GBLON".into(),
            environment: "production".into(),
            owner: "db-team".into(),
            support_group: "DBA-Operations".into(),
            criticality: "critical".into(),
            attributes: HashMap::from([
                ("os_version".into(), "Windows Server 2022".into()),
                ("cpu_count".into(), "8".into()),
                ("memory_gb".into(), "64".into()),
                ("db_type".into(), "SQL Server 2019".into()),
            ]),
            relationships: vec![CmdbRelationship {
                target_ci_id: "ci-001".into(),
                relationship_type: "Provides data to".into(),
                direction: "depends_on".into(),
            }],
            import_status: ImportStatus::Accepted,
            validation_errors: Vec::new(),
        },
        CmdbRecord {
            ci_id: "ci-003".into(),
            ci_name: "srv-frpar-app01.corp.local".into(),
            ci_type: "Application Server".into(),
            site: "FRPAR".into(),
            environment: "production".into(),
            owner: "".into(),
            support_group: "".into(),
            criticality: "high".into(),
            attributes: HashMap::from([
                ("os_version".into(), "Windows Server 2022".into()),
                ("cpu_count".into(), "4".into()),
            ]),
            relationships: Vec::new(),
            import_status: ImportStatus::Rejected,
            validation_errors: vec!["Missing owner".into(), "Missing support group".into()],
        },
    ];

    Ok(records)
}

fn mock_servicenow_import() -> Result<Vec<CmdbRecord>, String> {
    let records = vec![
        CmdbRecord {
            ci_id: "sn-ci-001".into(),
            ci_name: "srv-nlams-mon01.corp.local".into(),
            ci_type: "Monitoring Server".into(),
            site: "NLAMS".into(),
            environment: "production".into(),
            owner: "monitoring-team".into(),
            support_group: "Monitoring-Operations".into(),
            criticality: "high".into(),
            attributes: HashMap::from([
                ("os_version".into(), "RHEL 9".into()),
                ("cpu_count".into(), "2".into()),
                ("memory_gb".into(), "8".into()),
            ]),
            relationships: Vec::new(),
            import_status: ImportStatus::PendingReview,
            validation_errors: Vec::new(),
        },
        CmdbRecord {
            ci_id: "sn-ci-002".into(),
            ci_name: "srv-gblon-fs01.corp.local".into(),
            ci_type: "File Server".into(),
            site: "GBLON".into(),
            environment: "production".into(),
            owner: "fs-team".into(),
            support_group: "Storage-Operations".into(),
            criticality: "medium".into(),
            attributes: HashMap::from([
                ("os_version".into(), "Windows Server 2022".into()),
                ("cpu_count".into(), "4".into()),
                ("memory_gb".into(), "32".into()),
                ("disk_gb".into(), "2000".into()),
            ]),
            relationships: Vec::new(),
            import_status: ImportStatus::Accepted,
            validation_errors: Vec::new(),
        },
    ];

    Ok(records)
}

pub fn reconcile_cmdb(
    platform: &[InventoryItem],
    cmdb: &[CmdbRecord],
) -> Result<Vec<String>, String> {
    let mut results: Vec<String> = Vec::new();

    let platform_server_names: HashSet<&str> = platform.iter().map(|i| i.name.as_str()).collect();
    let cmdb_ci_names: HashSet<&str> = cmdb.iter().map(|r| r.ci_name.as_str()).collect();

    let in_platform_not_cmdb: Vec<&&str> =
        platform_server_names.difference(&cmdb_ci_names).collect();

    let in_cmdb_not_platform: Vec<&&str> =
        cmdb_ci_names.difference(&platform_server_names).collect();

    let in_both: Vec<&&str> = platform_server_names.intersection(&cmdb_ci_names).collect();

    if !in_platform_not_cmdb.is_empty() {
        results.push(format!(
            "DRY-RUN: {} item(s) in platform inventory but not in CMDB: {:?}",
            in_platform_not_cmdb.len(),
            in_platform_not_cmdb
        ));
    }

    if !in_cmdb_not_platform.is_empty() {
        results.push(format!(
            "DRY-RUN: {} item(s) in CMDB but not in platform inventory: {:?}",
            in_cmdb_not_platform.len(),
            in_cmdb_not_platform
        ));
    }

    results.push(format!(
        "DRY-RUN: {} item(s) reconciled (present in both)",
        in_both.len()
    ));

    for record in cmdb {
        if record.import_status == ImportStatus::Rejected {
            results.push(format!(
                "DRY-RUN: CMDB record {} ({}) rejected: {:?}",
                record.ci_id, record.ci_name, record.validation_errors
            ));
        }
    }

    let accepted_count = cmdb
        .iter()
        .filter(|r| r.import_status == ImportStatus::Accepted)
        .count();
    let rejected_count = cmdb
        .iter()
        .filter(|r| r.import_status == ImportStatus::Rejected)
        .count();
    let pending_count = cmdb
        .iter()
        .filter(|r| r.import_status == ImportStatus::PendingReview)
        .count();

    results.push(format!(
        "DRY-RUN: Import summary - {} accepted, {} rejected, {} pending review",
        accepted_count, rejected_count, pending_count
    ));

    Ok(results)
}

pub fn export_cmdb(records: &[CmdbRecord], format: &str) -> Result<String, String> {
    if records.is_empty() {
        return Err("No CMDB records to export".into());
    }

    match format {
        "json" => serde_json::to_string_pretty(records).map_err(|e| e.to_string()),
        "yaml" => serde_yaml::to_string(records).map_err(|e| e.to_string()),
        _ => Err(format!("Unsupported export format: {}", format)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_cmdb_records_excel_source() {
        let records = import_cmdb_records("cmdb-excel-export").unwrap();
        assert_eq!(records.len(), 3);
        let accepted = records
            .iter()
            .filter(|r| r.import_status == ImportStatus::Accepted)
            .count();
        let rejected = records
            .iter()
            .filter(|r| r.import_status == ImportStatus::Rejected)
            .count();
        assert_eq!(accepted, 2);
        assert_eq!(rejected, 1);
    }

    #[test]
    fn test_import_cmdb_records_servicenow_source() {
        let records = import_cmdb_records("servicenow-export").unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.ci_name.contains("nlams-mon01")));
    }

    #[test]
    fn test_import_cmdb_records_unknown_source_fails() {
        assert!(import_cmdb_records("unknown").is_err());
    }

    #[test]
    fn test_import_cmdb_records_empty_source_fails() {
        assert!(import_cmdb_records("").is_err());
    }

    #[test]
    fn test_reconcile_cmdb_finds_gaps() {
        let platform = vec![
            InventoryItem {
                id: "inv-001".into(),
                name: "srv-defra-web01.corp.local".into(),
                item_type: InventoryType::Server,
                owner: "team".into(),
                site: "DEFRA".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: "2026-01-01T00:00:00Z".into(),
                source: "vmware".into(),
                stale: false,
                metadata: HashMap::new(),
            },
            InventoryItem {
                id: "inv-099".into(),
                name: "srv-platform-only.corp.local".into(),
                item_type: InventoryType::Server,
                owner: "team".into(),
                site: "DEFRA".into(),
                environment: "production".into(),
                criticality: "high".into(),
                last_synced: "2026-01-01T00:00:00Z".into(),
                source: "vmware".into(),
                stale: false,
                metadata: HashMap::new(),
            },
        ];
        let cmdb = import_cmdb_records("cmdb-excel-export").unwrap();
        let results = reconcile_cmdb(&platform, &cmdb).unwrap();

        assert!(
            results
                .iter()
                .any(|r| r.contains("in platform inventory but not in CMDB"))
        );
        assert!(
            results
                .iter()
                .any(|r| r.contains("in CMDB but not in platform inventory"))
        );
    }

    #[test]
    fn test_reconcile_cmdb_reports_rejected_records() {
        let platform: Vec<InventoryItem> = Vec::new();
        let cmdb = import_cmdb_records("cmdb-excel-export").unwrap();
        let results = reconcile_cmdb(&platform, &cmdb).unwrap();

        assert!(results.iter().any(|r| r.contains("rejected")));
        assert!(results.iter().any(|r| r.contains("ci-003")));
    }

    #[test]
    fn test_export_cmdb_json() {
        let cmdb = import_cmdb_records("servicenow-export").unwrap();
        let exported = export_cmdb(&cmdb, "json").unwrap();
        assert!(exported.contains("sn-ci-001"));
        assert!(exported.contains("srv-nlams-mon01"));
    }

    #[test]
    fn test_export_cmdb_yaml() {
        let cmdb = import_cmdb_records("cmdb-excel-export").unwrap();
        let exported = export_cmdb(&cmdb, "yaml").unwrap();
        assert!(!exported.is_empty());
        assert!(exported.contains("ci-001"));
    }

    #[test]
    fn test_export_cmdb_empty_fails() {
        let empty: Vec<CmdbRecord> = Vec::new();
        assert!(export_cmdb(&empty, "json").is_err());
    }

    #[test]
    fn test_export_cmdb_unsupported_format() {
        let cmdb = import_cmdb_records("cmdb-excel-export").unwrap();
        assert!(export_cmdb(&cmdb, "csv").is_err());
    }

    #[test]
    fn test_reconcile_cmdb_exact_match() {
        let platform = vec![InventoryItem {
            id: "inv-001".into(),
            name: "srv-defra-web01.corp.local".into(),
            item_type: InventoryType::Server,
            owner: "team".into(),
            site: "DEFRA".into(),
            environment: "production".into(),
            criticality: "high".into(),
            last_synced: "2026-01-01T00:00:00Z".into(),
            source: "vmware".into(),
            stale: false,
            metadata: HashMap::new(),
        }];
        let cmdb = vec![CmdbRecord {
            ci_id: "ci-001".into(),
            ci_name: "srv-defra-web01.corp.local".into(),
            ci_type: "Windows Server".into(),
            site: "DEFRA".into(),
            environment: "production".into(),
            owner: "team".into(),
            support_group: "wintel".into(),
            criticality: "high".into(),
            attributes: HashMap::new(),
            relationships: Vec::new(),
            import_status: ImportStatus::Accepted,
            validation_errors: Vec::new(),
        }];
        let results = reconcile_cmdb(&platform, &cmdb).unwrap();
        assert!(results.iter().any(|r| r.contains("reconciled")));
    }
}
