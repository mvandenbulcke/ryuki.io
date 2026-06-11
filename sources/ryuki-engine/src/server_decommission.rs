use crate::models::*;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

const DEPENDENCY_CATEGORIES: &[&str] = &[
    "backup-retention",
    "dns-records",
    "monitoring",
    "cmdb",
    "network-firewall",
    "certificates",
    "scheduled-tasks",
    "service-accounts",
    "group-policy",
    "file-shares",
];

pub fn plan_decommission(
    server_name: &str,
    site: &str,
    os_family: &str,
    server_type: ServerType,
    reason: &str,
    final_backup_required: bool,
    quarantine_days: u32,
) -> Result<DecommissionRequest, String> {
    if server_name.is_empty() {
        return Err("server_name cannot be empty".into());
    }
    if site.is_empty() {
        return Err("site cannot be empty".into());
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    if quarantine_days == 0 {
        return Err("quarantine_days must be greater than 0".into());
    }

    let id = format!(
        "decom-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let now = chrono::Utc::now().to_rfc3339();

    let dependencies_identified: Vec<String> = DEPENDENCY_CATEGORIES
        .iter()
        .map(|cat| {
            format!(
                "DRY-RUN: {} dependency check for {} (simulated, no live provider calls)",
                cat, server_name
            )
        })
        .collect();

    let active_connections_check = format!(
        "DRY-RUN: No active connections or critical services detected on {} (simulated)",
        server_name
    );

    let mut all_deps = dependencies_identified;
    all_deps.push(active_connections_check);

    Ok(DecommissionRequest {
        id,
        server_name: server_name.to_string(),
        site: site.to_string(),
        os_family: os_family.to_string(),
        server_type,
        reason: reason.to_string(),
        final_backup_required,
        quarantine_days,
        status: DecommissionStatus::Planned,
        dependencies_identified: all_deps,
        backup_confirmed: false,
        approvals_collected: Vec::new(),
        quarantine_until: None,
        created_at: now.clone(),
        updated_at: now,
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    })
}

pub fn validate_decommission(request: &DecommissionRequest) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if request.server_name.is_empty() {
        errors.push("Missing server_name".into());
        failed_rules.push("p0-server-name-required".into());
        remediation.push("Provide a valid server name.".into());
    }

    if !VALID_SITES.contains(&request.site.as_str()) {
        errors.push(format!("Unknown site: {}", request.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(format!(
            "Select a known site. Valid sites: {:?}",
            VALID_SITES
        ));
    }

    if request.reason.is_empty() {
        errors.push("Missing decommission reason".into());
        failed_rules.push("p0-decommission-reason-required".into());
        remediation.push("Provide a business justification for decommissioning.".into());
    }

    if request.dependencies_identified.len() < DEPENDENCY_CATEGORIES.len() {
        errors.push("Not all dependencies identified".into());
        failed_rules.push("p0-dependency-coverage-incomplete".into());
        remediation.push("Re-run dependency identification to cover all categories.".into());
    }

    if request.final_backup_required && !request.backup_confirmed {
        errors.push("Final backup required but not confirmed".into());
        failed_rules.push("p0-backup-not-confirmed".into());
        remediation.push("Confirm final backup has been completed before proceeding.".into());
    }

    if request.approvals_collected.is_empty() {
        errors.push("No approvals collected".into());
        failed_rules.push("p0-approvals-required".into());
        remediation.push(
            "Collect approvals from Datacenter Approver, Application Owner, and Backup Operator."
                .into(),
        );
    }

    warnings.push("DRY-RUN: Dependency verification simulated".into());
    warnings.push("DRY-RUN: No live backup or provider checks performed".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn quarantine_server(request: &DecommissionRequest) -> Result<DecommissionRequest, String> {
    if request.status == DecommissionStatus::Executed
        || request.status == DecommissionStatus::Completed
        || request.status == DecommissionStatus::RolledBack
    {
        return Err(format!(
            "Cannot quarantine server in terminal status: {:?}",
            request.status
        ));
    }

    let quarantine_until = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(request.quarantine_days as i64))
        .unwrap_or(chrono::Utc::now())
        .to_rfc3339();

    let mut quarantined = request.clone();
    quarantined.status = DecommissionStatus::Quarantined;
    quarantined.quarantine_until = Some(quarantine_until.clone());
    quarantined.updated_at = chrono::Utc::now().to_rfc3339();
    quarantined.metadata.insert(
        "quarantine_action".into(),
        format!(
            "DRY-RUN: Server {} shutdown, disk preserved, network blocked. Quarantine until {} (simulated, no hypervisor calls)",
            request.server_name, quarantine_until
        ),
    );

    Ok(quarantined)
}

pub fn execute_decommission(request: &DecommissionRequest) -> Result<DecommissionRequest, String> {
    if request.status == DecommissionStatus::Completed
        || request.status == DecommissionStatus::RolledBack
    {
        return Err(format!(
            "Cannot execute decommission in terminal status: {:?}",
            request.status
        ));
    }

    let mut executed = request.clone();
    executed.status = DecommissionStatus::Executed;
    executed.updated_at = chrono::Utc::now().to_rfc3339();

    let mut execution_log: Vec<String> = Vec::new();

    execution_log.push(format!(
        "DRY-RUN: VM/disk wiped for {} ({} server, simulated)",
        request.server_name,
        match request.server_type {
            ServerType::VM => "VM",
            ServerType::Physical => "Physical",
        }
    ));

    execution_log.push(format!(
        "DRY-RUN: DNS records removed for {} (simulated)",
        request.server_name
    ));

    execution_log.push(format!(
        "DRY-RUN: {} removed from monitoring/Zabbix (simulated)",
        request.server_name
    ));

    execution_log.push(format!(
        "DRY-RUN: {} removed from CMDB/ServiceNow (simulated)",
        request.server_name
    ));

    executed
        .metadata
        .insert("execution_log".into(), execution_log.join(" | "));

    Ok(executed)
}

pub fn verify_decommission(request: &DecommissionRequest) -> Result<Vec<EvidenceItem>, String> {
    if !matches!(
        request.status,
        DecommissionStatus::Executed | DecommissionStatus::Verified | DecommissionStatus::Completed
    ) {
        return Err(format!(
            "Cannot verify decommission in status {:?}. Must be Executed first.",
            request.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "decommission-dns-cleanup".into(),
        value: format!(
            "DRY-RUN: DNS references for {} verified clean (simulated)",
            request.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "decommission-monitoring-cleanup".into(),
        value: format!(
            "DRY-RUN: Monitoring references for {} verified removed (simulated)",
            request.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "decommission-cmdb-cleanup".into(),
        value: format!(
            "DRY-RUN: CMDB references for {} verified closed (simulated)",
            request.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::ExportPackage,
    });

    evidence.push(EvidenceItem {
        key: "decommission-backup-retention".into(),
        value: format!(
            "DRY-RUN: Backup retention policy verified for {} (simulated)",
            request.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    evidence.push(EvidenceItem {
        key: "decommission-summary".into(),
        value: format!(
            "DRY-RUN: All references for {} confirmed cleaned up. Decommission complete (simulated).",
            request.server_name
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    Ok(evidence)
}

pub fn rollback_decommission(request: &DecommissionRequest) -> Result<DecommissionRequest, String> {
    if request.status == DecommissionStatus::Completed
        || request.status == DecommissionStatus::RolledBack
    {
        return Err(format!(
            "Cannot rollback decommission in terminal status: {:?}",
            request.status
        ));
    }

    let quarantine_expired = request.quarantine_until.as_ref().is_none_or(|qu| {
        chrono::DateTime::parse_from_rfc3339(qu)
            .map(|q| q < chrono::Utc::now())
            .unwrap_or(true)
    });

    if quarantine_expired && request.quarantine_until.is_some() {
        return Err(format!(
            "Quarantine period has expired. Cannot rollback decommission for {}.",
            request.server_name
        ));
    }

    let mut rolled_back = request.clone();
    rolled_back.status = DecommissionStatus::RolledBack;
    rolled_back.updated_at = chrono::Utc::now().to_rfc3339();
    rolled_back.metadata.insert(
        "rollback_action".into(),
        format!(
            "DRY-RUN: Server {} restored from quarantine — disk reattached, network restored, monitoring and CMDB references reinstated (simulated)",
            request.server_name
        ),
    );

    Ok(rolled_back)
}

pub fn get_quarantine_inventory(requests: &[DecommissionRequest]) -> Vec<QuarantineEntry> {
    requests
        .iter()
        .filter(|r| r.status == DecommissionStatus::Quarantined)
        .map(|r| {
            let remaining_days = r.quarantine_until.as_ref().map_or(0, |qu| {
                chrono::DateTime::parse_from_rfc3339(qu)
                    .map(|q| {
                        let now = chrono::Utc::now();
                        let remaining = (q.to_utc() - now).num_days();
                        if remaining < 0 {
                            0u32
                        } else {
                            remaining as u32
                        }
                    })
                    .unwrap_or(0)
            });

            QuarantineEntry {
                server_name: r.server_name.clone(),
                site: r.site.clone(),
                quarantine_until: r.quarantine_until.clone().unwrap_or_default(),
                remaining_days,
                decommission_id: r.id.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request() -> DecommissionRequest {
        plan_decommission(
            "srv-app-01",
            "DEFRA",
            "Windows",
            ServerType::VM,
            "End of lifecycle — application retired",
            true,
            30,
        )
        .unwrap()
    }

    #[test]
    fn test_plan_decommission_creates_request() {
        let req = make_test_request();
        assert!(req.id.starts_with("decom-"));
        assert_eq!(req.status, DecommissionStatus::Planned);
        assert_eq!(req.quarantine_days, 30);
        assert!(req.dependencies_identified.len() >= DEPENDENCY_CATEGORIES.len());
        assert!(req.final_backup_required);
        assert!(!req.backup_confirmed);
    }

    #[test]
    fn test_plan_decommission_empty_server_name_fails() {
        assert!(
            plan_decommission("", "DEFRA", "Windows", ServerType::VM, "reason", true, 30,).is_err()
        );
    }

    #[test]
    fn test_plan_decommission_unknown_site_fails() {
        assert!(
            plan_decommission(
                "srv-01",
                "UNKNOWN",
                "Windows",
                ServerType::VM,
                "reason",
                true,
                30,
            )
            .is_err()
        );
    }

    #[test]
    fn test_plan_decommission_zero_quarantine_days_fails() {
        assert!(
            plan_decommission(
                "srv-01",
                "DEFRA",
                "Windows",
                ServerType::VM,
                "reason",
                true,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn test_plan_physical_server() {
        let req = plan_decommission(
            "srv-phys-01",
            "GBLON",
            "Linux",
            ServerType::Physical,
            "Hardware refresh",
            false,
            60,
        )
        .unwrap();
        assert_eq!(req.server_type, ServerType::Physical);
        assert_eq!(req.os_family, "Linux");
        assert!(!req.final_backup_required);
    }

    #[test]
    fn test_validate_decommission_passes_for_valid_request() {
        let mut req = make_test_request();
        req.backup_confirmed = true;
        req.approvals_collected = vec!["Datacenter Approver".into(), "Application Owner".into()];
        let result = validate_decommission(&req).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_decommission_detects_missing_backup() {
        let mut req = make_test_request();
        req.approvals_collected = vec!["Datacenter Approver".into()];
        let result = validate_decommission(&req).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .failed_rules
                .contains(&"p0-backup-not-confirmed".into())
        );
    }

    #[test]
    fn test_validate_decommission_detects_missing_approvals() {
        let req = make_test_request();
        let result = validate_decommission(&req).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .failed_rules
                .contains(&"p0-approvals-required".into())
        );
    }

    #[test]
    fn test_validate_decommission_detects_missing_reason() {
        let mut req = make_test_request();
        req.reason = "".into();
        let result = validate_decommission(&req).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .failed_rules
                .contains(&"p0-decommission-reason-required".into())
        );
    }

    #[test]
    fn test_quarantine_server() {
        let mut req = make_test_request();
        req.backup_confirmed = true;
        req.approvals_collected = vec!["Datacenter Approver".into()];
        let quarantined = quarantine_server(&req).unwrap();
        assert_eq!(quarantined.status, DecommissionStatus::Quarantined);
        assert!(quarantined.quarantine_until.is_some());
        assert!(quarantined.metadata.contains_key("quarantine_action"));
    }

    #[test]
    fn test_quarantine_server_refuses_terminal_status() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Completed;
        assert!(quarantine_server(&req).is_err());
    }

    #[test]
    fn test_execute_decommission() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Quarantined;
        let executed = execute_decommission(&req).unwrap();
        assert_eq!(executed.status, DecommissionStatus::Executed);
        let log = executed.metadata.get("execution_log").unwrap();
        assert!(log.contains("wiped"));
        assert!(log.contains("DNS records removed"));
        assert!(log.contains("monitoring"));
        assert!(log.contains("CMDB"));
    }

    #[test]
    fn test_execute_decommission_refuses_terminal_status() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Completed;
        assert!(execute_decommission(&req).is_err());
    }

    #[test]
    fn test_verify_decommission_requires_execution() {
        let req = make_test_request();
        assert!(verify_decommission(&req).is_err());
    }

    #[test]
    fn test_verify_decommission_after_execute() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Quarantined;
        let executed = execute_decommission(&req).unwrap();
        let evidence = verify_decommission(&executed).unwrap();
        assert_eq!(evidence.len(), 5);
        assert!(evidence.iter().any(|e| e.key == "decommission-dns-cleanup"));
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "decommission-monitoring-cleanup")
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "decommission-cmdb-cleanup")
        );
        assert!(evidence.iter().any(|e| e.key == "decommission-summary"));
    }

    #[test]
    fn test_rollback_decommission_within_quarantine() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Quarantined;
        req.quarantine_until = Some((chrono::Utc::now() + chrono::Duration::days(15)).to_rfc3339());
        let rolled_back = rollback_decommission(&req).unwrap();
        assert_eq!(rolled_back.status, DecommissionStatus::RolledBack);
        assert!(rolled_back.metadata.contains_key("rollback_action"));
    }

    #[test]
    fn test_rollback_decommission_refuses_terminal_status() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Completed;
        assert!(rollback_decommission(&req).is_err());
    }

    #[test]
    fn test_rollback_expired_quarantine_fails() {
        let mut req = make_test_request();
        req.status = DecommissionStatus::Quarantined;
        req.quarantine_until = Some("2020-01-01T00:00:00Z".into());
        assert!(rollback_decommission(&req).is_err());
    }

    #[test]
    fn test_get_quarantine_inventory() {
        let mut req1 = make_test_request();
        req1.status = DecommissionStatus::Quarantined;
        req1.quarantine_until =
            Some((chrono::Utc::now() + chrono::Duration::days(10)).to_rfc3339());

        let mut req2 = make_test_request();
        req2.id = "decom-other".into();
        req2.server_name = "srv-db-01".into();
        req2.status = DecommissionStatus::Planned;

        let mut req3 = make_test_request();
        req3.id = "decom-another".into();
        req3.server_name = "srv-web-01".into();
        req3.status = DecommissionStatus::Quarantined;
        req3.quarantine_until = Some((chrono::Utc::now() + chrono::Duration::days(5)).to_rfc3339());

        let inventory = get_quarantine_inventory(&[req1, req2, req3]);
        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory[0].server_name, "srv-app-01");
        assert_eq!(inventory[1].server_name, "srv-web-01");
    }

    #[test]
    fn test_server_type_display() {
        assert_eq!(ServerType::VM.to_string(), "VM");
        assert_eq!(ServerType::Physical.to_string(), "Physical");
    }

    #[test]
    fn test_decommission_status_display() {
        assert_eq!(DecommissionStatus::Draft.to_string(), "draft");
        assert_eq!(DecommissionStatus::Planned.to_string(), "planned");
        assert_eq!(DecommissionStatus::Quarantined.to_string(), "quarantined");
        assert_eq!(DecommissionStatus::Executed.to_string(), "executed");
        assert_eq!(DecommissionStatus::Completed.to_string(), "completed");
    }
}
