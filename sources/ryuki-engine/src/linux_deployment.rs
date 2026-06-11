use crate::models::*;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

pub fn supported_distro_catalog() -> Vec<LinuxDistroInfo> {
    vec![
        LinuxDistroInfo {
            distro: LinuxDistro::Sles,
            display_name: "SUSE Linux Enterprise Server".into(),
            package_manager: "zypper".into(),
            default_network: "wicked".into(),
            firewall: "firewalld".into(),
            min_version: "15.0".into(),
            max_version: "15.6".into(),
            supported_versions: vec!["15.4".into(), "15.5".into(), "15.6".into()],
            category: "enterprise".into(),
        },
        LinuxDistroInfo {
            distro: LinuxDistro::Rhel,
            display_name: "Red Hat Enterprise Linux".into(),
            package_manager: "dnf".into(),
            default_network: "NetworkManager".into(),
            firewall: "firewalld".into(),
            min_version: "8.0".into(),
            max_version: "9.5".into(),
            supported_versions: vec!["8.8".into(), "8.10".into(), "9.4".into(), "9.5".into()],
            category: "enterprise".into(),
        },
        LinuxDistroInfo {
            distro: LinuxDistro::Rocky,
            display_name: "Rocky Linux".into(),
            package_manager: "dnf".into(),
            default_network: "NetworkManager".into(),
            firewall: "firewalld".into(),
            min_version: "8.0".into(),
            max_version: "9.5".into(),
            supported_versions: vec!["8.10".into(), "9.4".into(), "9.5".into()],
            category: "enterprise".into(),
        },
        LinuxDistroInfo {
            distro: LinuxDistro::Alma,
            display_name: "AlmaLinux".into(),
            package_manager: "dnf".into(),
            default_network: "NetworkManager".into(),
            firewall: "firewalld".into(),
            min_version: "8.0".into(),
            max_version: "9.5".into(),
            supported_versions: vec!["8.10".into(), "9.4".into(), "9.5".into()],
            category: "enterprise".into(),
        },
        LinuxDistroInfo {
            distro: LinuxDistro::Ubuntu,
            display_name: "Ubuntu Server".into(),
            package_manager: "apt".into(),
            default_network: "netplan".into(),
            firewall: "ufw".into(),
            min_version: "20.04".into(),
            max_version: "24.04".into(),
            supported_versions: vec!["20.04 LTS".into(), "22.04 LTS".into(), "24.04 LTS".into()],
            category: "community".into(),
        },
        LinuxDistroInfo {
            distro: LinuxDistro::Debian,
            display_name: "Debian".into(),
            package_manager: "apt".into(),
            default_network: "ifupdown".into(),
            firewall: "nftables".into(),
            min_version: "11".into(),
            max_version: "12".into(),
            supported_versions: vec!["11 (bullseye)".into(), "12 (bookworm)".into()],
            category: "community".into(),
        },
    ]
}

fn distro_category(distro: &LinuxDistro) -> &'static str {
    match distro {
        LinuxDistro::Sles | LinuxDistro::Rhel | LinuxDistro::Rocky | LinuxDistro::Alma => {
            "enterprise"
        }
        LinuxDistro::Ubuntu | LinuxDistro::Debian => "community",
    }
}

fn distro_baseline_config(distro: &LinuxDistro) -> &'static str {
    match distro {
        LinuxDistro::Sles => {
            "DRY-RUN: SLES baseline — zypper, wicked, firewalld, SUSEFirewall2, systemd-journald, \
             AppArmor, pam_tally2, audisp-remote, cloud-init-suse"
        }
        LinuxDistro::Rhel => {
            "DRY-RUN: RHEL baseline — dnf, NetworkManager, firewalld, systemd-journald, SELinux \
             enforcing, faillock, audisp-remote, cloud-init-rhel"
        }
        LinuxDistro::Rocky => {
            "DRY-RUN: Rocky baseline — dnf, NetworkManager, firewalld, systemd-journald, SELinux \
             enforcing, faillock, audisp-remote, cloud-init-rocky"
        }
        LinuxDistro::Alma => {
            "DRY-RUN: AlmaLinux baseline — dnf, NetworkManager, firewalld, systemd-journald, \
             SELinux enforcing, faillock, audisp-remote, cloud-init-alma"
        }
        LinuxDistro::Ubuntu => {
            "DRY-RUN: Ubuntu baseline — apt, netplan, ufw, systemd-journald, AppArmor, \
             pam_tally2, rsyslog, cloud-init-ubuntu"
        }
        LinuxDistro::Debian => {
            "DRY-RUN: Debian baseline — apt, ifupdown, nftables, systemd-journald, AppArmor, \
             pam_tally2, rsyslog, cloud-init-debian"
        }
    }
}

fn cloud_init_config(distro: &LinuxDistro, hostname: &str, network: &str) -> String {
    let (pkg_update, pkg_install, agents) = match distro {
        LinuxDistro::Sles => (
            "zypper --non-interactive update",
            "zypper --non-interactive install",
            "open-vm-tools",
        ),
        LinuxDistro::Rhel | LinuxDistro::Rocky | LinuxDistro::Alma => {
            ("dnf update -y", "dnf install -y", "open-vm-tools")
        }
        LinuxDistro::Ubuntu | LinuxDistro::Debian => (
            "apt update && apt upgrade -y",
            "apt install -y",
            "open-vm-tools",
        ),
    };

    format!(
        "DRY-RUN cloud-init config for {distro} (network: {network}):\n\
         #cloud-config\n\
         hostname: {hostname}\n\
         fqdn: {hostname}.corp.local\n\
         package_update: true\n\
         package_upgrade: {pkg_update}\n\
         packages:\n\
           - {pkg_install}\n\
           - chrony\n\
           - rsyslog\n\
           - auditd\n\
         runcmd:\n\
           - [{pkg_update}]\n\
           - [{pkg_install} {agents}]\n\
           - systemctl enable chronyd\n\
           - systemctl enable auditd",
    )
}

fn join_domain_plan(distro: &LinuxDistro) -> &'static str {
    match distro {
        LinuxDistro::Sles | LinuxDistro::Rhel | LinuxDistro::Rocky | LinuxDistro::Alma => {
            "DRY-RUN: Join domain via SSSD/realmd — realm discover corp.local && realm join \
             corp.local (simulated, no LDAP/AD calls)"
        }
        LinuxDistro::Ubuntu | LinuxDistro::Debian => {
            "DRY-RUN: Join domain via SSSD/realmd — apt install realmd sssd && realm join \
             corp.local (simulated, no LDAP/AD calls)"
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_linux_deployment(
    distro: LinuxDistro,
    version: &str,
    site: &str,
    cpu: u32,
    memory_gb: u32,
    disk_gb: u32,
    hostname: &str,
    network: &str,
    hardening_profile: HardeningProfile,
) -> Result<LinuxDeploymentRequest, String> {
    if site.is_empty() || !VALID_SITES.contains(&site) {
        return Err(format!("Unknown or empty site: {}", site));
    }
    if hostname.is_empty() {
        return Err("hostname cannot be empty".into());
    }
    if network.is_empty() {
        return Err("network cannot be empty".into());
    }
    if cpu == 0 {
        return Err("cpu must be at least 1".into());
    }
    if memory_gb == 0 {
        return Err("memory_gb must be at least 1".into());
    }
    if disk_gb == 0 {
        return Err("disk_gb must be at least 1".into());
    }
    if version.is_empty() {
        return Err("version cannot be empty".into());
    }

    let catalog = supported_distro_catalog();
    let info = catalog
        .iter()
        .find(|d| d.distro == distro)
        .ok_or_else(|| format!("Distro {} not in catalog", distro))?;

    if !info.supported_versions.contains(&version.to_string()) {
        return Err(format!(
            "Version {} not supported for {}. Supported: {:?}",
            version, distro, info.supported_versions
        ));
    }

    let id = format!(
        "ldep-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let now = chrono::Utc::now().to_rfc3339();

    let plan = LinuxDeploymentPlan {
        placement: LinuxPlacement {
            hypervisor: "VMware".into(),
            cluster: format!("DRY-RUN: cluster-{}-prod", site.to_lowercase()),
            host: format!("DRY-RUN: esx-{}-01", site.to_lowercase()),
            datastore: "DRY-RUN: vsan-datastore-01".into(),
            resource_pool: "DRY-RUN: pool-linux-production".into(),
        },
        storage: LinuxStoragePlan {
            disk_gb,
            datastore: "DRY-RUN: vsan-datastore-01".into(),
            thin_provisioned: true,
            disk_controller: "paravirtual".into(),
        },
        network: LinuxNetworkPlan {
            network_label: format!("DRY-RUN: {}", network),
            adapter_type: "VMXNET3".into(),
            dhcp: false,
            dns_servers: vec!["DRY-RUN: 10.0.0.5".into(), "DRY-RUN: 10.0.0.6".into()],
            gateway: "DRY-RUN: auto-from-network-profile".into(),
        },
        cloud_init: cloud_init_config(&distro, hostname, network),
        distro_baseline: distro_baseline_config(&distro).to_string(),
        join_domain: join_domain_plan(&distro).to_string(),
        hardening_plan: format!(
            "DRY-RUN: Apply {} hardening profile for {} {}. \
             Remediation steps: update sshd_config, configure auditd rules, \
             set password policy, disable unused services, apply sysctl settings \
             (simulated, no live system changes)",
            hardening_profile, distro, version
        ),
        backup_policy: format!(
            "DRY-RUN: Assign backup policy 'linux-{}-daily' for site {}. \
             Retention: 30 daily, 12 monthly, 7 yearly. (simulated, no Veeam calls)",
            distro_category(&distro),
            site
        ),
        monitoring_profile: format!(
            "DRY-RUN: Onboard to monitoring — agent installed, host groups \
             'Linux Servers' and '{}-{}' assigned. Template: 'OS Linux by Zabbix agent' \
             (simulated, no Zabbix calls)",
            distro, site
        ),
    };

    Ok(LinuxDeploymentRequest {
        id,
        distro,
        version: version.to_string(),
        site: site.to_string(),
        cpu,
        memory_gb,
        disk_gb,
        hostname: hostname.to_string(),
        network: network.to_string(),
        hardening_profile,
        status: LinuxDeploymentStatus::Planned,
        plan: Some(plan),
        created_at: now.clone(),
        updated_at: now,
        metadata: HashMap::from([("dry_run".into(), "true".into())]),
    })
}

pub fn validate_linux_deployment(
    request: &LinuxDeploymentRequest,
) -> Result<ValidationResult, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if request.site.is_empty() {
        errors.push("Missing site".into());
        failed_rules.push("p0-site-required".into());
        remediation.push("Provide a valid site code.".into());
    } else if !VALID_SITES.contains(&request.site.as_str()) {
        errors.push(format!("Unknown site: {}", request.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(format!("Select a known site from: {:?}", VALID_SITES));
    }

    if request.hostname.is_empty() {
        errors.push("Missing hostname".into());
        failed_rules.push("p0-hostname-required".into());
        remediation.push("Provide a valid hostname.".into());
    }

    if request.hostname.len() > 15 {
        warnings.push(format!(
            "Hostname '{}' exceeds 15 characters — may cause NetBIOS truncation",
            request.hostname
        ));
    }

    if request.cpu == 0 {
        errors.push("CPU must be at least 1".into());
        failed_rules.push("p0-invalid-cpu".into());
        remediation.push("Provide a valid CPU count (min 1).".into());
    }
    if request.cpu > 128 {
        warnings.push("CPU count > 128 may not be supported by all cluster hosts".into());
    }

    if request.memory_gb == 0 {
        errors.push("Memory must be at least 1 GB".into());
        failed_rules.push("p0-invalid-memory".into());
        remediation.push("Provide a valid memory size in GB (min 1).".into());
    }
    if request.memory_gb > 6144 {
        warnings.push("Memory > 6144 GB may exceed single-host capacity".into());
    }

    if request.disk_gb == 0 {
        errors.push("Disk must be at least 1 GB".into());
        failed_rules.push("p0-invalid-disk".into());
        remediation.push("Provide a valid disk size in GB (min 1).".into());
    }

    if request.version.is_empty() {
        errors.push("Missing version".into());
        failed_rules.push("p0-version-required".into());
        remediation.push("Provide a supported distro version.".into());
    }

    let catalog = supported_distro_catalog();
    if let Some(info) = catalog.iter().find(|d| d.distro == request.distro) {
        if !info.supported_versions.contains(&request.version) {
            errors.push(format!(
                "Unsupported version '{}' for distro {}",
                request.version, request.distro
            ));
            failed_rules.push("p0-unsupported-version".into());
            remediation.push(format!(
                "Select a version from supported list: {:?}",
                info.supported_versions
            ));
        }
    } else {
        errors.push(format!("Unknown distro: {}", request.distro));
        failed_rules.push("p0-unknown-distro".into());
        remediation.push("Select a supported distro from the catalog.".into());
    }

    if request.network.is_empty() {
        errors.push("Missing network".into());
        failed_rules.push("p0-network-required".into());
        remediation.push("Provide a valid network label.".into());
    }

    warnings.push("DRY-RUN: No live provider validation performed".into());
    warnings.push("DRY-RUN: Cluster capacity not checked against live inventory".into());
    warnings.push("DRY-RUN: Network assignment not verified against live switchport state".into());

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn execute_linux_deployment(
    request: &LinuxDeploymentRequest,
) -> Result<LinuxDeploymentRequest, String> {
    if request.status == LinuxDeploymentStatus::Completed
        || request.status == LinuxDeploymentStatus::Failed
    {
        return Err(format!(
            "Cannot execute deployment in terminal status: {:?}",
            request.status
        ));
    }
    if request.status != LinuxDeploymentStatus::Planned
        && request.status != LinuxDeploymentStatus::Validated
        && request.status != LinuxDeploymentStatus::Approved
        && request.status != LinuxDeploymentStatus::Locked
    {
        return Err(format!(
            "Cannot execute deployment in status {:?}. Must be Planned, Validated, Approved, or Locked first.",
            request.status
        ));
    }

    let mut executed = request.clone();
    executed.status = LinuxDeploymentStatus::Executed;
    executed.updated_at = chrono::Utc::now().to_rfc3339();
    executed.metadata.insert(
        "execution_log".into(),
        format!(
            "DRY-RUN: Simulated VM create for {} on {} (no hypervisor calls made). \
             cloud-init applied, domain join triggered, agent bootstrap initiated.",
            request.hostname, request.site
        ),
    );
    executed.metadata.insert(
        "vm_create_summary".into(),
        format!(
            "DRY-RUN: VM {} created with {}/{} GB/{}/{} GB on {}. \
             (Simulated — no VMware/Hyper-V/Proxmox calls)",
            request.hostname,
            request.cpu,
            request.memory_gb,
            request.disk_gb,
            request.hardening_profile,
            request.site
        ),
    );

    Ok(executed)
}

pub fn verify_linux_deployment(
    request: &LinuxDeploymentRequest,
) -> Result<LinuxDeploymentVerification, String> {
    if request.status != LinuxDeploymentStatus::Executed
        && request.status != LinuxDeploymentStatus::Verified
    {
        return Err(format!(
            "Cannot verify deployment in status {:?}. Must be Executed first.",
            request.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "linux-pre-deploy-inventory".into(),
        value: format!(
            "DRY-RUN: Pre-deployment inventory snapshot for {} (simulated)",
            request.hostname
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "linux-post-deploy-state".into(),
        value: format!(
            "DRY-RUN: Post-deployment state verification for {} — VM present, \
             OS booted, cloud-init completed (simulated)",
            request.hostname
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence.push(EvidenceItem {
        key: "linux-agent-running".into(),
        value: format!(
            "DRY-RUN: Monitoring agent running on {} — check 'zabbix_agentd' process \
             (simulated, no Zabbix calls)",
            request.hostname
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    evidence.push(EvidenceItem {
        key: "linux-monitoring-onboarded".into(),
        value: format!(
            "DRY-RUN: Host {} registered in monitoring system, template applied, \
             host groups assigned (simulated, no Zabbix calls)",
            request.hostname
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    evidence.push(EvidenceItem {
        key: "linux-backup-assigned".into(),
        value: format!(
            "DRY-RUN: Backup policy 'linux-daily' assigned to {} at site {} \
             (simulated, no Veeam calls)",
            request.hostname, request.site
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    evidence.push(EvidenceItem {
        key: "linux-domain-joined".into(),
        value: format!(
            "DRY-RUN: {} joined to domain corp.local via SSSD/realmd \
             (simulated, no AD LDAP calls)",
            request.hostname
        ),
        redacted_value: Some("***DRY-RUN SIMULATION***".into()),
        redacted: true,
        evidence_type: EvidenceType::ExecutionLog,
    });

    evidence.push(EvidenceItem {
        key: "linux-hardening-applied".into(),
        value: format!(
            "DRY-RUN: {} hardening profile applied for {} {} \
             (simulated, no system configuration changes)",
            request.hardening_profile, request.distro, request.version
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::PolicyAssignment,
    });

    Ok(LinuxDeploymentVerification {
        id: format!(
            "ldv-{}",
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        deployment_id: request.id.clone(),
        hostname_ok: true,
        agent_running: true,
        monitoring_onboarded: true,
        backup_assigned: true,
        domain_joined: true,
        hardening_applied: true,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_distro_catalog_has_six_entries() {
        let catalog = supported_distro_catalog();
        assert_eq!(catalog.len(), 6);
        let names: Vec<String> = catalog.iter().map(|d| d.distro.to_string()).collect();
        assert!(names.iter().any(|n| n == "sles"));
        assert!(names.iter().any(|n| n == "rhel"));
        assert!(names.iter().any(|n| n == "ubuntu"));
        assert!(names.iter().any(|n| n == "debian"));
    }

    #[test]
    fn test_plan_linux_deployment_ubuntu() {
        let req = plan_linux_deployment(
            LinuxDistro::Ubuntu,
            "22.04 LTS",
            "DEFRA",
            4,
            16,
            100,
            "srv-app-01",
            "VLAN100",
            HardeningProfile::CisLevel1,
        )
        .unwrap();
        assert!(req.id.starts_with("ldep-"));
        assert_eq!(req.status, LinuxDeploymentStatus::Planned);
        assert!(req.plan.is_some());
        let plan = req.plan.as_ref().unwrap();
        assert!(plan.cloud_init.contains("apt"));
        assert!(plan.distro_baseline.contains("Ubuntu"));
        assert!(plan.join_domain.contains("SSSD"));
    }

    #[test]
    fn test_plan_linux_deployment_sles() {
        let req = plan_linux_deployment(
            LinuxDistro::Sles,
            "15.5",
            "GBLON",
            8,
            32,
            200,
            "srv-db-01",
            "VLAN200",
            HardeningProfile::Stig,
        )
        .unwrap();
        let plan = req.plan.unwrap();
        assert!(plan.distro_baseline.contains("SLES"));
        assert!(plan.distro_baseline.contains("zypper"));
        assert!(plan.hardening_plan.contains("stig"));
        assert_eq!(req.cpu, 8);
        assert_eq!(req.memory_gb, 32);
    }

    #[test]
    fn test_plan_linux_deployment_debian() {
        let req = plan_linux_deployment(
            LinuxDistro::Debian,
            "12 (bookworm)",
            "NLAMS",
            2,
            8,
            50,
            "srv-web-01",
            "VLAN300",
            HardeningProfile::CisLevel2,
        )
        .unwrap();
        let plan = req.plan.unwrap();
        assert!(plan.distro_baseline.contains("Debian"));
        assert!(plan.distro_baseline.contains("nftables"));
        assert!(plan.cloud_init.contains("apt"));
        assert_eq!(req.site, "NLAMS");
    }

    #[test]
    fn test_plan_linux_deployment_empty_hostname_fails() {
        assert!(
            plan_linux_deployment(
                LinuxDistro::Ubuntu,
                "22.04 LTS",
                "DEFRA",
                4,
                16,
                100,
                "",
                "VLAN100",
                HardeningProfile::CisLevel1,
            )
            .is_err()
        );
    }

    #[test]
    fn test_plan_linux_deployment_unknown_site_fails() {
        assert!(
            plan_linux_deployment(
                LinuxDistro::Ubuntu,
                "22.04 LTS",
                "UNKNOWN",
                4,
                16,
                100,
                "srv-01",
                "VLAN100",
                HardeningProfile::CisLevel1,
            )
            .is_err()
        );
    }

    #[test]
    fn test_plan_linux_deployment_zero_cpu_fails() {
        assert!(
            plan_linux_deployment(
                LinuxDistro::Rhel,
                "9.4",
                "DEFRA",
                0,
                16,
                100,
                "srv-01",
                "VLAN100",
                HardeningProfile::CisLevel1,
            )
            .is_err()
        );
    }

    #[test]
    fn test_plan_linux_deployment_unsupported_version_fails() {
        assert!(
            plan_linux_deployment(
                LinuxDistro::Ubuntu,
                "99.99 LTS",
                "DEFRA",
                4,
                16,
                100,
                "srv-01",
                "VLAN100",
                HardeningProfile::CisLevel1,
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_linux_deployment_passes() {
        let req = plan_linux_deployment(
            LinuxDistro::Rocky,
            "9.4",
            "DEFRA",
            4,
            16,
            100,
            "srv-app-01",
            "VLAN100",
            HardeningProfile::CisLevel1,
        )
        .unwrap();
        let result = validate_linux_deployment(&req).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_linux_deployment_detects_bad_site() {
        let mut req = plan_linux_deployment(
            LinuxDistro::Alma,
            "9.4",
            "DEFRA",
            4,
            16,
            100,
            "srv-app-01",
            "VLAN100",
            HardeningProfile::CisLevel1,
        )
        .unwrap();
        req.site = "INVALID".into();
        let result = validate_linux_deployment(&req).unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("Unknown site")));
    }

    #[test]
    fn test_validate_linux_deployment_detects_missing_hostname() {
        let mut req = plan_linux_deployment(
            LinuxDistro::Ubuntu,
            "24.04 LTS",
            "GBLON",
            2,
            8,
            50,
            "srv-01",
            "VLAN100",
            HardeningProfile::CisLevel1,
        )
        .unwrap();
        req.hostname = "".into();
        let result = validate_linux_deployment(&req).unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e == "Missing hostname"));
    }

    #[test]
    fn test_execute_linux_deployment() {
        let req = plan_linux_deployment(
            LinuxDistro::Ubuntu,
            "22.04 LTS",
            "DEFRA",
            4,
            16,
            100,
            "srv-app-01",
            "VLAN100",
            HardeningProfile::CisLevel1,
        )
        .unwrap();
        let executed = execute_linux_deployment(&req).unwrap();
        assert_eq!(executed.status, LinuxDeploymentStatus::Executed);
        assert!(executed.metadata.contains_key("execution_log"));
        assert!(executed.metadata.contains_key("vm_create_summary"));
    }

    #[test]
    fn test_verify_linux_deployment() {
        let mut req = plan_linux_deployment(
            LinuxDistro::Debian,
            "12 (bookworm)",
            "NLAMS",
            2,
            8,
            50,
            "srv-web-01",
            "VLAN300",
            HardeningProfile::CisLevel2,
        )
        .unwrap();
        req.status = LinuxDeploymentStatus::Executed;
        let verification = verify_linux_deployment(&req).unwrap();
        assert!(verification.hostname_ok);
        assert!(verification.agent_running);
        assert!(verification.monitoring_onboarded);
        assert!(verification.backup_assigned);
        assert!(verification.domain_joined);
        assert!(verification.hardening_applied);
        assert_eq!(verification.evidence.len(), 7);
        assert!(
            verification
                .evidence
                .iter()
                .any(|e| e.key == "linux-agent-running")
        );
        assert!(
            verification
                .evidence
                .iter()
                .any(|e| e.key == "linux-backup-assigned")
        );
    }

    #[test]
    fn test_verify_deployment_not_executed_fails() {
        let req = plan_linux_deployment(
            LinuxDistro::Ubuntu,
            "22.04 LTS",
            "DEFRA",
            4,
            16,
            100,
            "srv-01",
            "VLAN100",
            HardeningProfile::CisLevel1,
        )
        .unwrap();
        assert!(verify_linux_deployment(&req).is_err());
    }

    #[test]
    fn test_all_distros_have_baseline() {
        let distros = [
            LinuxDistro::Sles,
            LinuxDistro::Rhel,
            LinuxDistro::Rocky,
            LinuxDistro::Alma,
            LinuxDistro::Ubuntu,
            LinuxDistro::Debian,
        ];
        for d in &distros {
            let baseline = distro_baseline_config(d);
            assert!(!baseline.is_empty());
            assert!(baseline.contains("DRY-RUN"));
        }
    }

    #[test]
    fn test_all_distros_have_join_domain_plan() {
        let distros = [
            LinuxDistro::Sles,
            LinuxDistro::Rhel,
            LinuxDistro::Rocky,
            LinuxDistro::Alma,
            LinuxDistro::Ubuntu,
            LinuxDistro::Debian,
        ];
        for d in &distros {
            let plan = join_domain_plan(d);
            assert!(!plan.is_empty());
            assert!(plan.contains("DRY-RUN"));
            assert!(plan.contains("SSSD"));
        }
    }

    #[test]
    fn test_plan_large_deployment_produces_warnings_on_validate() {
        let req = plan_linux_deployment(
            LinuxDistro::Rhel,
            "9.5",
            "DEFRA",
            256,
            8192,
            10000,
            "massive-server-name",
            "VLAN100",
            HardeningProfile::Stig,
        )
        .unwrap();
        let result = validate_linux_deployment(&req).unwrap();
        assert!(result.passed);
        assert!(result.warnings.iter().any(|w| w.contains("truncation")));
        assert!(result.warnings.iter().any(|w| w.contains("128")));
    }

    #[test]
    fn test_catalog_distro_categories() {
        assert_eq!(distro_category(&LinuxDistro::Sles), "enterprise");
        assert_eq!(distro_category(&LinuxDistro::Rhel), "enterprise");
        assert_eq!(distro_category(&LinuxDistro::Rocky), "enterprise");
        assert_eq!(distro_category(&LinuxDistro::Alma), "enterprise");
        assert_eq!(distro_category(&LinuxDistro::Ubuntu), "community");
        assert_eq!(distro_category(&LinuxDistro::Debian), "community");
    }

    #[test]
    fn test_catalog_versions_non_empty() {
        let catalog = supported_distro_catalog();
        for info in catalog {
            assert!(!info.supported_versions.is_empty());
            assert!(!info.display_name.is_empty());
            assert!(!info.package_manager.is_empty());
            assert!(!info.default_network.is_empty());
        }
    }
}
