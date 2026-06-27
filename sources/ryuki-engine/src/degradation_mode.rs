use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComponentStatus {
    Up,
    Degraded,
    Down,
}

impl std::fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentStatus::Up => write!(f, "up"),
            ComponentStatus::Degraded => write!(f, "degraded"),
            ComponentStatus::Down => write!(f, "down"),
        }
    }
}

impl ComponentStatus {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "degraded" => ComponentStatus::Degraded,
            "down" => ComponentStatus::Down,
            _ => ComponentStatus::Up,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SiteDegradationState {
    Healthy,
    Degraded,
    Unreachable,
    Recovering,
}

impl std::fmt::Display for SiteDegradationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteDegradationState::Healthy => write!(f, "healthy"),
            SiteDegradationState::Degraded => write!(f, "degraded"),
            SiteDegradationState::Unreachable => write!(f, "unreachable"),
            SiteDegradationState::Recovering => write!(f, "recovering"),
        }
    }
}

impl SiteDegradationState {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "degraded" => SiteDegradationState::Degraded,
            "unreachable" => SiteDegradationState::Unreachable,
            "recovering" => SiteDegradationState::Recovering,
            _ => SiteDegradationState::Healthy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterComponentStatus {
    pub vmware: ComponentStatus,
    pub hyperv: ComponentStatus,
    pub proxmox: ComponentStatus,
    pub nutanix: ComponentStatus,
    pub xen: ComponentStatus,
    pub kvm: ComponentStatus,
    pub veeam: ComponentStatus,
    pub zabbix: ComponentStatus,
    pub servicenow: ComponentStatus,
    pub commvault: ComponentStatus,
    pub rubrik: ComponentStatus,
    pub cohesity: ComponentStatus,
    pub netbackup: ComponentStatus,
}

impl Default for AdapterComponentStatus {
    fn default() -> Self {
        AdapterComponentStatus {
            vmware: ComponentStatus::Up,
            hyperv: ComponentStatus::Up,
            proxmox: ComponentStatus::Up,
            nutanix: ComponentStatus::Up,
            xen: ComponentStatus::Up,
            kvm: ComponentStatus::Up,
            veeam: ComponentStatus::Up,
            zabbix: ComponentStatus::Up,
            servicenow: ComponentStatus::Up,
            commvault: ComponentStatus::Up,
            rubrik: ComponentStatus::Up,
            cohesity: ComponentStatus::Up,
            netbackup: ComponentStatus::Up,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteStatus {
    pub site: String,
    pub state: SiteDegradationState,
    pub api_status: ComponentStatus,
    pub db_status: ComponentStatus,
    pub adapter_status: AdapterComponentStatus,
    pub degradation_reason: Option<String>,
    pub last_check: String,
}

impl SiteStatus {
    pub fn healthy(site: &str) -> Self {
        SiteStatus {
            site: site.to_string(),
            state: SiteDegradationState::Healthy,
            api_status: ComponentStatus::Up,
            db_status: ComponentStatus::Up,
            adapter_status: AdapterComponentStatus::default(),
            degradation_reason: None,
            last_check: Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalStatus {
    pub sites: Vec<SiteStatus>,
    pub overall_health: SiteDegradationState,
    pub total_sites: usize,
    pub healthy_sites: usize,
    pub degraded_sites: usize,
    pub unreachable_sites: usize,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DegradationRule {
    pub id: String,
    pub decision: String,
    pub requirement: String,
    pub evidence: String,
}

fn seed_sites() -> Vec<SiteStatus> {
    let mut defra = SiteStatus::healthy("DEFRA");
    let mut gblon = SiteStatus {
        site: "GBLON".into(),
        state: SiteDegradationState::Degraded,
        api_status: ComponentStatus::Degraded,
        db_status: ComponentStatus::Up,
        adapter_status: AdapterComponentStatus {
            vmware: ComponentStatus::Up,
            hyperv: ComponentStatus::Degraded,
            proxmox: ComponentStatus::Up,
            nutanix: ComponentStatus::Up,
            xen: ComponentStatus::Up,
            kvm: ComponentStatus::Up,
            veeam: ComponentStatus::Degraded,
            zabbix: ComponentStatus::Up,
            servicenow: ComponentStatus::Up,
            commvault: ComponentStatus::Up,
            rubrik: ComponentStatus::Up,
            cohesity: ComponentStatus::Up,
            netbackup: ComponentStatus::Up,
        },
        degradation_reason: Some(
            "Hyper-V and Veeam adapters reporting degraded connectivity".into(),
        ),
        last_check: Utc::now().to_rfc3339(),
    };
    let mut nlams = SiteStatus {
        site: "NLAMS".into(),
        state: SiteDegradationState::Unreachable,
        api_status: ComponentStatus::Down,
        db_status: ComponentStatus::Down,
        adapter_status: AdapterComponentStatus {
            vmware: ComponentStatus::Down,
            hyperv: ComponentStatus::Down,
            proxmox: ComponentStatus::Down,
            nutanix: ComponentStatus::Down,
            xen: ComponentStatus::Down,
            kvm: ComponentStatus::Down,
            veeam: ComponentStatus::Down,
            zabbix: ComponentStatus::Down,
            servicenow: ComponentStatus::Down,
            commvault: ComponentStatus::Down,
            rubrik: ComponentStatus::Down,
            cohesity: ComponentStatus::Down,
            netbackup: ComponentStatus::Down,
        },
        degradation_reason: Some("Site NLAMS network unreachable, all components down".into()),
        last_check: Utc::now().to_rfc3339(),
    };

    defra.last_check = Utc::now().to_rfc3339();
    gblon.last_check = Utc::now().to_rfc3339();
    nlams.last_check = Utc::now().to_rfc3339();

    vec![defra, gblon, nlams]
}

pub fn get_site_statuses() -> Vec<SiteStatus> {
    seed_sites()
}

pub fn check_site_health(site: &str) -> SiteStatus {
    let sites = seed_sites();
    if let Some(found) = sites.into_iter().find(|s| s.site == site) {
        return found;
    }
    SiteStatus {
        site: site.to_string(),
        state: SiteDegradationState::Healthy,
        api_status: ComponentStatus::Up,
        db_status: ComponentStatus::Up,
        adapter_status: AdapterComponentStatus::default(),
        degradation_reason: None,
        last_check: Utc::now().to_rfc3339(),
    }
}

pub fn global_status_from(sites: Vec<SiteStatus>) -> GlobalStatus {
    let total = sites.len();
    let healthy_count = sites
        .iter()
        .filter(|s| s.state == SiteDegradationState::Healthy)
        .count();
    let degraded_count = sites
        .iter()
        .filter(|s| s.state == SiteDegradationState::Degraded)
        .count();
    let unreachable_count = sites
        .iter()
        .filter(|s| s.state == SiteDegradationState::Unreachable)
        .count();
    let overall = if unreachable_count > 0 {
        SiteDegradationState::Unreachable
    } else if degraded_count > 0 {
        SiteDegradationState::Degraded
    } else {
        SiteDegradationState::Healthy
    };
    GlobalStatus {
        sites,
        overall_health: overall,
        total_sites: total,
        healthy_sites: healthy_count,
        degraded_sites: degraded_count,
        unreachable_sites: unreachable_count,
        timestamp: Utc::now().to_rfc3339(),
    }
}

pub fn get_global_status() -> GlobalStatus {
    global_status_from(seed_sites())
}

pub fn get_degraded_sites() -> Vec<SiteStatus> {
    seed_sites()
        .into_iter()
        .filter(|s| {
            s.state == SiteDegradationState::Degraded
                || s.state == SiteDegradationState::Unreachable
        })
        .collect()
}

pub fn enter_degradation_mode(site: &str, reason: &str) -> SiteStatus {
    SiteStatus {
        site: site.to_string(),
        state: SiteDegradationState::Degraded,
        api_status: ComponentStatus::Degraded,
        db_status: ComponentStatus::Degraded,
        adapter_status: AdapterComponentStatus {
            vmware: ComponentStatus::Degraded,
            hyperv: ComponentStatus::Degraded,
            proxmox: ComponentStatus::Degraded,
            nutanix: ComponentStatus::Degraded,
            xen: ComponentStatus::Degraded,
            kvm: ComponentStatus::Degraded,
            veeam: ComponentStatus::Degraded,
            zabbix: ComponentStatus::Degraded,
            servicenow: ComponentStatus::Degraded,
            commvault: ComponentStatus::Degraded,
            rubrik: ComponentStatus::Degraded,
            cohesity: ComponentStatus::Degraded,
            netbackup: ComponentStatus::Degraded,
        },
        degradation_reason: Some(reason.to_string()),
        last_check: Utc::now().to_rfc3339(),
    }
}

pub fn exit_degradation_mode(site: &str) -> SiteStatus {
    let mut status = SiteStatus::healthy(site);
    status.state = SiteDegradationState::Recovering;
    status.degradation_reason =
        Some("DRY-RUN: Site marked as recovering, exiting degradation mode".into());
    status
}

pub fn get_degradation_rules() -> Vec<DegradationRule> {
    vec![
        DegradationRule {
            id: "write-execution-blocked-when-degraded".into(),
            decision: "block".into(),
            requirement:
                "Write-capable workflows remain blocked while affected scope is degraded or stale."
                    .into(),
            evidence: "Blocked execution decision".into(),
        },
        DegradationRule {
            id: "stale-data-must-be-marked".into(),
            decision: "block".into(),
            requirement:
                "Cached or stale data must be marked before read-only views can be shown.".into(),
            evidence: "Stale-data marker".into(),
        },
        DegradationRule {
            id: "affected-scope-required".into(),
            decision: "block".into(),
            requirement:
                "Degraded site, provider, adapter, dependency, workflow, or evidence scope must be explicit."
                    .into(),
            evidence: "Affected scope".into(),
        },
        DegradationRule {
            id: "no-automatic-faidefrar".into(),
            decision: "block".into(),
            requirement:
                "Degradation mode can suggest safe remediation but must not perform automatic faidefrar."
                    .into(),
            evidence: "Safe remediation".into(),
        },
    ]
}

pub fn get_degradation_contract() -> serde_json::Value {
    serde_json::json!({
        "source": "static-seed",
        "degradationMode": "fail-safe-read-only",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "faidefrarAutomationAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "degradationScopes": ["site","provider","adapter","dependency","workflow","evidence"],
        "degradationStates": ["normal","degraded-read-only","stale-read-only","blocked","recovering"],
        "safeCapabilities": ["read-only-inventory","evidence-read","request-intake","plan-only","handover","remediation-guidance"],
        "requiredInputs": ["affectedScope","degradationState","dependencyStatus","staleDataMarker","owner","safeRemediation","evidenceManifest"],
        "requiredGuards": ["affected-scope-known","dependency-status-known","stale-data-marked","write-execution-blocked","safe-remediation-set","owner-known","evidence-redacted"],
        "blockedReasons": ["affected-scope-unknown","dependency-status-unknown","stale-data-unmarked","write-execution-requested","unsafe-remediation","owner-unknown","evidence-not-redacted"],
        "requiredEvidence": ["Degradation summary","Affected scope","Dependency state","Stale-data marker","Blocked execution decision","Safe remediation","Handover notes","Evidence references"],
        "rules": [
            {"id":"write-execution-blocked-when-degraded","decision":"block","requirement":"Write-capable workflows remain blocked while affected scope is degraded or stale.","evidence":"Blocked execution decision"},
            {"id":"stale-data-must-be-marked","decision":"block","requirement":"Cached or stale data must be marked before read-only views can be shown.","evidence":"Stale-data marker"},
            {"id":"affected-scope-required","decision":"block","requirement":"Degraded site, provider, adapter, dependency, workflow, or evidence scope must be explicit.","evidence":"Affected scope"},
            {"id":"no-automatic-faidefrar","decision":"block","requirement":"Degradation mode can suggest safe remediation but must not perform automatic faidefrar.","evidence":"Safe remediation"}
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_site_health_known_sites() {
        let defra = check_site_health("DEFRA");
        assert_eq!(defra.site, "DEFRA");
        assert_eq!(defra.state, SiteDegradationState::Healthy);
        assert_eq!(defra.api_status, ComponentStatus::Up);

        let gblon = check_site_health("GBLON");
        assert_eq!(gblon.site, "GBLON");
        assert_eq!(gblon.state, SiteDegradationState::Degraded);
        assert_eq!(gblon.adapter_status.hyperv, ComponentStatus::Degraded);

        let nlams = check_site_health("NLAMS");
        assert_eq!(nlams.site, "NLAMS");
        assert_eq!(nlams.state, SiteDegradationState::Unreachable);
    }

    #[test]
    fn test_check_site_health_unknown_site_defaults_healthy() {
        let unknown = check_site_health("UNKNOWN-SITE");
        assert_eq!(unknown.site, "UNKNOWN-SITE");
        assert_eq!(unknown.state, SiteDegradationState::Healthy);
        assert_eq!(unknown.api_status, ComponentStatus::Up);
    }

    #[test]
    fn test_get_global_status_counts() {
        let global = get_global_status();
        assert_eq!(global.total_sites, 3);
        assert_eq!(global.healthy_sites, 1);
        assert_eq!(global.degraded_sites, 1);
        assert_eq!(global.unreachable_sites, 1);
        assert_eq!(global.overall_health, SiteDegradationState::Unreachable);
        assert!(!global.timestamp.is_empty());
    }

    #[test]
    fn test_get_degraded_sites_returns_degraded_and_unreachable() {
        let degraded = get_degraded_sites();
        assert_eq!(degraded.len(), 2);
        let sites: Vec<&str> = degraded.iter().map(|s| s.site.as_str()).collect();
        assert!(sites.contains(&"GBLON"));
        assert!(sites.contains(&"NLAMS"));
    }

    #[test]
    fn test_enter_degradation_mode_marks_all_components_degraded() {
        let status = enter_degradation_mode("DEFRA", "Scheduled maintenance");
        assert_eq!(status.site, "DEFRA");
        assert_eq!(status.state, SiteDegradationState::Degraded);
        assert_eq!(status.api_status, ComponentStatus::Degraded);
        assert_eq!(status.db_status, ComponentStatus::Degraded);
        assert_eq!(status.adapter_status.vmware, ComponentStatus::Degraded);
        assert_eq!(status.adapter_status.zabbix, ComponentStatus::Degraded);
        assert_eq!(
            status.degradation_reason,
            Some("Scheduled maintenance".into())
        );
    }

    #[test]
    fn test_exit_degradation_mode_sets_recovering_state() {
        let status = exit_degradation_mode("GBLON");
        assert_eq!(status.site, "GBLON");
        assert_eq!(status.state, SiteDegradationState::Recovering);
        assert!(status.degradation_reason.unwrap().contains("DRY-RUN"));
        assert_eq!(status.api_status, ComponentStatus::Up);
    }

    #[test]
    fn test_get_degradation_rules_returns_four_rules() {
        let rules = get_degradation_rules();
        assert_eq!(rules.len(), 4);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"write-execution-blocked-when-degraded"));
        assert!(ids.contains(&"stale-data-must-be-marked"));
        assert!(ids.contains(&"affected-scope-required"));
        assert!(ids.contains(&"no-automatic-faidefrar"));
        for rule in &rules {
            assert_eq!(rule.decision, "block");
        }
    }

    #[test]
    fn test_get_degradation_contract_has_all_fields() {
        let contract = get_degradation_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["degradationMode"], "fail-safe-read-only");
        assert_eq!(contract["providerCallsEnabled"], false);
        assert_eq!(contract["liveExecutionAllowed"], false);
        assert_eq!(contract["faidefrarAutomationAllowed"], false);
        assert_eq!(contract["rawProviderPayloadsAllowed"], false);
        assert!(contract["degradationScopes"].as_array().unwrap().len() == 6);
        assert!(contract["rules"].as_array().unwrap().len() == 4);
    }

    #[test]
    fn test_site_status_serialization_roundtrip() {
        let status = check_site_health("DEFRA");
        let json = serde_json::to_string(&status).expect("Failed to serialize");
        let deserialized: SiteStatus = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(status.site, deserialized.site);
        assert_eq!(status.state, deserialized.state);
    }

    #[test]
    fn test_global_status_serialization_roundtrip() {
        let global = get_global_status();
        let json = serde_json::to_string(&global).expect("Failed to serialize");
        let deserialized: GlobalStatus =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(global.total_sites, deserialized.total_sites);
        assert_eq!(global.overall_health, deserialized.overall_health);
    }

    #[test]
    fn test_component_status_display() {
        assert_eq!(ComponentStatus::Up.to_string(), "up");
        assert_eq!(ComponentStatus::Degraded.to_string(), "degraded");
        assert_eq!(ComponentStatus::Down.to_string(), "down");
    }

    #[test]
    fn test_site_degradation_state_display() {
        assert_eq!(SiteDegradationState::Healthy.to_string(), "healthy");
        assert_eq!(SiteDegradationState::Degraded.to_string(), "degraded");
        assert_eq!(SiteDegradationState::Unreachable.to_string(), "unreachable");
        assert_eq!(SiteDegradationState::Recovering.to_string(), "recovering");
    }

    #[test]
    fn test_component_status_from_str() {
        assert_eq!(ComponentStatus::from_str("up"), ComponentStatus::Up);
        assert_eq!(
            ComponentStatus::from_str("degraded"),
            ComponentStatus::Degraded
        );
        assert_eq!(ComponentStatus::from_str("down"), ComponentStatus::Down);
        assert_eq!(ComponentStatus::from_str("unknown"), ComponentStatus::Up);
    }

    #[test]
    fn test_site_degradation_state_from_str() {
        assert_eq!(
            SiteDegradationState::from_str("healthy"),
            SiteDegradationState::Healthy
        );
        assert_eq!(
            SiteDegradationState::from_str("degraded"),
            SiteDegradationState::Degraded
        );
        assert_eq!(
            SiteDegradationState::from_str("unreachable"),
            SiteDegradationState::Unreachable
        );
        assert_eq!(
            SiteDegradationState::from_str("recovering"),
            SiteDegradationState::Recovering
        );
        assert_eq!(
            SiteDegradationState::from_str("other"),
            SiteDegradationState::Healthy
        );
    }

    #[test]
    fn test_global_status_from_matches_get_global_status() {
        let from_fn = global_status_from(seed_sites());
        let direct = get_global_status();
        assert_eq!(from_fn.total_sites, direct.total_sites);
        assert_eq!(from_fn.healthy_sites, direct.healthy_sites);
        assert_eq!(from_fn.degraded_sites, direct.degraded_sites);
        assert_eq!(from_fn.unreachable_sites, direct.unreachable_sites);
        assert_eq!(from_fn.overall_health, direct.overall_health);
    }
}
