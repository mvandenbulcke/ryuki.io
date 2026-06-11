use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentContext {
    pub incident_id: String,
    pub title: String,
    pub severity: String,
    pub affected_ci: Vec<AffectedCI>,
    pub upstream_deps: Vec<Dependency>,
    pub downstream_deps: Vec<Dependency>,
    pub recent_changes: Vec<RecentChange>,
    pub on_call: OnCallInfo,
    pub related_tickets: Vec<String>,
    pub assembled_at: String,
    pub status: String,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AffectedCI {
    pub ci_name: String,
    pub ci_type: String,
    pub site: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub ci_name: String,
    pub relationship: String,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentChange {
    pub change_id: String,
    pub description: String,
    pub changed_by: String,
    pub timestamp: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnCallInfo {
    pub primary: String,
    pub secondary: String,
    pub escalation: String,
    pub group: String,
}

type IncidentContextStore = Vec<IncidentContext>;

static INCIDENT_CONTEXT_STORE: OnceLock<Mutex<IncidentContextStore>> = OnceLock::new();

fn incident_context_store() -> &'static Mutex<IncidentContextStore> {
    INCIDENT_CONTEXT_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn seed_data() -> IncidentContextStore {
    vec![
        IncidentContext {
            incident_id: "inc-love-001".into(),
            title: "LOVE database latency spike".into(),
            severity: "sev2".into(),
            affected_ci: vec![AffectedCI {
                ci_name: "love-db-cluster".into(),
                ci_type: "database".into(),
                site: "LOVE".into(),
                status: "degraded".into(),
            }],
            upstream_deps: mock_upstream_deps("LOVE"),
            downstream_deps: mock_downstream_deps("LOVE"),
            recent_changes: mock_recent_changes("LOVE"),
            on_call: mock_on_call("LOVE"),
            related_tickets: vec!["INC-LOVE-7421".into(), "CHG-LOVE-219".into()],
            assembled_at: "2026-06-11T10:00:00Z".into(),
            status: "active".into(),
            resolution: None,
        },
        IncidentContext {
            incident_id: "inc-bur1-001".into(),
            title: "BUR1 storage fabric errors".into(),
            severity: "sev1".into(),
            affected_ci: vec![AffectedCI {
                ci_name: "bur1-vsan-cluster".into(),
                ci_type: "storage".into(),
                site: "BUR1".into(),
                status: "critical".into(),
            }],
            upstream_deps: mock_upstream_deps("BUR1"),
            downstream_deps: mock_downstream_deps("BUR1"),
            recent_changes: mock_recent_changes("BUR1"),
            on_call: mock_on_call("BUR1"),
            related_tickets: vec!["INC-BUR1-8844".into(), "CHG-BUR1-118".into()],
            assembled_at: "2026-06-11T09:30:00Z".into(),
            status: "active".into(),
            resolution: None,
        },
    ]
}

fn mock_upstream_deps(site: &str) -> Vec<Dependency> {
    vec![
        Dependency {
            ci_name: format!("{}-core-network", site.to_lowercase()),
            relationship: "network-connectivity".into(),
            direction: "upstream".into(),
        },
        Dependency {
            ci_name: format!("{}-identity-services", site.to_lowercase()),
            relationship: "authentication".into(),
            direction: "upstream".into(),
        },
    ]
}

fn mock_downstream_deps(site: &str) -> Vec<Dependency> {
    vec![
        Dependency {
            ci_name: format!("{}-portal-ui", site.to_lowercase()),
            relationship: "user-facing-service".into(),
            direction: "downstream".into(),
        },
        Dependency {
            ci_name: format!("{}-batch-workers", site.to_lowercase()),
            relationship: "processing-dependency".into(),
            direction: "downstream".into(),
        },
    ]
}

fn mock_recent_changes(site: &str) -> Vec<RecentChange> {
    vec![
        RecentChange {
            change_id: format!("CHG-{}-net-001", site.to_uppercase()),
            description: format!("{} spine switch policy update", site.to_uppercase()),
            changed_by: "alex.netops".into(),
            timestamp: "2026-06-11T08:45:00Z".into(),
            risk_level: "medium".into(),
        },
        RecentChange {
            change_id: format!("CHG-{}-app-002", site.to_uppercase()),
            description: format!("{} workload placement rebalance", site.to_uppercase()),
            changed_by: "sam.platform".into(),
            timestamp: "2026-06-11T07:15:00Z".into(),
            risk_level: "low".into(),
        },
    ]
}

fn mock_on_call(site: &str) -> OnCallInfo {
    match site.to_uppercase().as_str() {
        "BUR1" => OnCallInfo {
            primary: "casey.storage".into(),
            secondary: "riley.datacenter".into(),
            escalation: "bur1-incident-commander".into(),
            group: "storage-operations".into(),
        },
        _ => OnCallInfo {
            primary: "morgan.platform".into(),
            secondary: "jamie.sre".into(),
            escalation: "love-incident-commander".into(),
            group: "platform-operations".into(),
        },
    }
}

fn ci_type_for(ci_name: &str) -> String {
    if ci_name.contains("db") {
        "database".into()
    } else if ci_name.contains("vsan") || ci_name.contains("storage") {
        "storage".into()
    } else if ci_name.contains("switch") || ci_name.contains("network") {
        "network".into()
    } else {
        "service".into()
    }
}

pub fn assemble_context(
    incident_title: &str,
    severity: &str,
    affected_ci_names: Vec<String>,
    site: &str,
) -> Result<Value, String> {
    if incident_title.trim().is_empty() {
        return Err("incident_title cannot be empty".into());
    }
    if severity.trim().is_empty() {
        return Err("severity cannot be empty".into());
    }
    if affected_ci_names.is_empty() {
        return Err("affected_ci_names cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let normalized_site = site.to_uppercase();
    let incident_id = format!(
        "inc-{}-{}",
        normalized_site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let affected_ci = affected_ci_names
        .into_iter()
        .map(|ci_name| AffectedCI {
            ci_type: ci_type_for(&ci_name),
            ci_name,
            site: normalized_site.clone(),
            status: "impacted".into(),
        })
        .collect::<Vec<_>>();

    let context = IncidentContext {
        incident_id: incident_id.clone(),
        title: incident_title.to_string(),
        severity: severity.to_string(),
        affected_ci,
        upstream_deps: mock_upstream_deps(&normalized_site),
        downstream_deps: mock_downstream_deps(&normalized_site),
        recent_changes: mock_recent_changes(&normalized_site),
        on_call: mock_on_call(&normalized_site),
        related_tickets: vec![format!("INC-{}-DRYRUN", normalized_site)],
        assembled_at: now_iso(),
        status: "active".into(),
        resolution: None,
    };

    incident_context_store()
        .lock()
        .unwrap()
        .push(context.clone());

    Ok(json!({
        "source": "dry-run",
        "action": "assemble_context",
        "incident_id": incident_id,
        "context": context,
    }))
}

pub fn get_context(incident_id: &str) -> Result<Value, String> {
    let store = incident_context_store().lock().unwrap();
    let context = store
        .iter()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    Ok(json!({
        "source": "dry-run",
        "incident_id": incident_id,
        "context": context,
    }))
}

pub fn list_active_incidents() -> Result<Value, String> {
    let store = incident_context_store().lock().unwrap();
    let incidents = store
        .iter()
        .filter(|incident| incident.status != "resolved")
        .cloned()
        .collect::<Vec<_>>();

    Ok(json!({
        "source": "dry-run",
        "count": incidents.len(),
        "incidents": incidents,
    }))
}

pub fn get_affected_services(incident_id: &str) -> Result<Value, String> {
    let store = incident_context_store().lock().unwrap();
    let context = store
        .iter()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    Ok(json!({
        "source": "dry-run",
        "incident_id": incident_id,
        "affected_ci": context.affected_ci,
        "upstream_deps": context.upstream_deps,
        "downstream_deps": context.downstream_deps,
    }))
}

pub fn get_on_call(incident_id: &str) -> Result<Value, String> {
    let store = incident_context_store().lock().unwrap();
    let context = store
        .iter()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    Ok(json!({
        "source": "dry-run",
        "incident_id": incident_id,
        "on_call": context.on_call,
    }))
}

pub fn get_recent_changes(incident_id: &str) -> Result<Value, String> {
    let store = incident_context_store().lock().unwrap();
    let context = store
        .iter()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    Ok(json!({
        "source": "dry-run",
        "incident_id": incident_id,
        "recent_changes": context.recent_changes,
    }))
}

pub fn resolve_incident(incident_id: &str, resolution: &str) -> Result<Value, String> {
    if resolution.trim().is_empty() {
        return Err("resolution cannot be empty".into());
    }

    let mut store = incident_context_store().lock().unwrap();
    let context = store
        .iter_mut()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    context.status = "resolved".into();
    context.resolution = Some(resolution.to_string());

    Ok(json!({
        "source": "dry-run",
        "action": "resolve_incident",
        "incident_id": incident_id,
        "status": context.status,
        "resolution": context.resolution,
    }))
}

pub fn add_affected_ci(incident_id: &str, ci_name: &str, ci_type: &str) -> Result<Value, String> {
    if ci_name.trim().is_empty() {
        return Err("ci_name cannot be empty".into());
    }
    if ci_type.trim().is_empty() {
        return Err("ci_type cannot be empty".into());
    }

    let mut store = incident_context_store().lock().unwrap();
    let context = store
        .iter_mut()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    let site = context
        .affected_ci
        .first()
        .map(|ci| ci.site.clone())
        .unwrap_or_else(|| "UNKNOWN".into());
    let affected_ci = AffectedCI {
        ci_name: ci_name.to_string(),
        ci_type: ci_type.to_string(),
        site,
        status: "impacted".into(),
    };

    context.affected_ci.push(affected_ci.clone());

    Ok(json!({
        "source": "dry-run",
        "action": "add_affected_ci",
        "incident_id": incident_id,
        "affected_ci": affected_ci,
        "affected_count": context.affected_ci.len(),
    }))
}

pub fn escalate(incident_id: &str, reason: &str) -> Result<Value, String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }

    let mut store = incident_context_store().lock().unwrap();
    let context = store
        .iter_mut()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;

    context.on_call.escalation = format!("{} | escalated: {}", context.on_call.escalation, reason);

    Ok(json!({
        "source": "dry-run",
        "action": "escalate",
        "incident_id": incident_id,
        "reason": reason,
        "on_call": context.on_call,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_test_incident(site: &str) -> String {
        let result = assemble_context(
            "test incident",
            "sev2",
            vec![format!("{}-test-ci", site.to_lowercase())],
            site,
        )
        .unwrap();

        result["incident_id"].as_str().unwrap().to_string()
    }

    #[test]
    fn test_assemble_context_creates_incident_with_deps_and_changes() {
        let result = assemble_context(
            "LOVE app latency",
            "sev2",
            vec!["love-app-servers".into()],
            "LOVE",
        )
        .unwrap();

        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["context"]["title"], "LOVE app latency");
        assert!(
            !result["context"]["upstream_deps"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            !result["context"]["downstream_deps"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            !result["context"]["recent_changes"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_get_context_returns_full_assembled_data() {
        let incident_id = new_test_incident("LOVE");
        let result = get_context(&incident_id).unwrap();

        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["context"]["incident_id"], incident_id);
        assert!(result["context"]["on_call"].is_object());
        assert!(result["context"]["related_tickets"].is_array());
    }

    #[test]
    fn test_get_affected_services_returns_ci_list_with_deps() {
        let incident_id = new_test_incident("BUR1");
        let result = get_affected_services(&incident_id).unwrap();

        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["affected_ci"].as_array().unwrap().len(), 1);
        assert!(!result["upstream_deps"].as_array().unwrap().is_empty());
        assert!(!result["downstream_deps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_resolve_incident_marks_resolved() {
        let incident_id = new_test_incident("LOVE");
        let result =
            resolve_incident(&incident_id, "service restored after mock rollback").unwrap();

        assert_eq!(result["status"], "resolved");
        assert_eq!(result["resolution"], "service restored after mock rollback");

        let context = get_context(&incident_id).unwrap();
        assert_eq!(context["context"]["status"], "resolved");
    }

    #[test]
    fn test_escalate_updates_on_call_info() {
        let incident_id = new_test_incident("BUR1");
        let result = escalate(&incident_id, "customer impact exceeded threshold").unwrap();

        assert!(
            result["on_call"]["escalation"]
                .as_str()
                .unwrap()
                .contains("customer impact exceeded threshold")
        );
    }

    #[test]
    fn test_list_active_incidents_filters_resolved() {
        let active_id = new_test_incident("LOVE");
        let resolved_id = new_test_incident("BUR1");
        resolve_incident(&resolved_id, "mock validation complete").unwrap();

        let result = list_active_incidents().unwrap();
        let incidents = result["incidents"].as_array().unwrap();
        let ids = incidents
            .iter()
            .map(|incident| incident["incident_id"].as_str().unwrap())
            .collect::<Vec<_>>();

        assert!(ids.contains(&active_id.as_str()));
        assert!(!ids.contains(&resolved_id.as_str()));
    }
}
