use crate::models::*;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AlertRoute {
    pub id: String,
    pub trigger_name: String,
    pub severity: String,
    pub host_group: String,
    pub support_group: String,
    pub priority: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RouteDecision {
    pub alert_id: String,
    pub route_id: Option<String>,
    pub support_group: String,
    pub escalated: bool,
    pub timestamp: String,
    pub evidence: String,
}

const VALID_SEVERITIES: &[&str] = &["info", "warning", "average", "high", "disaster"];

const VALID_PRIORITIES: &[&str] = &["P1", "P2", "P3", "P4"];

fn seed_routes() -> Vec<AlertRoute> {
    let now = chrono::Utc::now().to_rfc3339();
    vec![
        AlertRoute {
            id: Uuid::new_v4().to_string(),
            trigger_name: "High CPU utilization".into(),
            severity: "high".into(),
            host_group: "Windows Servers".into(),
            support_group: "Wintel Operations".into(),
            priority: "P2".into(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        AlertRoute {
            id: Uuid::new_v4().to_string(),
            trigger_name: "Disk space low".into(),
            severity: "warning".into(),
            host_group: "Linux Servers".into(),
            support_group: "Linux Operations".into(),
            priority: "P3".into(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        AlertRoute {
            id: Uuid::new_v4().to_string(),
            trigger_name: "Service unavailable".into(),
            severity: "disaster".into(),
            host_group: "Critical Infrastructure".into(),
            support_group: "Datacenter Operations".into(),
            priority: "P1".into(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        AlertRoute {
            id: Uuid::new_v4().to_string(),
            trigger_name: "Backup job failed".into(),
            severity: "high".into(),
            host_group: "Veeam Infrastructure".into(),
            support_group: "Backup Operations".into(),
            priority: "P2".into(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
        },
    ]
}

static ROUTE_STORE: std::sync::LazyLock<Mutex<Vec<AlertRoute>>> =
    std::sync::LazyLock::new(|| Mutex::new(seed_routes()));

/// Validate and construct an alert route without changing the legacy in-memory
/// store. Durable callers use this before their database transaction so a
/// failed insert/audit cannot leave a ghost route in process memory.
pub fn prepare_alert_route(
    trigger_name: &str,
    severity: &str,
    host_group: &str,
    support_group: &str,
    priority: &str,
) -> Result<AlertRoute, String> {
    if trigger_name.is_empty() {
        return Err("trigger_name cannot be empty".into());
    }
    if host_group.is_empty() {
        return Err("host_group cannot be empty".into());
    }
    if support_group.is_empty() {
        return Err("support_group cannot be empty".into());
    }
    if !VALID_SEVERITIES.contains(&severity) {
        return Err(format!(
            "Invalid severity: {}. Must be one of: {:?}",
            severity, VALID_SEVERITIES
        ));
    }
    if !VALID_PRIORITIES.contains(&priority) {
        return Err(format!(
            "Invalid priority: {}. Must be one of: {:?}",
            priority, VALID_PRIORITIES
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let route = AlertRoute {
        id: Uuid::new_v4().to_string(),
        trigger_name: trigger_name.to_string(),
        severity: severity.to_string(),
        host_group: host_group.to_string(),
        support_group: support_group.to_string(),
        priority: priority.to_string(),
        enabled: true,
        created_at: now.clone(),
        updated_at: now,
    };

    Ok(route)
}

/// Legacy in-memory constructor retained for dry-run engine consumers.
pub fn build_alert_route(
    trigger_name: &str,
    severity: &str,
    host_group: &str,
    support_group: &str,
    priority: &str,
) -> Result<AlertRoute, String> {
    let route = prepare_alert_route(trigger_name, severity, host_group, support_group, priority)?;
    ROUTE_STORE.lock().unwrap().push(route.clone());
    Ok(route)
}

pub fn validate_alert_route(route: &AlertRoute) -> Result<ValidationResult, String> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if route.trigger_name.is_empty() {
        errors.push("trigger_name cannot be empty".into());
    }
    if !VALID_SEVERITIES.contains(&route.severity.as_str()) {
        errors.push(format!(
            "Invalid severity: {}. Must be one of: {:?}",
            route.severity, VALID_SEVERITIES
        ));
    }
    if route.host_group.is_empty() {
        errors.push("host_group cannot be empty".into());
    }
    if route.support_group.is_empty() {
        errors.push("support_group cannot be empty".into());
    }
    if !VALID_PRIORITIES.contains(&route.priority.as_str()) {
        warnings.push(format!(
            "Non-standard priority: {}. Expected one of: {:?}",
            route.priority, VALID_PRIORITIES
        ));
    }

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules: Vec::new(),
        remediation: Vec::new(),
    })
}

pub fn resolve_alert_route(
    trigger_name: &str,
    severity: &str,
    host_group: &str,
) -> Result<RouteDecision, String> {
    let store = ROUTE_STORE.lock().unwrap();
    let matching = store.iter().find(|route| {
        route.enabled
            && route.trigger_name == trigger_name
            && route.severity == severity
            && route.host_group == host_group
    });

    let now = chrono::Utc::now().to_rfc3339();
    let alert_id = format!(
        "alert-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    match matching {
        Some(route) => Ok(RouteDecision {
            alert_id: alert_id.clone(),
            route_id: Some(route.id.clone()),
            support_group: route.support_group.clone(),
            escalated: route.severity == "disaster",
            timestamp: now,
            evidence: format!(
                "DRY-RUN: Alert '{}' (severity={}, host_group={}) matched route {} -> support group '{}' (priority={}). No live Zabbix or ServiceNow calls.",
                trigger_name, severity, host_group, route.id, route.support_group, route.priority
            ),
        }),
        None => Ok(RouteDecision {
            alert_id,
            route_id: None,
            support_group: "Unrouted".into(),
            escalated: severity == "disaster",
            timestamp: now,
            evidence: format!(
                "DRY-RUN: No matching route found for alert '{}' (severity={}, host_group={}). Alert is unrouted. Configure a route or review coverage.",
                trigger_name, severity, host_group
            ),
        }),
    }
}

pub fn list_routes() -> Vec<AlertRoute> {
    ROUTE_STORE.lock().unwrap().clone()
}

pub fn get_route(id: &str) -> Option<AlertRoute> {
    ROUTE_STORE
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.id == id)
        .cloned()
}

pub fn update_route(
    id: &str,
    trigger_name: Option<&str>,
    severity: Option<&str>,
    host_group: Option<&str>,
    support_group: Option<&str>,
    priority: Option<&str>,
    enabled: Option<bool>,
) -> Result<AlertRoute, String> {
    let mut store = ROUTE_STORE.lock().unwrap();
    let index = store
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| format!("Route not found: {}", id))?;

    let now = chrono::Utc::now().to_rfc3339();

    if let Some(v) = trigger_name {
        if v.is_empty() {
            return Err("trigger_name cannot be empty".into());
        }
        store[index].trigger_name = v.to_string();
    }
    if let Some(v) = severity {
        if !VALID_SEVERITIES.contains(&v) {
            return Err(format!(
                "Invalid severity: {}. Must be one of: {:?}",
                v, VALID_SEVERITIES
            ));
        }
        store[index].severity = v.to_string();
    }
    if let Some(v) = host_group {
        if v.is_empty() {
            return Err("host_group cannot be empty".into());
        }
        store[index].host_group = v.to_string();
    }
    if let Some(v) = support_group {
        if v.is_empty() {
            return Err("support_group cannot be empty".into());
        }
        store[index].support_group = v.to_string();
    }
    if let Some(v) = priority {
        if !VALID_PRIORITIES.contains(&v) {
            return Err(format!(
                "Invalid priority: {}. Must be one of: {:?}",
                v, VALID_PRIORITIES
            ));
        }
        store[index].priority = v.to_string();
    }
    if let Some(v) = enabled {
        store[index].enabled = v;
    }

    store[index].updated_at = now;
    Ok(store[index].clone())
}

pub fn delete_route(id: &str) -> Result<(), String> {
    let mut store = ROUTE_STORE.lock().unwrap();
    let initial_len = store.len();
    store.retain(|r| r.id != id);
    if store.len() == initial_len {
        Err(format!("Route not found: {}", id))
    } else {
        Ok(())
    }
}

pub fn get_unrouted_alerts() -> Vec<HashMap<String, String>> {
    let store = ROUTE_STORE.lock().unwrap();

    let all_triggers = [
        ("High CPU utilization", "high", "Linux Servers"),
        ("High CPU utilization", "high", "Network Devices"),
        ("Disk space low", "warning", "Windows Servers"),
        ("Disk space low", "high", "Linux Servers"),
        ("Service unavailable", "disaster", "Web Servers"),
        ("Backup job failed", "high", "Windows Servers"),
        ("Memory usage high", "average", "Database Servers"),
        ("Certificate expiring", "warning", "Critical Infrastructure"),
    ];

    let mut unrouted = Vec::new();
    for (trigger, severity, host_group) in &all_triggers {
        let matched = store.iter().any(|route| {
            route.enabled
                && route.trigger_name == *trigger
                && route.severity == *severity
                && route.host_group == *host_group
        });
        if !matched {
            let mut entry = HashMap::new();
            entry.insert("trigger_name".into(), trigger.to_string());
            entry.insert("severity".into(), severity.to_string());
            entry.insert("host_group".into(), host_group.to_string());
            unrouted.push(entry);
        }
    }
    unrouted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_route() -> AlertRoute {
        AlertRoute {
            id: Uuid::new_v4().to_string(),
            trigger_name: "High CPU utilization".into(),
            severity: "high".into(),
            host_group: "Windows Servers".into(),
            support_group: "Wintel Operations".into(),
            priority: "P2".into(),
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_build_alert_route() {
        let route = build_alert_route(
            "High CPU utilization",
            "high",
            "Windows Servers",
            "Wintel Operations",
            "P2",
        )
        .unwrap();
        assert_eq!(route.trigger_name, "High CPU utilization");
        assert_eq!(route.severity, "high");
        assert_eq!(route.priority, "P2");
        assert!(route.enabled);
    }

    #[test]
    fn test_build_alert_route_empty_trigger_fails() {
        let result = build_alert_route("", "high", "Windows Servers", "Wintel Operations", "P2");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_alert_route_invalid_severity_fails() {
        let result = build_alert_route(
            "High CPU",
            "critical",
            "Windows Servers",
            "Wintel Operations",
            "P2",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_alert_route_invalid_priority_fails() {
        let result = build_alert_route(
            "High CPU",
            "high",
            "Windows Servers",
            "Wintel Operations",
            "P5",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_alert_route_passes() {
        let route = test_route();
        let result = validate_alert_route(&route).unwrap();
        assert!(result.passed);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_alert_route_empty_trigger_fails() {
        let mut route = test_route();
        route.trigger_name = "".into();
        let result = validate_alert_route(&route).unwrap();
        assert!(!result.passed);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_alert_route_invalid_severity() {
        let mut route = test_route();
        route.severity = "unknown".into();
        let result = validate_alert_route(&route).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_validate_alert_route_empty_host_group_fails() {
        let mut route = test_route();
        route.host_group = "".into();
        let result = validate_alert_route(&route).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn test_resolve_alert_route_matches() {
        let route = build_alert_route(
            "Test trigger",
            "warning",
            "Test Servers",
            "Test Group",
            "P3",
        )
        .unwrap();

        let decision = resolve_alert_route("Test trigger", "warning", "Test Servers").unwrap();
        assert_eq!(decision.route_id, Some(route.id));
        assert_eq!(decision.support_group, "Test Group");
        assert!(!decision.escalated);
        assert!(decision.evidence.contains("DRY-RUN"));
    }

    #[test]
    fn test_resolve_alert_route_no_match() {
        let decision = resolve_alert_route("Nonexistent", "info", "Nowhere").unwrap();
        assert_eq!(decision.route_id, None);
        assert_eq!(decision.support_group, "Unrouted");
    }

    #[test]
    fn test_resolve_alert_route_disaster_escalates() {
        let decision =
            resolve_alert_route("Service unavailable", "disaster", "Critical Infrastructure")
                .unwrap();
        assert!(decision.route_id.is_some());
        assert!(decision.escalated);
    }

    #[test]
    fn test_list_routes_includes_seed() {
        let routes = list_routes();
        assert!(routes.len() >= 4);
    }

    #[test]
    fn test_get_route_found() {
        let routes = list_routes();
        let first_id = routes[0].id.clone();
        let found = get_route(&first_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, first_id);
    }

    #[test]
    fn test_get_route_not_found() {
        let found = get_route("nonexistent-id");
        assert!(found.is_none());
    }

    #[test]
    fn test_update_route() {
        let route = build_alert_route(
            "Original trigger",
            "warning",
            "Original Servers",
            "Original Group",
            "P3",
        )
        .unwrap();

        let updated = update_route(
            &route.id,
            Some("Updated trigger"),
            Some("average"),
            None,
            None,
            None,
            Some(false),
        )
        .unwrap();

        assert_eq!(updated.trigger_name, "Updated trigger");
        assert_eq!(updated.severity, "average");
        assert!(!updated.enabled);
    }

    #[test]
    fn test_update_route_not_found() {
        let result = update_route("nonexistent", None, None, None, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_route() {
        let route = build_alert_route(
            "To delete",
            "warning",
            "Delete Servers",
            "Delete Group",
            "P4",
        )
        .unwrap();

        assert!(delete_route(&route.id).is_ok());
        assert!(get_route(&route.id).is_none());
    }

    #[test]
    fn test_delete_route_not_found() {
        assert!(delete_route("nonexistent").is_err());
    }

    #[test]
    fn test_get_unrouted_alerts() {
        let unrouted = get_unrouted_alerts();
        assert!(!unrouted.is_empty());
    }

    #[test]
    fn test_disabled_route_not_matched() {
        let route = build_alert_route(
            "Disabled trigger",
            "warning",
            "Disabled Servers",
            "Disabled Group",
            "P3",
        )
        .unwrap();

        update_route(&route.id, None, None, None, None, None, Some(false)).unwrap();

        let decision =
            resolve_alert_route("Disabled trigger", "warning", "Disabled Servers").unwrap();
        assert_eq!(decision.route_id, None);
    }
}
