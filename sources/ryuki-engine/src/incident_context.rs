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
            incident_id: "inc-defra-001".into(),
            title: "DEFRA database latency spike".into(),
            severity: "sev2".into(),
            affected_ci: vec![AffectedCI {
                ci_name: "defra-db-cluster".into(),
                ci_type: "database".into(),
                site: "DEFRA".into(),
                status: "degraded".into(),
            }],
            upstream_deps: mock_upstream_deps("DEFRA"),
            downstream_deps: mock_downstream_deps("DEFRA"),
            recent_changes: mock_recent_changes("DEFRA"),
            on_call: mock_on_call("DEFRA"),
            related_tickets: vec!["INC-DEFRA-7421".into(), "CHG-DEFRA-219".into()],
            assembled_at: "2026-06-11T10:00:00Z".into(),
            status: "active".into(),
            resolution: None,
        },
        IncidentContext {
            incident_id: "inc-gblon-001".into(),
            title: "GBLON storage fabric errors".into(),
            severity: "sev1".into(),
            affected_ci: vec![AffectedCI {
                ci_name: "gblon-vsan-cluster".into(),
                ci_type: "storage".into(),
                site: "GBLON".into(),
                status: "critical".into(),
            }],
            upstream_deps: mock_upstream_deps("GBLON"),
            downstream_deps: mock_downstream_deps("GBLON"),
            recent_changes: mock_recent_changes("GBLON"),
            on_call: mock_on_call("GBLON"),
            related_tickets: vec!["INC-GBLON-8844".into(), "CHG-GBLON-118".into()],
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
        "GBLON" => OnCallInfo {
            primary: "casey.storage".into(),
            secondary: "riley.datacenter".into(),
            escalation: "gblon-incident-commander".into(),
            group: "storage-operations".into(),
        },
        _ => OnCallInfo {
            primary: "morgan.platform".into(),
            secondary: "jamie.sre".into(),
            escalation: "defra-incident-commander".into(),
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

/// Pure constructor — no I/O, no static store. Validates inputs and builds an
/// `IncidentContext` with a uuid-based id. Suitable for DB-backed handlers.
pub fn build_incident_context(
    incident_title: &str,
    severity: &str,
    affected_ci_names: Vec<String>,
    site: &str,
) -> Result<IncidentContext, String> {
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

    Ok(IncidentContext {
        incident_id,
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
    })
}

/// Pure resolver — clones `ctx`, sets status="resolved" and resolution. No I/O.
pub fn resolve_incident_pure(
    ctx: &IncidentContext,
    resolution: &str,
) -> Result<IncidentContext, String> {
    // `resolved` is terminal: only an ACTIVE incident can be resolved. Check this BEFORE
    // input validation so a resolved incident reports the terminal-state reason rather
    // than an input error. Fail closed on any non-active status so a second resolve
    // cannot silently overwrite the first resolution (the xmin CAS does NOT prevent this
    // — xmin advances on every UPDATE).
    if ctx.status != "active" {
        return Err(format!(
            "only an active incident can be resolved (status is '{}')",
            ctx.status
        ));
    }
    if resolution.trim().is_empty() {
        return Err("resolution cannot be empty".into());
    }
    let mut updated = ctx.clone();
    updated.status = "resolved".into();
    updated.resolution = Some(resolution.to_string());
    Ok(updated)
}

/// Pure add-CI — clones `ctx`, appends AffectedCI, status stays "active". No I/O.
pub fn add_affected_ci_pure(
    ctx: &IncidentContext,
    ci_name: &str,
    ci_type: &str,
) -> Result<IncidentContext, String> {
    if ci_name.trim().is_empty() {
        return Err("ci_name cannot be empty".into());
    }
    if ci_type.trim().is_empty() {
        return Err("ci_type cannot be empty".into());
    }
    // Only an ACTIVE incident is mutable — a resolved (terminal) incident's record must
    // not be contaminated post-closure (it is compliance/review evidence).
    if ctx.status != "active" {
        return Err(format!(
            "cannot add a CI to a non-active incident (status is '{}')",
            ctx.status
        ));
    }
    let site = ctx
        .affected_ci
        .first()
        .map(|ci| ci.site.clone())
        .unwrap_or_else(|| "UNKNOWN".into());
    let mut updated = ctx.clone();
    updated.affected_ci.push(AffectedCI {
        ci_name: ci_name.to_string(),
        ci_type: ci_type.to_string(),
        site,
        status: "impacted".into(),
    });
    Ok(updated)
}

/// Pure escalate — clones `ctx`, appends reason to on_call.escalation. Status stays "active". No I/O.
pub fn escalate_pure(ctx: &IncidentContext, reason: &str) -> Result<IncidentContext, String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    // Only an ACTIVE incident is mutable — do not escalate a resolved (terminal) one.
    if ctx.status != "active" {
        return Err(format!(
            "cannot escalate a non-active incident (status is '{}')",
            ctx.status
        ));
    }
    let mut updated = ctx.clone();
    updated.on_call.escalation = format!("{} | escalated: {}", ctx.on_call.escalation, reason);
    Ok(updated)
}

pub fn assemble_context(
    incident_title: &str,
    severity: &str,
    affected_ci_names: Vec<String>,
    site: &str,
) -> Result<Value, String> {
    let context = build_incident_context(incident_title, severity, affected_ci_names, site)?;
    let incident_id = context.incident_id.clone();

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
    // Hold the store lock across the whole read-modify-write so the transition is
    // atomic (a clone-then-relock would let a concurrent mutation be lost).
    let mut store = incident_context_store().lock().unwrap();
    let entry = store
        .iter_mut()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;
    let updated = resolve_incident_pure(entry, resolution)?;
    let status = updated.status.clone();
    let resolution_val = updated.resolution.clone();
    *entry = updated;
    Ok(json!({
        "source": "dry-run",
        "action": "resolve_incident",
        "incident_id": incident_id,
        "status": status,
        "resolution": resolution_val,
    }))
}

pub fn add_affected_ci(incident_id: &str, ci_name: &str, ci_type: &str) -> Result<Value, String> {
    // Hold the store lock across the whole read-modify-write so two concurrent
    // add-ci calls cannot lose an append (the DB path is guarded by the xmin CAS;
    // this keeps the no-DB static fallback equally atomic, as the original was).
    let mut store = incident_context_store().lock().unwrap();
    let entry = store
        .iter_mut()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;
    let updated = add_affected_ci_pure(entry, ci_name, ci_type)?;
    let new_ci = updated.affected_ci.last().cloned();
    let affected_count = updated.affected_ci.len();
    *entry = updated;
    Ok(json!({
        "source": "dry-run",
        "action": "add_affected_ci",
        "incident_id": incident_id,
        "affected_ci": new_ci,
        "affected_count": affected_count,
    }))
}

pub fn escalate(incident_id: &str, reason: &str) -> Result<Value, String> {
    // Hold the store lock across the whole read-modify-write so two concurrent
    // escalations cannot drop a reason (atomic, as the original was).
    let mut store = incident_context_store().lock().unwrap();
    let entry = store
        .iter_mut()
        .find(|incident| incident.incident_id == incident_id)
        .ok_or_else(|| format!("Incident context '{}' not found", incident_id))?;
    let updated = escalate_pure(entry, reason)?;
    let on_call = updated.on_call.clone();
    *entry = updated;
    Ok(json!({
        "source": "dry-run",
        "action": "escalate",
        "incident_id": incident_id,
        "reason": reason,
        "on_call": on_call,
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
            "DEFRA app latency",
            "sev2",
            vec!["defra-app-servers".into()],
            "DEFRA",
        )
        .unwrap();

        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["context"]["title"], "DEFRA app latency");
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
        let incident_id = new_test_incident("DEFRA");
        let result = get_context(&incident_id).unwrap();

        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["context"]["incident_id"], incident_id);
        assert!(result["context"]["on_call"].is_object());
        assert!(result["context"]["related_tickets"].is_array());
    }

    #[test]
    fn test_get_affected_services_returns_ci_list_with_deps() {
        let incident_id = new_test_incident("GBLON");
        let result = get_affected_services(&incident_id).unwrap();

        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["affected_ci"].as_array().unwrap().len(), 1);
        assert!(!result["upstream_deps"].as_array().unwrap().is_empty());
        assert!(!result["downstream_deps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_resolve_incident_marks_resolved() {
        let incident_id = new_test_incident("DEFRA");
        let result =
            resolve_incident(&incident_id, "service restored after mock rollback").unwrap();

        assert_eq!(result["status"], "resolved");
        assert_eq!(result["resolution"], "service restored after mock rollback");

        let context = get_context(&incident_id).unwrap();
        assert_eq!(context["context"]["status"], "resolved");
    }

    /// `resolved` is a TERMINAL state: a resolved incident must not be re-resolved,
    /// have a CI appended, or be escalated (it is compliance/review evidence). An
    /// ACTIVE incident permits all three. (Pure fns — no store.)
    #[test]
    fn test_resolved_incident_is_terminal_and_immutable() {
        let active =
            build_incident_context("term-test", "sev2", vec!["ci-1".into()], "DEFRA").unwrap();
        assert_eq!(active.status, "active");
        // Active: all three transitions are permitted.
        assert!(resolve_incident_pure(&active, "fixed").is_ok());
        assert!(add_affected_ci_pure(&active, "ci-2", "server").is_ok());
        assert!(escalate_pure(&active, "paged on-call").is_ok());

        let resolved = resolve_incident_pure(&active, "service restored").unwrap();
        assert_eq!(resolved.status, "resolved");

        // Resolved (terminal): every mutating transition is rejected.
        assert!(
            resolve_incident_pure(&resolved, "again").is_err(),
            "a resolved incident must not be re-resolved (no silent overwrite)"
        );
        assert!(
            add_affected_ci_pure(&resolved, "ci-3", "server").is_err(),
            "a resolved incident must not accept a new CI"
        );
        assert!(
            escalate_pure(&resolved, "late escalation").is_err(),
            "a resolved incident must not be escalated"
        );

        // Fail-closed is an ALLOWLIST: any non-"active" status (not just "resolved")
        // is rejected, so a future/unknown status can never be silently mutated.
        let mut weird = active.clone();
        weird.status = "paused".into();
        assert!(resolve_incident_pure(&weird, "x").is_err());
        assert!(add_affected_ci_pure(&weird, "ci-x", "server").is_err());
        assert!(escalate_pure(&weird, "x").is_err());
    }

    #[test]
    fn test_escalate_updates_on_call_info() {
        let incident_id = new_test_incident("GBLON");
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
        let active_id = new_test_incident("DEFRA");
        let resolved_id = new_test_incident("GBLON");
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
