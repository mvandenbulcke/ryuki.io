use crate::patch_engine::get_patch_waves;
use chrono::{DateTime, Datelike, Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceWindow {
    pub id: String,
    pub site: String,
    pub start_time: String,
    pub end_time: String,
    pub reason: String,
    pub affected_cis: Vec<String>,
    pub status: MaintenanceWindowStatus,
    pub created_by: String,
    pub created_at: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MaintenanceWindowStatus {
    Planned,
    Active,
    Completed,
    Cancelled,
}

impl std::fmt::Display for MaintenanceWindowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaintenanceWindowStatus::Planned => write!(f, "Planned"),
            MaintenanceWindowStatus::Active => write!(f, "Active"),
            MaintenanceWindowStatus::Completed => write!(f, "Completed"),
            MaintenanceWindowStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

static WINDOW_STORE: OnceLock<Mutex<Vec<MaintenanceWindow>>> = OnceLock::new();

fn window_store() -> &'static Mutex<Vec<MaintenanceWindow>> {
    WINDOW_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

fn parse_iso_time(time: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn overlaps(a_start: &str, a_end: &str, b_start: &str, b_end: &str) -> bool {
    let (Some(as_), Some(ae), Some(bs), Some(be)) = (
        parse_iso_time(a_start),
        parse_iso_time(a_end),
        parse_iso_time(b_start),
        parse_iso_time(b_end),
    ) else {
        return false;
    };
    as_ < be && bs < ae
}

/// Pure input validation + window construction. Does NOT check for conflicts
/// and does NOT mutate the in-memory store. Safe to call in DB mode without
/// touching the OnceLock store — the handler runs the DB conflict pre-check
/// instead.
pub fn validate_window_inputs(
    site: &str,
    start_time: &str,
    end_time: &str,
    reason: &str,
    affected_cis: Vec<String>,
) -> Result<MaintenanceWindow, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    if parse_iso_time(start_time).is_none() {
        return Err(format!("Invalid start_time: {}", start_time));
    }
    if parse_iso_time(end_time).is_none() {
        return Err(format!("Invalid end_time: {}", end_time));
    }
    if parse_iso_time(end_time) <= parse_iso_time(start_time) {
        return Err("end_time must be after start_time".into());
    }
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }

    let id = format!(
        "mw-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    Ok(MaintenanceWindow {
        id,
        site: site.to_string(),
        start_time: start_time.to_string(),
        end_time: end_time.to_string(),
        reason: reason.to_string(),
        affected_cis,
        status: MaintenanceWindowStatus::Planned,
        created_by: "system".to_string(),
        created_at: Utc::now().to_rfc3339(),
        metadata: HashMap::from([
            ("dry_run".into(), "true".into()),
            ("source".into(), "static-seed".into()),
        ]),
    })
}

pub fn schedule_window(
    site: &str,
    start_time: &str,
    end_time: &str,
    reason: &str,
    affected_cis: Vec<String>,
) -> Result<MaintenanceWindow, String> {
    let window = validate_window_inputs(site, start_time, end_time, reason, affected_cis.clone())?;

    let conflicts = check_conflicts_internal(site, start_time, end_time, None);
    if !conflicts.is_empty() {
        return Err(format!(
            "Conflict detected with {} existing window(s): {}",
            conflicts.len(),
            conflicts
                .iter()
                .map(|w| format!("{} ({})", w.id, w.reason))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    window_store().lock().unwrap().push(window.clone());
    Ok(window)
}

fn check_conflicts_internal(
    site: &str,
    start_time: &str,
    end_time: &str,
    exclude_id: Option<&str>,
) -> Vec<MaintenanceWindow> {
    window_store()
        .lock()
        .unwrap()
        .iter()
        .filter(|w| {
            w.site == site
                && (exclude_id.is_none_or(|id| w.id != id))
                && w.status != MaintenanceWindowStatus::Cancelled
                && w.status != MaintenanceWindowStatus::Completed
                && overlaps(&w.start_time, &w.end_time, start_time, end_time)
        })
        .cloned()
        .collect()
}

pub fn check_conflicts(site: &str, start_time: &str, end_time: &str) -> Vec<MaintenanceWindow> {
    check_conflicts_internal(site, start_time, end_time, None)
}

pub fn get_upcoming(site: &str) -> Vec<MaintenanceWindow> {
    let now = Utc::now();
    let cutoff = now + Days::new(30);
    window_store()
        .lock()
        .unwrap()
        .iter()
        .filter(|w| {
            w.site == site
                && w.status != MaintenanceWindowStatus::Cancelled
                && match parse_iso_time(&w.start_time) {
                    Some(start) => start >= now && start <= cutoff,
                    None => false,
                }
        })
        .cloned()
        .collect()
}

pub fn get_active(site: &str) -> Vec<MaintenanceWindow> {
    let now = Utc::now();
    window_store()
        .lock()
        .unwrap()
        .iter()
        .filter(|w| {
            w.site == site
                && match (parse_iso_time(&w.start_time), parse_iso_time(&w.end_time)) {
                    (Some(start), Some(end)) => now >= start && now <= end,
                    _ => false,
                }
        })
        .cloned()
        .collect()
}

pub fn get_calendar(site: &str, month: &str) -> Result<Vec<MaintenanceWindow>, String> {
    let month_start = DateTime::parse_from_rfc3339(&format!("{}-01T00:00:00Z", month))
        .map_err(|e| format!("Invalid month format (expected YYYY-MM): {}", e))?;

    let next_month = if month_start.month() == 12 {
        DateTime::parse_from_rfc3339(&format!("{}-{:02}-01T00:00:00Z", month_start.year() + 1, 1))
            .map_err(|e| format!("Date calculation error: {}", e))?
    } else {
        DateTime::parse_from_rfc3339(&format!(
            "{}-{:02}-01T00:00:00Z",
            month_start.year(),
            month_start.month() + 1
        ))
        .map_err(|e| format!("Date calculation error: {}", e))?
    };

    let windows = window_store()
        .lock()
        .unwrap()
        .iter()
        .filter(|w| {
            w.site == site
                && parse_iso_time(&w.start_time).is_some_and(|s| s >= month_start && s < next_month)
        })
        .cloned()
        .collect();
    Ok(windows)
}

pub fn cancel_window(window_id: &str) -> Result<MaintenanceWindow, String> {
    let mut store = window_store().lock().unwrap();
    let idx = store
        .iter()
        .position(|w| w.id == window_id)
        .ok_or_else(|| format!("Maintenance window not found: {}", window_id))?;

    let window = &store[idx];
    if window.status == MaintenanceWindowStatus::Completed {
        return Err("Cannot cancel a completed maintenance window".into());
    }
    if window.status == MaintenanceWindowStatus::Cancelled {
        return Err("Maintenance window is already cancelled".into());
    }

    let mut cancelled = window.clone();
    cancelled.status = MaintenanceWindowStatus::Cancelled;
    cancelled
        .metadata
        .insert("cancelled_at".into(), Utc::now().to_rfc3339());
    store[idx] = cancelled.clone();
    Ok(cancelled)
}

pub fn get_dependency_warnings(window_id: &str) -> Result<Vec<DependencyWarning>, String> {
    let store = window_store().lock().unwrap();
    let window = store
        .iter()
        .find(|w| w.id == window_id)
        .ok_or_else(|| format!("Maintenance window not found: {}", window_id))?
        .clone();

    let mut warnings: Vec<DependencyWarning> = Vec::new();

    let other_windows: Vec<MaintenanceWindow> = store
        .iter()
        .filter(|w| {
            w.id != window_id
                && w.site == window.site
                && w.status != MaintenanceWindowStatus::Cancelled
                && overlaps(
                    &w.start_time,
                    &w.end_time,
                    &window.start_time,
                    &window.end_time,
                )
        })
        .cloned()
        .collect();

    for ow in &other_windows {
        warnings.push(DependencyWarning {
            severity: "warning".into(),
            source_type: "maintenance-window".into(),
            source_id: ow.id.clone(),
            message: format!(
                "This window overlaps with maintenance window '{}' for {}",
                ow.reason,
                ow.affected_cis.join(", ")
            ),
            metadata: HashMap::from([
                ("overlap_start".into(), ow.start_time.clone()),
                ("overlap_end".into(), ow.end_time.clone()),
            ]),
        });
    }

    let patch_waves = get_patch_waves();
    for pw in &patch_waves {
        if pw.site_scope.contains(&window.site)
            && overlaps(
                &pw.schedule.start,
                &pw.schedule.end,
                &window.start_time,
                &window.end_time,
            )
        {
            warnings.push(DependencyWarning {
                severity: "critical".into(),
                source_type: "patch-wave".into(),
                source_id: pw.id.clone(),
                message: format!(
                    "This window overlaps with patch wave '{}' for {} ({:?} status)",
                    pw.name, window.site, pw.status
                ),
                metadata: HashMap::from([
                    ("patch_wave_name".into(), pw.name.clone()),
                    ("patch_wave_id".into(), pw.id.clone()),
                    ("patch_count".into(), pw.servers.len().to_string()),
                ]),
            });
        }
    }

    Ok(warnings)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencyWarning {
    pub severity: String,
    pub source_type: String,
    pub source_id: String,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

pub fn seed_example_windows() {
    let mut store = window_store().lock().unwrap();

    let now = Utc::now();
    let examples = vec![
        MaintenanceWindow {
            id: "mw-example-001".into(),
            site: "DEFRA".into(),
            start_time: (now + Days::new(3)).to_rfc3339(),
            end_time: (now + Days::new(3) + chrono::Duration::hours(8)).to_rfc3339(),
            reason: "Scheduled SQL Server patching".into(),
            affected_cis: vec!["sql-defra-01".into(), "sql-defra-02".into()],
            status: MaintenanceWindowStatus::Planned,
            created_by: "patch-team".into(),
            created_at: now.to_rfc3339(),
            metadata: HashMap::from([
                ("dry_run".into(), "true".into()),
                ("source".into(), "static-seed".into()),
            ]),
        },
        MaintenanceWindow {
            id: "mw-example-002".into(),
            site: "GBLON".into(),
            start_time: (now + Days::new(5)).to_rfc3339(),
            end_time: (now + Days::new(5) + chrono::Duration::hours(4)).to_rfc3339(),
            reason: "Hypervisor firmware upgrade".into(),
            affected_cis: vec![
                "esx-gblon-01".into(),
                "esx-gblon-02".into(),
                "esx-gblon-03".into(),
            ],
            status: MaintenanceWindowStatus::Planned,
            created_by: "infra-team".into(),
            created_at: now.to_rfc3339(),
            metadata: HashMap::from([
                ("dry_run".into(), "true".into()),
                ("source".into(), "static-seed".into()),
            ]),
        },
        MaintenanceWindow {
            id: "mw-example-003".into(),
            site: "FRPAR".into(),
            start_time: (now + Days::new(7)).to_rfc3339(),
            end_time: (now + Days::new(7) + chrono::Duration::hours(6)).to_rfc3339(),
            reason: "Network switch firmware upgrade".into(),
            affected_cis: vec!["sw-frpar-core-01".into(), "sw-frpar-core-02".into()],
            status: MaintenanceWindowStatus::Planned,
            created_by: "network-team".into(),
            created_at: now.to_rfc3339(),
            metadata: HashMap::from([
                ("dry_run".into(), "true".into()),
                ("source".into(), "static-seed".into()),
            ]),
        },
        MaintenanceWindow {
            id: "mw-example-004".into(),
            site: "DEFRA".into(),
            start_time: (now + Days::new(14)).to_rfc3339(),
            end_time: (now + Days::new(14) + chrono::Duration::hours(2)).to_rfc3339(),
            reason: "Load balancer certificate rotation".into(),
            affected_cis: vec!["lb-defra-01".into()],
            status: MaintenanceWindowStatus::Planned,
            created_by: "sec-team".into(),
            created_at: now.to_rfc3339(),
            metadata: HashMap::from([
                ("dry_run".into(), "true".into()),
                ("source".into(), "static-seed".into()),
            ]),
        },
    ];

    for window in examples {
        if !store.iter().any(|existing| existing.id == window.id) {
            store.push(window);
        }
    }
}

pub fn get_calendar_contract() -> Value {
    seed_example_windows();
    json!({
        "source": "static-seed",
        "calendarMode": "aggregate-draft",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveSchedulingAllowed": false,
        "liveNotificationAllowed": false,
        "rawRecipientDataAllowed": false,
        "supportedWorkflows": [
            "patch-calendar",
            "reboot-calendar",
            "sql-maintenance-calendar",
            "application-tier-maintenance",
            "outage-communications-draft",
            "conflict-review"
        ],
        "calendarDimensions": [
            "application",
            "environment",
            "site",
            "dependencyGroup",
            "maintenanceWindow",
            "criticality",
            "owner",
            "supportGroup",
            "changeContext"
        ],
        "requiredInputs": [
            "maintenanceWindow",
            "affectedServices",
            "dependencyGraphSummary",
            "owner",
            "supportGroup",
            "site",
            "environment",
            "changeContext",
            "evidenceManifest"
        ],
        "requiredGuards": [
            "cmdb-relationship-graph-ready",
            "patch-policy-imported",
            "maintenance-window-known",
            "dependency-order-known",
            "blackout-window-clear",
            "owner-known",
            "communications-draft-only",
            "approval-route-assigned",
            "evidence-redacted"
        ],
        "planSections": [
            "calendarSummary",
            "affectedServiceSummary",
            "dependencyOrder",
            "conflictReview",
            "communicationsDraft",
            "approvalRoute",
            "handoverNotes",
            "evidenceReferences"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-scheduling-disabled",
            "live-notification-disabled",
            "missing-maintenance-window",
            "dependency-order-unknown",
            "blackout-window-conflict",
            "owner-unknown",
            "conflict-review-missing",
            "approval-missing",
            "evidence-not-redacted"
        ],
        "requiredEvidence": [
            "Calendar summary",
            "Affected service summary",
            "Dependency order",
            "Conflict review",
            "Communication draft",
            "Approval decisions",
            "Handover notes",
            "Evidence references"
        ],
        "rules": [
            {
                "id": "no-live-calendar-action",
                "decision": "block",
                "requirement": "Dependency-aware maintenance calendar produces aggregate plans only and never schedules changes or sends notifications.",
                "evidence": "Calendar summary"
            },
            {
                "id": "dependency-order-required",
                "decision": "block",
                "requirement": "Dependency order must be known before maintenance windows can be presented for approval.",
                "evidence": "Dependency order"
            },
            {
                "id": "conflict-review-required",
                "decision": "block",
                "requirement": "Calendar conflicts, blackout windows, and tier overlaps must be reviewed before approval.",
                "evidence": "Conflict review"
            },
            {
                "id": "communications-draft-only",
                "decision": "block",
                "requirement": "Outage communications remain draft-only until live notification approval exists.",
                "evidence": "Communication draft"
            },
            {
                "id": "approval-and-evidence-required",
                "decision": "block",
                "requirement": "Approval route and redacted evidence are required before future execution can be considered.",
                "evidence": "Approval decisions"
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn future_time(days: i64, hours: i64) -> String {
        (Utc::now() + Days::new(days as u64) + Duration::hours(hours)).to_rfc3339()
    }

    fn make_cis() -> Vec<String> {
        vec!["srv-01".into(), "srv-02".into()]
    }

    /// Verifies that `validate_window_inputs` is pure: it returns Ok with the
    /// constructed window (all 5 error cases → Err) and NEVER pushes to the
    /// in-memory store.
    #[test]
    fn test_validate_window_inputs_no_side_effects() {
        let start = future_time(50, 0);
        let end = future_time(50, 4);

        // Valid inputs — should return Ok without mutating the store.
        let store_before = window_store().lock().unwrap().len();
        let result = validate_window_inputs("DEFRA", &start, &end, "pure validate", make_cis());
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        let store_after = window_store().lock().unwrap().len();
        assert_eq!(
            store_before, store_after,
            "validate_window_inputs must NOT push to the store"
        );

        // Error: unknown site.
        let err = validate_window_inputs("MARS", &start, &end, "bad site", make_cis());
        assert!(err.unwrap_err().contains("Unknown site"));

        // Error: invalid start_time.
        let err = validate_window_inputs("DEFRA", "not-a-time", &end, "bad start", make_cis());
        assert!(err.unwrap_err().contains("Invalid start_time"));

        // Error: invalid end_time.
        let err = validate_window_inputs("DEFRA", &start, "not-a-time", "bad end", make_cis());
        assert!(err.unwrap_err().contains("Invalid end_time"));

        // Error: end <= start.
        let err = validate_window_inputs("DEFRA", &end, &start, "reversed", make_cis());
        assert!(err.unwrap_err().contains("end_time must be after"));

        // Error: empty reason.
        let err = validate_window_inputs("DEFRA", &start, &end, "   ", make_cis());
        assert!(err.unwrap_err().contains("reason cannot be empty"));
    }

    #[test]
    fn test_schedule_window_creates_window() {
        let start = future_time(10, 0);
        let end = future_time(10, 4);
        let window =
            schedule_window("DEFRA", &start, &end, "Test maintenance", make_cis()).unwrap();

        assert!(window.id.starts_with("mw-"));
        assert_eq!(window.site, "DEFRA");
        assert_eq!(window.status, MaintenanceWindowStatus::Planned);
        assert_eq!(window.affected_cis.len(), 2);
        assert_eq!(window.reason, "Test maintenance");
    }

    #[test]
    fn test_schedule_window_conflict_detected() {
        let start = future_time(20, 0);
        let end = future_time(20, 4);

        schedule_window("GBLON", &start, &end, "First window", make_cis()).unwrap();
        let result = schedule_window("GBLON", &start, &end, "Conflicting window", make_cis());

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Conflict detected"));
    }

    #[test]
    fn test_schedule_window_invalid_site() {
        let result = schedule_window(
            "MARS",
            &future_time(10, 0),
            &future_time(10, 4),
            "Invalid site",
            make_cis(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown site"));
    }

    #[test]
    fn test_schedule_window_invalid_time_range() {
        let result = schedule_window(
            "DEFRA",
            &future_time(10, 4),
            &future_time(10, 0),
            "Bad range",
            make_cis(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("end_time must be after"));
    }

    #[test]
    fn test_check_conflicts_detects_overlap() {
        let start_a = future_time(15, 0);
        let end_a = future_time(15, 6);
        let start_b = future_time(15, 3);
        let end_b = future_time(15, 9);

        schedule_window("NLAMS", &start_a, &end_a, "Window A", make_cis()).unwrap();
        let conflicts = check_conflicts("NLAMS", &start_b, &end_b);

        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].reason, "Window A");
    }

    #[test]
    fn test_check_conflicts_no_overlap() {
        let start_a = future_time(12, 0);
        let end_a = future_time(12, 4);
        let start_b = future_time(12, 5);
        let end_b = future_time(12, 9);

        schedule_window("FRPAR", &start_a, &end_a, "Window A", make_cis()).unwrap();
        let conflicts = check_conflicts("FRPAR", &start_b, &end_b);

        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_cancel_window() {
        let start = future_time(30, 0);
        let end = future_time(30, 4);
        let window = schedule_window("FRPAR", &start, &end, "To be cancelled", make_cis()).unwrap();

        let cancelled = cancel_window(&window.id).unwrap();
        assert_eq!(cancelled.status, MaintenanceWindowStatus::Cancelled);
        assert!(cancelled.metadata.contains_key("cancelled_at"));
    }

    #[test]
    fn test_cancel_window_not_found() {
        assert!(cancel_window("mw-nonexistent").is_err());
    }

    #[test]
    fn test_get_upcoming_filters_correctly() {
        let near_start = future_time(2, 0);
        let near_end = future_time(2, 2);
        let far_start = future_time(40, 0);
        let far_end = future_time(40, 2);

        schedule_window("DEBER", &near_start, &near_end, "Near window", make_cis()).unwrap();
        schedule_window("DEBER", &far_start, &far_end, "Far window", make_cis()).unwrap();

        let upcoming = get_upcoming("DEBER");
        assert_eq!(upcoming.len(), 1);
        assert_eq!(upcoming[0].reason, "Near window");
    }

    #[test]
    fn test_get_active_returns_currently_active() {
        let now = Utc::now();
        let start = (now - Duration::hours(1)).to_rfc3339();
        let end = (now + Duration::hours(1)).to_rfc3339();

        schedule_window("DEFRA", &start, &end, "Active window", make_cis()).unwrap();
        let active = get_active("DEFRA");

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].reason, "Active window");
    }

    #[test]
    fn test_get_calendar_returns_monthly_windows() {
        let now = Utc::now();
        let month = now.format("%Y-%m").to_string();
        let start = format!("{}-01T10:00:00Z", month);
        let end = format!("{}-02T14:00:00Z", month);

        schedule_window("GBLON", &start, &end, "Monthly window", make_cis()).unwrap();
        let calendar = get_calendar("GBLON", &month).unwrap();

        assert!(
            calendar
                .iter()
                .any(|window| window.reason == "Monthly window")
        );
    }

    #[test]
    fn test_get_dependency_warnings_patch_wave_overlap() {
        crate::patch_engine::plan_patch_wave("NLAMS", "windows", "high").unwrap();

        let window = schedule_window(
            "NLAMS",
            "2026-06-15T22:00:00Z",
            "2026-06-16T06:00:00Z",
            "Overlapping window",
            make_cis(),
        )
        .unwrap();

        let warnings = get_dependency_warnings(&window.id).unwrap();
        let has_patch_warning = warnings.iter().any(|w| w.source_type == "patch-wave");
        assert!(has_patch_warning, "Expected patch wave dependency warning");
    }

    #[test]
    fn test_seed_example_windows_creates_data() {
        seed_example_windows();
        let store = window_store().lock().unwrap();
        for id in [
            "mw-example-001",
            "mw-example-002",
            "mw-example-003",
            "mw-example-004",
        ] {
            assert!(store.iter().any(|window| window.id == id));
        }
    }

    #[test]
    fn test_get_calendar_contract_returns_valid_structure() {
        let contract = get_calendar_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["dryRunRequired"], true);
        assert!(contract["supportedWorkflows"].as_array().unwrap().len() > 0);
    }
}
