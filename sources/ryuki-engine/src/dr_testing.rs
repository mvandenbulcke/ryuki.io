use chrono::{Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DrPlanStatus {
    Draft,
    Approved,
    Active,
    Expired,
}

impl std::fmt::Display for DrPlanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrPlanStatus::Draft => write!(f, "Draft"),
            DrPlanStatus::Approved => write!(f, "Approved"),
            DrPlanStatus::Active => write!(f, "Active"),
            DrPlanStatus::Expired => write!(f, "Expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DrTestResult {
    Passed,
    Failed,
    Partial,
}

impl std::fmt::Display for DrTestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrTestResult::Passed => write!(f, "Passed"),
            DrTestResult::Failed => write!(f, "Failed"),
            DrTestResult::Partial => write!(f, "Partial"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DrScenarioType {
    FullFailover,
    PartialFailover,
    Tabletop,
    CommunicationOnly,
}

impl std::fmt::Display for DrScenarioType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrScenarioType::FullFailover => write!(f, "FullFailover"),
            DrScenarioType::PartialFailover => write!(f, "PartialFailover"),
            DrScenarioType::Tabletop => write!(f, "Tabletop"),
            DrScenarioType::CommunicationOnly => write!(f, "CommunicationOnly"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrPlan {
    pub id: String,
    pub name: String,
    pub site: String,
    pub target_site: String,
    pub systems: Vec<String>,
    pub rpo_minutes: u32,
    pub rto_minutes: u32,
    pub last_tested: Option<String>,
    pub next_test_due: String,
    pub status: DrPlanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrTestRun {
    pub id: String,
    pub plan_id: String,
    pub site: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub result: DrTestResult,
    pub systems_tested: Vec<String>,
    pub systems_failed: Vec<String>,
    pub tester: String,
    pub evidence_pack_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrScenario {
    pub id: String,
    pub name: String,
    pub scenario_type: DrScenarioType,
    pub site: String,
    pub target_site: String,
    pub systems: Vec<String>,
}

type DrStore = (Vec<DrPlan>, Vec<DrTestRun>, Vec<DrScenario>);

static DR_STORE: OnceLock<Mutex<DrStore>> = OnceLock::new();

fn dr_store() -> &'static Mutex<DrStore> {
    DR_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn parse_iso_time(time: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn parse_scenario_type(scenario_type: &str) -> Result<DrScenarioType, String> {
    match scenario_type {
        "FullFailover" | "full-failover" => Ok(DrScenarioType::FullFailover),
        "PartialFailover" | "partial-failover" => Ok(DrScenarioType::PartialFailover),
        "Tabletop" | "tabletop" => Ok(DrScenarioType::Tabletop),
        "CommunicationOnly" | "communication-only" => Ok(DrScenarioType::CommunicationOnly),
        other => Err(format!(
            "Invalid scenario_type: {}. Must be FullFailover, PartialFailover, Tabletop, or CommunicationOnly",
            other
        )),
    }
}

fn parse_test_result(result: &str) -> Result<DrTestResult, String> {
    match result {
        "Passed" | "passed" => Ok(DrTestResult::Passed),
        "Failed" | "failed" => Ok(DrTestResult::Failed),
        "Partial" | "partial" => Ok(DrTestResult::Partial),
        other => Err(format!(
            "Invalid result: {}. Must be Passed, Failed, or Partial",
            other
        )),
    }
}

fn seed_data() -> DrStore {
    let now = Utc::now();
    let plans = vec![
        DrPlan {
            id: "drp-defra-001".into(),
            name: "DEFRA production full-site failover".into(),
            site: "DEFRA".into(),
            target_site: "GBLON".into(),
            systems: vec!["defra-app-01".into(), "defra-db-01".into()],
            rpo_minutes: 15,
            rto_minutes: 120,
            last_tested: Some((now - chrono::Duration::days(40)).to_rfc3339()),
            next_test_due: (now - chrono::Duration::days(10)).to_rfc3339(),
            status: DrPlanStatus::Active,
        },
        DrPlan {
            id: "drp-gblon-001".into(),
            name: "GBLON storage partial failover".into(),
            site: "GBLON".into(),
            target_site: "FRPAR".into(),
            systems: vec!["gblon-vsan-01".into(), "gblon-vsan-02".into()],
            rpo_minutes: 30,
            rto_minutes: 180,
            last_tested: Some((now - chrono::Duration::days(12)).to_rfc3339()),
            next_test_due: (now + Days::new(18)).to_rfc3339(),
            status: DrPlanStatus::Approved,
        },
        DrPlan {
            id: "drp-frpar-001".into(),
            name: "FRPAR communications tabletop".into(),
            site: "FRPAR".into(),
            target_site: "DEFRA".into(),
            systems: vec!["frpar-core-01".into(), "frpar-fw-01".into()],
            rpo_minutes: 60,
            rto_minutes: 240,
            last_tested: None,
            next_test_due: (now - chrono::Duration::days(2)).to_rfc3339(),
            status: DrPlanStatus::Draft,
        },
    ];

    let test_runs = vec![
        DrTestRun {
            id: "drt-defra-001".into(),
            plan_id: "drp-defra-001".into(),
            site: "DEFRA".into(),
            started_at: (now - chrono::Duration::days(40) - chrono::Duration::hours(3))
                .to_rfc3339(),
            completed_at: Some(
                (now - chrono::Duration::days(40) - chrono::Duration::hours(1)).to_rfc3339(),
            ),
            result: DrTestResult::Passed,
            systems_tested: vec!["defra-app-01".into(), "defra-db-01".into()],
            systems_failed: vec![],
            tester: "dr.coordinator".into(),
            evidence_pack_id: "evp-dr-defra-001".into(),
        },
        DrTestRun {
            id: "drt-defra-002".into(),
            plan_id: "drp-defra-001".into(),
            site: "DEFRA".into(),
            started_at: (now - chrono::Duration::days(95) - chrono::Duration::hours(4))
                .to_rfc3339(),
            completed_at: Some(
                (now - chrono::Duration::days(95) - chrono::Duration::hours(2)).to_rfc3339(),
            ),
            result: DrTestResult::Partial,
            systems_tested: vec!["defra-app-01".into(), "defra-db-01".into()],
            systems_failed: vec!["defra-db-01".into()],
            tester: "platform.ops".into(),
            evidence_pack_id: "evp-dr-defra-002".into(),
        },
        DrTestRun {
            id: "drt-gblon-001".into(),
            plan_id: "drp-gblon-001".into(),
            site: "GBLON".into(),
            started_at: (now - chrono::Duration::days(12) - chrono::Duration::hours(2))
                .to_rfc3339(),
            completed_at: Some(
                (now - chrono::Duration::days(12) - chrono::Duration::hours(1)).to_rfc3339(),
            ),
            result: DrTestResult::Passed,
            systems_tested: vec!["gblon-vsan-01".into(), "gblon-vsan-02".into()],
            systems_failed: vec![],
            tester: "storage.ops".into(),
            evidence_pack_id: "evp-dr-gblon-001".into(),
        },
        DrTestRun {
            id: "drt-frpar-001".into(),
            plan_id: "drp-frpar-001".into(),
            site: "FRPAR".into(),
            started_at: (now - chrono::Duration::days(180) - chrono::Duration::hours(2))
                .to_rfc3339(),
            completed_at: Some(
                (now - chrono::Duration::days(180) - chrono::Duration::hours(1)).to_rfc3339(),
            ),
            result: DrTestResult::Failed,
            systems_tested: vec!["frpar-core-01".into(), "frpar-fw-01".into()],
            systems_failed: vec!["frpar-fw-01".into()],
            tester: "network.ops".into(),
            evidence_pack_id: "evp-dr-frpar-001".into(),
        },
    ];

    let scenarios = vec![
        DrScenario {
            id: "drs-defra-full".into(),
            name: "DEFRA full production failover".into(),
            scenario_type: DrScenarioType::FullFailover,
            site: "DEFRA".into(),
            target_site: "GBLON".into(),
            systems: vec!["defra-app-01".into(), "defra-db-01".into()],
        },
        DrScenario {
            id: "drs-gblon-partial".into(),
            name: "GBLON storage pool partial failover".into(),
            scenario_type: DrScenarioType::PartialFailover,
            site: "GBLON".into(),
            target_site: "FRPAR".into(),
            systems: vec!["gblon-vsan-01".into()],
        },
        DrScenario {
            id: "drs-frpar-tabletop".into(),
            name: "FRPAR network recovery tabletop".into(),
            scenario_type: DrScenarioType::Tabletop,
            site: "FRPAR".into(),
            target_site: "DEFRA".into(),
            systems: vec!["frpar-core-01".into(), "frpar-fw-01".into()],
        },
        DrScenario {
            id: "drs-defra-comms".into(),
            name: "DEFRA crisis communications only".into(),
            scenario_type: DrScenarioType::CommunicationOnly,
            site: "DEFRA".into(),
            target_site: "GBLON".into(),
            systems: vec!["defra-app-01".into()],
        },
    ];

    (plans, test_runs, scenarios)
}

/// Returns a clone of the plan from the in-memory store (DB-consistent via write-through).
/// Used by the DB-backed handler for `start_test` to resolve the plan without I/O.
pub fn get_plan_from_store(plan_id: &str) -> Option<DrPlan> {
    let store = dr_store().lock().ok()?;
    store.0.iter().find(|p| p.id == plan_id).cloned()
}

/// Pure constructor: takes the resolved plan + inputs, returns a DrTestRun ready for DB insert.
pub fn build_test_run(
    plan: &DrPlan,
    scenario_type: &str,
    tester: &str,
) -> Result<DrTestRun, String> {
    parse_scenario_type(scenario_type)?; // validates; we don't need the value
    if tester.trim().is_empty() {
        return Err("tester cannot be empty".into());
    }
    let id = format!(
        "drt-{}-{}",
        plan.site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let evidence_pack_id = format!("evp-{}", id);
    Ok(DrTestRun {
        id,
        plan_id: plan.id.clone(),
        site: plan.site.clone(),
        started_at: now_iso(),
        completed_at: None,
        result: DrTestResult::Partial, // placeholder until complete
        systems_tested: plan.systems.clone(),
        systems_failed: vec![],
        tester: tester.to_string(),
        evidence_pack_id,
    })
}

/// Pure transition: returns completed run. Returns Err if already completed (-> 409).
pub fn complete_test_run_pure(
    run: &DrTestRun,
    result: &str,
    systems_failed: Vec<String>,
) -> Result<DrTestRun, String> {
    if run.completed_at.is_some() {
        return Err(format!("DR test '{}' is already completed", run.id));
    }
    let result = parse_test_result(result)?;
    let mut updated = run.clone();
    updated.completed_at = Some(now_iso());
    updated.result = result;
    updated.systems_failed = systems_failed;
    Ok(updated)
}

/// Pure: returns updated plan with last_tested + next_test_due set.
pub fn mark_plan_tested_pure(plan: &DrPlan, completed_at: &str) -> DrPlan {
    let mut updated = plan.clone();
    updated.last_tested = Some(completed_at.to_string());
    updated.next_test_due = (Utc::now() + Days::new(90)).to_rfc3339();
    updated
}

pub fn list_plans(site: &str) -> Result<Value, String> {
    let store = dr_store().lock().unwrap();
    let plans: Vec<DrPlan> = if site.is_empty() {
        store.0.clone()
    } else {
        store.0.iter().filter(|p| p.site == site).cloned().collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "count": plans.len(),
        "plans": plans,
        "dry_run": true
    }))
}

pub fn get_plan(id: &str) -> Result<Value, String> {
    let store = dr_store().lock().unwrap();
    let plan = store
        .0
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("DR plan '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "plan": plan,
        "rpo_minutes": plan.rpo_minutes,
        "rto_minutes": plan.rto_minutes,
        "dry_run": true
    }))
}

/// Pure constructor: validates inputs + builds a DrPlan ready for persistence.
/// Status is always Draft on creation. Called by the stateful create_plan.
pub fn build_dr_plan(
    name: &str,
    site: &str,
    target_site: &str,
    systems: Vec<String>,
    rpo: u32,
    rto: u32,
) -> Result<DrPlan, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    if target_site.trim().is_empty() {
        return Err("target_site cannot be empty".into());
    }
    if systems.is_empty() {
        return Err("systems cannot be empty".into());
    }
    if rpo == 0 || rto == 0 {
        return Err("rpo and rto must be greater than zero".into());
    }

    let id = format!(
        "drp-{}-{}",
        site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    Ok(DrPlan {
        id,
        name: name.to_string(),
        site: site.to_string(),
        target_site: target_site.to_string(),
        systems,
        rpo_minutes: rpo,
        rto_minutes: rto,
        last_tested: None,
        next_test_due: (Utc::now() + Days::new(90)).to_rfc3339(),
        status: DrPlanStatus::Draft,
    })
}

/// Pure update: returns a cloned DrPlan with rpo/rto updated.
/// Status is UNCHANGED (this is a same-status mutation).
pub fn update_rpo_rto_pure(plan: &DrPlan, rpo: u32, rto: u32) -> Result<DrPlan, String> {
    if rpo == 0 || rto == 0 {
        return Err("rpo and rto must be greater than zero".into());
    }
    let mut updated = plan.clone();
    updated.rpo_minutes = rpo;
    updated.rto_minutes = rto;
    Ok(updated)
}

/// Insert-or-replace a plan in the in-memory store by id. The API layer is the
/// durable source of truth for plans (DB), but the static store is still the
/// cross-domain read surface for test-run creation (`start_test` resolves the
/// plan from here). After a DB write, the API calls this to keep the static
/// store consistent (write-through cache), and at startup it replays the
/// persisted plans the same way. No I/O — only the in-memory store is touched.
pub fn upsert_plan(plan: &DrPlan) {
    let Ok(mut store) = dr_store().lock() else {
        return;
    };
    if let Some(existing) = store.0.iter_mut().find(|p| p.id == plan.id) {
        *existing = plan.clone();
    } else {
        store.0.push(plan.clone());
    }
}

pub fn create_plan(
    name: &str,
    site: &str,
    target_site: &str,
    systems: Vec<String>,
    rpo: u32,
    rto: u32,
) -> Result<Value, String> {
    let plan = build_dr_plan(name, site, target_site, systems, rpo, rto)?;
    let id = plan.id.clone();
    dr_store().lock().unwrap().0.push(plan.clone());
    Ok(json!({
        "source": "dry-run",
        "plan_id": id,
        "plan": plan,
        "dry_run": true
    }))
}

pub fn start_test(plan_id: &str, scenario_type: &str, tester: &str) -> Result<Value, String> {
    let mut store = dr_store().lock().unwrap();
    let plan = store
        .0
        .iter()
        .find(|p| p.id == plan_id)
        .cloned()
        .ok_or_else(|| format!("DR plan '{}' not found", plan_id))?;
    // Hold the lock across build + push to avoid race on store.1
    let test_run = build_test_run(&plan, scenario_type, tester)?;
    let id = test_run.id.clone();
    let evidence_pack_id = test_run.evidence_pack_id.clone();
    let scenario = parse_scenario_type(scenario_type)?; // for response json
    store.1.push(test_run.clone());
    Ok(json!({
        "source": "dry-run",
        "test_id": id,
        "plan_id": plan_id,
        "scenario_type": scenario,
        "test_run": test_run,
        "evidence_pack_id": evidence_pack_id,
        "dry_run": true
    }))
}

pub fn complete_test(
    test_id: &str,
    result: &str,
    systems_failed: Vec<String>,
) -> Result<Value, String> {
    let mut store = dr_store().lock().unwrap();
    let run = store
        .1
        .iter()
        .find(|r| r.id == test_id)
        .cloned()
        .ok_or_else(|| format!("DR test '{}' not found", test_id))?;
    let completed_run = complete_test_run_pure(&run, result, systems_failed)?;
    // Update in-place in the static store
    if let Some(r) = store.1.iter_mut().find(|r| r.id == test_id) {
        *r = completed_run.clone();
    }
    // Update the plan in-place
    let completed_at = completed_run.completed_at.as_deref().unwrap_or("");
    if let Some(plan) = store.0.iter_mut().find(|p| p.id == completed_run.plan_id) {
        *plan = mark_plan_tested_pure(plan, completed_at);
    }
    Ok(json!({
        "source": "dry-run",
        "test_id": test_id,
        "test_run": completed_run,
        "dry_run": true
    }))
}

pub fn get_test_results(plan_id: &str) -> Result<Value, String> {
    let store = dr_store().lock().unwrap();
    if !store.0.iter().any(|p| p.id == plan_id) {
        return Err(format!("DR plan '{}' not found", plan_id));
    }

    let results: Vec<DrTestRun> = store
        .1
        .iter()
        .filter(|r| r.plan_id == plan_id)
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "plan_id": plan_id,
        "count": results.len(),
        "test_results": results,
        "dry_run": true
    }))
}

pub fn list_due_tests() -> Result<Value, String> {
    let now = Utc::now();
    let store = dr_store().lock().unwrap();
    let due: Vec<DrPlan> = store
        .0
        .iter()
        .filter(|p| parse_iso_time(&p.next_test_due).is_some_and(|due| due <= now))
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": due.len(),
        "due_tests": due,
        "dry_run": true
    }))
}

pub fn get_dr_readiness(site: &str) -> Result<Value, String> {
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let now = Utc::now();
    let store = dr_store().lock().unwrap();
    let plans: Vec<&DrPlan> = store.0.iter().filter(|p| p.site == site).collect();
    if plans.is_empty() {
        return Err(format!("Site '{}' has no DR plans", site));
    }

    let overdue = plans
        .iter()
        .filter(|p| parse_iso_time(&p.next_test_due).is_some_and(|due| due <= now))
        .count();
    let last_tested = plans
        .iter()
        .filter_map(|p| p.last_tested.as_deref())
        .filter_map(parse_iso_time)
        .max()
        .map(|dt| dt.to_rfc3339());
    let completed_runs: Vec<&DrTestRun> = store
        .1
        .iter()
        .filter(|r| r.site == site && r.completed_at.is_some())
        .collect();
    let passed = completed_runs
        .iter()
        .filter(|r| r.result == DrTestResult::Passed)
        .count();
    let pass_rate_pct = if completed_runs.is_empty() {
        0
    } else {
        ((passed as f64 / completed_runs.len() as f64) * 100.0).round() as u32
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "plans_count": plans.len(),
        "last_tested": last_tested,
        "overdue": overdue,
        "pass_rate_pct": pass_rate_pct,
        "dry_run": true
    }))
}

pub fn list_scenarios(site: &str) -> Result<Value, String> {
    let store = dr_store().lock().unwrap();
    let scenarios: Vec<DrScenario> = if site.is_empty() {
        store.2.clone()
    } else {
        store.2.iter().filter(|s| s.site == site).cloned().collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "count": scenarios.len(),
        "scenarios": scenarios,
        "dry_run": true
    }))
}

pub fn update_rpo_rto(plan_id: &str, rpo: u32, rto: u32) -> Result<Value, String> {
    let mut store = dr_store().lock().unwrap();
    let entry = store
        .0
        .iter_mut()
        .find(|p| p.id == plan_id)
        .ok_or_else(|| format!("DR plan '{}' not found", plan_id))?;
    let updated = update_rpo_rto_pure(entry, rpo, rto)?;
    *entry = updated;
    Ok(json!({
        "source": "dry-run",
        "plan_id": plan_id,
        "rpo_minutes": entry.rpo_minutes,
        "rto_minutes": entry.rto_minutes,
        "plan": entry.clone(),
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_list_plans() {
        let site = "NLAMS";
        let created = create_plan(
            "NLAMS application DR",
            site,
            "DEFRA",
            vec!["nlams-app-01".into(), "nlams-db-01".into()],
            20,
            90,
        )
        .unwrap();

        assert!(
            created["plan_id"]
                .as_str()
                .unwrap()
                .starts_with("drp-nlams-")
        );
        let listed = list_plans(site).unwrap();
        assert!(
            listed["plans"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| { p["id"] == created["plan_id"] && p["site"] == site })
        );
    }

    #[test]
    fn test_start_and_complete_test_passed() {
        let plan = create_plan(
            "DEBER pass test DR",
            "DEBER",
            "GBLON",
            vec!["deber-app-01".into()],
            15,
            60,
        )
        .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap();
        let started = start_test(plan_id, "Tabletop", "qa.operator").unwrap();
        let test_id = started["test_id"].as_str().unwrap();

        let completed = complete_test(test_id, "Passed", vec![]).unwrap();
        assert_eq!(completed["test_run"]["result"], "passed");
        assert!(completed["test_run"]["completed_at"].is_string());
    }

    /// A plan built via the pure constructor (as the DB-backed create handler does)
    /// is NOT in the static store until upsert_plan replays it — so start_test must
    /// fail before the upsert and succeed after. This is the cross-domain
    /// consistency the write-through cache provides (the API persists to DB and
    /// upserts the static so test-run creation can resolve the plan).
    #[test]
    fn test_upsert_plan_makes_it_startable() {
        let plan = build_dr_plan(
            "FRMRS upsert DR",
            "FRMRS",
            "GBLON",
            vec!["frmrs-app-01".into()],
            20,
            90,
        )
        .unwrap();
        let id = plan.id.clone();

        // Before the upsert, the plan exists only as a value (DB-only) — start_test
        // resolves from the static store, so it must not find it.
        assert!(
            start_test(&id, "Tabletop", "qa.operator").is_err(),
            "a plan not yet in the static store must not be startable"
        );

        upsert_plan(&plan);

        // After the write-through upsert, the same plan id is resolvable.
        assert!(
            start_test(&id, "Tabletop", "qa.operator").is_ok(),
            "an upserted plan must be startable"
        );
    }

    #[test]
    fn test_start_and_complete_test_failed() {
        let plan = create_plan(
            "DEHAM failed test DR",
            "DEHAM",
            "FRPAR",
            vec!["deham-app-01".into(), "deham-db-01".into()],
            30,
            120,
        )
        .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap();
        let started = start_test(plan_id, "FullFailover", "qa.operator").unwrap();
        let test_id = started["test_id"].as_str().unwrap();

        let completed = complete_test(test_id, "Failed", vec!["deham-db-01".into()]).unwrap();
        assert_eq!(completed["test_run"]["result"], "failed");
        assert_eq!(
            completed["test_run"]["systems_failed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_list_due_tests() {
        let due = list_due_tests().unwrap();
        assert!(due["count"].as_u64().unwrap() >= 1);
        assert!(
            due["due_tests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "drp-defra-001")
        );
    }

    #[test]
    fn test_dr_readiness_report() {
        let report = get_dr_readiness("DEFRA").unwrap();
        assert_eq!(report["site"], "DEFRA");
        assert!(report["plans_count"].as_u64().unwrap() >= 1);
        assert!(report["pass_rate_pct"].as_u64().unwrap() <= 100);
    }

    #[test]
    fn test_update_rpo_rto() {
        let plan = create_plan(
            "NOOSL objective update DR",
            "NOOSL",
            "DEFRA",
            vec!["noosl-app-01".into()],
            45,
            180,
        )
        .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap();

        let updated = update_rpo_rto(plan_id, 10, 45).unwrap();
        assert_eq!(updated["rpo_minutes"], 10);
        assert_eq!(updated["rto_minutes"], 45);
    }

    #[test]
    fn test_test_not_found_error() {
        let result = complete_test("drt-nonexistent", "Passed", vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_get_test_results() {
        let results = get_test_results("drp-defra-001").unwrap();
        assert_eq!(results["plan_id"], "drp-defra-001");
        assert!(results["count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_list_scenarios() {
        let scenarios = list_scenarios("DEFRA").unwrap();
        assert!(scenarios["count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_dr_test_result_serde_strings() {
        assert_eq!(
            serde_json::to_value(&DrTestResult::Passed).unwrap(),
            serde_json::Value::String("passed".into())
        );
        assert_eq!(
            serde_json::to_value(&DrTestResult::Failed).unwrap(),
            serde_json::Value::String("failed".into())
        );
        assert_eq!(
            serde_json::to_value(&DrTestResult::Partial).unwrap(),
            serde_json::Value::String("partial".into())
        );
    }

    #[test]
    fn test_dr_plan_status_serde_strings() {
        assert_eq!(
            serde_json::to_value(&DrPlanStatus::Draft).unwrap(),
            serde_json::Value::String("draft".into())
        );
        assert_eq!(
            serde_json::to_value(&DrPlanStatus::Approved).unwrap(),
            serde_json::Value::String("approved".into())
        );
        assert_eq!(
            serde_json::to_value(&DrPlanStatus::Active).unwrap(),
            serde_json::Value::String("active".into())
        );
        assert_eq!(
            serde_json::to_value(&DrPlanStatus::Expired).unwrap(),
            serde_json::Value::String("expired".into())
        );
    }
}
