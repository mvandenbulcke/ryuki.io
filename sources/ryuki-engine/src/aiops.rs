use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionType {
    RightSizing,
    Migration,
    Consolidation,
    RiskReduction,
    CostOptimization,
    PerformanceImprovement,
}

impl std::fmt::Display for SuggestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuggestionType::RightSizing => write!(f, "right-sizing"),
            SuggestionType::Migration => write!(f, "migration"),
            SuggestionType::Consolidation => write!(f, "consolidation"),
            SuggestionType::RiskReduction => write!(f, "risk-reduction"),
            SuggestionType::CostOptimization => write!(f, "cost-optimization"),
            SuggestionType::PerformanceImprovement => write!(f, "performance-improvement"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionStatus {
    New,
    Reviewed,
    Accepted,
    Rejected,
    Implemented,
}

impl std::fmt::Display for SuggestionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuggestionStatus::New => write!(f, "new"),
            SuggestionStatus::Reviewed => write!(f, "reviewed"),
            SuggestionStatus::Accepted => write!(f, "accepted"),
            SuggestionStatus::Rejected => write!(f, "rejected"),
            SuggestionStatus::Implemented => write!(f, "implemented"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIOpsSuggestion {
    pub id: String,
    pub suggestion_type: SuggestionType,
    pub title: String,
    pub description: String,
    pub affected_components: Vec<String>,
    pub estimated_savings: Option<f64>,
    pub confidence_score: f64,
    pub status: SuggestionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_plan: Option<String>,
    pub site: String,
    pub created_at: String,
    pub updated_at: String,
}

type AIOpsStore = Vec<AIOpsSuggestion>;
static AIOPS_STORE: OnceLock<Mutex<AIOpsStore>> = OnceLock::new();

fn aiops_store() -> &'static Mutex<AIOpsStore> {
    AIOPS_STORE.get_or_init(|| Mutex::new(seed_suggestions()))
}

fn seed_suggestions() -> AIOpsStore {
    vec![
        AIOpsSuggestion {
            id: "aiops-0001".into(),
            suggestion_type: SuggestionType::RightSizing,
            title: "Downsize love-web-01 from 8 GB to 4 GB memory".into(),
            description: "love-web-01 averages 31% memory utilization over 90 days. Reducing from 8 GB to 4 GB aligns allocation with observed demand while maintaining a 2x headroom.".into(),
            affected_components: vec!["love-web-01".into(), "love-web-cluster".into()],
            estimated_savings: Some(192.00),
            confidence_score: 0.89,
            status: SuggestionStatus::New,
            reviewer: None,
            rejection_reason: None,
            implementation_plan: None,
            site: "LOVE".into(),
            created_at: "2026-06-01T08:00:00Z".into(),
            updated_at: "2026-06-01T08:00:00Z".into(),
        },
        AIOpsSuggestion {
            id: "aiops-0002".into(),
            suggestion_type: SuggestionType::CostOptimization,
            title: "Shutdown idle dev VMs during non-business hours".into(),
            description: "love-dev-01 and love-dev-02 show < 4% CPU utilization outside 08:00-18:00. Automated power schedule could save ~65% of their monthly cost.".into(),
            affected_components: vec!["love-dev-01".into(), "love-dev-02".into(), "love-general-cluster".into()],
            estimated_savings: Some(348.40),
            confidence_score: 0.95,
            status: SuggestionStatus::New,
            reviewer: None,
            rejection_reason: None,
            implementation_plan: None,
            site: "LOVE".into(),
            created_at: "2026-06-03T12:00:00Z".into(),
            updated_at: "2026-06-03T12:00:00Z".into(),
        },
        AIOpsSuggestion {
            id: "aiops-0003".into(),
            suggestion_type: SuggestionType::Migration,
            title: "Migrate love-legacy-01 from VMware to newer cluster".into(),
            description: "love-legacy-01 runs at 95% CPU / 92% memory on aging hardware with no vMotion compatibility. Migrate to love-general-cluster to reduce contention and improve availability.".into(),
            affected_components: vec!["love-legacy-01".into(), "vCenter".into(), "love-general-cluster".into()],
            estimated_savings: None,
            confidence_score: 0.82,
            status: SuggestionStatus::New,
            reviewer: None,
            rejection_reason: None,
            implementation_plan: None,
            site: "LOVE".into(),
            created_at: "2026-06-05T09:00:00Z".into(),
            updated_at: "2026-06-05T09:00:00Z".into(),
        },
        AIOpsSuggestion {
            id: "aiops-0004".into(),
            suggestion_type: SuggestionType::Consolidation,
            title: "Consolidate bur1-web-01 and bur1-qa-01 onto shared host".into(),
            description: "Both VMs run on separate hosts with combined utilization under 25%. Consolidating frees one hypervisor license and reduces power draw.".into(),
            affected_components: vec!["bur1-web-01".into(), "bur1-qa-01".into(), "bur1-web-cluster".into()],
            estimated_savings: Some(1280.00),
            confidence_score: 0.78,
            status: SuggestionStatus::New,
            reviewer: None,
            rejection_reason: None,
            implementation_plan: None,
            site: "BUR1".into(),
            created_at: "2026-06-07T14:00:00Z".into(),
            updated_at: "2026-06-07T14:00:00Z".into(),
        },
        AIOpsSuggestion {
            id: "aiops-0005".into(),
            suggestion_type: SuggestionType::RiskReduction,
            title: "Update backup policy for bur1-dr-01 — last verified 90+ days ago".into(),
            description: "bur1-dr-01 backup verification is 90+ days stale. A failed restore test would leave DR site unrecoverable. Schedule immediate verification and increase frequency to weekly.".into(),
            affected_components: vec!["bur1-dr-01".into(), "Veeam".into(), "bur1-dr-cluster".into()],
            estimated_savings: None,
            confidence_score: 0.97,
            status: SuggestionStatus::New,
            reviewer: None,
            rejection_reason: None,
            implementation_plan: None,
            site: "BUR1".into(),
            created_at: "2026-06-09T16:00:00Z".into(),
            updated_at: "2026-06-09T16:00:00Z".into(),
        },
    ]
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn generate_suggestions(site: &str) -> Result<Value, String> {
    let store = aiops_store().lock().map_err(|e| e.to_string())?;
    let existing: Vec<&AIOpsSuggestion> = store.iter().filter(|s| s.site == site).collect();
    let count = existing.len();
    let suggestions: Vec<Value> = existing
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "suggestion_type": s.suggestion_type.to_string(),
                "title": s.title,
                "description": s.description,
                "affected_components": s.affected_components,
                "estimated_savings": s.estimated_savings,
                "confidence_score": s.confidence_score,
                "status": s.status.to_string(),
                "site": s.site,
                "created_at": s.created_at
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_suggestions": count,
        "suggestions": suggestions
    }))
}

pub fn review_suggestion(id: &str, reviewer: &str) -> Result<Value, String> {
    let mut store = aiops_store().lock().map_err(|e| e.to_string())?;
    let suggestion = store
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("Suggestion '{}' not found", id))?;

    if suggestion.status != SuggestionStatus::New {
        return Err(format!(
            "Suggestion '{}' is already {}",
            id,
            suggestion.status.to_string()
        ));
    }

    suggestion.status = SuggestionStatus::Reviewed;
    suggestion.reviewer = Some(reviewer.to_string());
    suggestion.updated_at = now_iso();

    Ok(json!({
        "source": "dry-run",
        "id": suggestion.id,
        "status": suggestion.status.to_string(),
        "reviewer": suggestion.reviewer,
        "updated_at": suggestion.updated_at
    }))
}

pub fn accept_suggestion(id: &str) -> Result<Value, String> {
    let mut store = aiops_store().lock().map_err(|e| e.to_string())?;
    let suggestion = store
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("Suggestion '{}' not found", id))?;

    if suggestion.status != SuggestionStatus::Reviewed {
        return Err(format!(
            "Suggestion '{}' must be reviewed before accepting (current status: {})",
            id,
            suggestion.status.to_string()
        ));
    }

    suggestion.status = SuggestionStatus::Accepted;
    suggestion.implementation_plan =
        Some(format!("Implementation plan for {}: dry-run assessment, maintenance window scheduling, execution, verification.", suggestion.title));
    suggestion.updated_at = now_iso();

    Ok(json!({
        "source": "dry-run",
        "id": suggestion.id,
        "status": suggestion.status.to_string(),
        "implementation_plan": suggestion.implementation_plan,
        "updated_at": suggestion.updated_at
    }))
}

pub fn reject_suggestion(id: &str, reason: &str) -> Result<Value, String> {
    let mut store = aiops_store().lock().map_err(|e| e.to_string())?;
    let suggestion = store
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("Suggestion '{}' not found", id))?;

    if suggestion.status != SuggestionStatus::New && suggestion.status != SuggestionStatus::Reviewed {
        return Err(format!(
            "Suggestion '{}' cannot be rejected (current status: {})",
            id,
            suggestion.status.to_string()
        ));
    }

    suggestion.status = SuggestionStatus::Rejected;
    suggestion.rejection_reason = Some(reason.to_string());
    suggestion.updated_at = now_iso();

    Ok(json!({
        "source": "dry-run",
        "id": suggestion.id,
        "status": suggestion.status.to_string(),
        "rejection_reason": suggestion.rejection_reason,
        "updated_at": suggestion.updated_at
    }))
}

pub fn implement_suggestion(id: &str) -> Result<Value, String> {
    let mut store = aiops_store().lock().map_err(|e| e.to_string())?;
    let suggestion = store
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("Suggestion '{}' not found", id))?;

    if suggestion.status != SuggestionStatus::Accepted {
        return Err(format!(
            "Suggestion '{}' must be accepted before implementation (current status: {})",
            id,
            suggestion.status.to_string()
        ));
    }

    suggestion.status = SuggestionStatus::Implemented;
    suggestion.updated_at = now_iso();

    Ok(json!({
        "source": "dry-run",
        "id": suggestion.id,
        "status": suggestion.status.to_string(),
        "updated_at": suggestion.updated_at,
        "note": "Implementation tracked — static dry-run mode; no live provider calls performed."
    }))
}

pub fn get_suggestions_by_type(suggestion_type: &str) -> Result<Value, String> {
    let store = aiops_store().lock().map_err(|e| e.to_string())?;

    let filtered: Vec<&AIOpsSuggestion> = store
        .iter()
        .filter(|s| s.suggestion_type.to_string() == suggestion_type)
        .collect();

    let suggestions: Vec<Value> = filtered
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "suggestion_type": s.suggestion_type.to_string(),
                "title": s.title,
                "description": s.description,
                "affected_components": s.affected_components,
                "estimated_savings": s.estimated_savings,
                "confidence_score": s.confidence_score,
                "status": s.status.to_string(),
                "site": s.site,
                "created_at": s.created_at
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "suggestion_type": suggestion_type,
        "count": suggestions.len(),
        "suggestions": suggestions
    }))
}

pub fn get_savings_summary(site: &str) -> Result<Value, String> {
    let store = aiops_store().lock().map_err(|e| e.to_string())?;

    let accepted: Vec<&AIOpsSuggestion> = store
        .iter()
        .filter(|s| s.site == site && s.status == SuggestionStatus::Accepted)
        .collect();

    let total_savings: f64 = accepted.iter().filter_map(|s| s.estimated_savings).sum();

    let breakdown: Vec<Value> = accepted
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "title": s.title,
                "suggestion_type": s.suggestion_type.to_string(),
                "estimated_savings": s.estimated_savings,
                "confidence_score": s.confidence_score
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_potential_savings": (total_savings * 100.0).round() / 100.0,
        "accepted_count": accepted.len(),
        "breakdown": breakdown
    }))
}

pub fn get_suggestion_stats(site: &str) -> Result<Value, String> {
    let store = aiops_store().lock().map_err(|e| e.to_string())?;

    let site_suggestions: Vec<&AIOpsSuggestion> =
        store.iter().filter(|s| s.site == site).collect();

    let accepted = site_suggestions
        .iter()
        .filter(|s| s.status == SuggestionStatus::Accepted)
        .count();
    let rejected = site_suggestions
        .iter()
        .filter(|s| s.status == SuggestionStatus::Rejected)
        .count();
    let pending = site_suggestions
        .iter()
        .filter(|s| s.status == SuggestionStatus::New || s.status == SuggestionStatus::Reviewed)
        .count();
    let implemented = site_suggestions
        .iter()
        .filter(|s| s.status == SuggestionStatus::Implemented)
        .count();

    let by_type: HashMap<String, usize> =
        site_suggestions
            .iter()
            .fold(HashMap::new(), |mut acc, s| {
                *acc.entry(s.suggestion_type.to_string()).or_default() += 1;
                acc
            });

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total": site_suggestions.len(),
        "accepted": accepted,
        "rejected": rejected,
        "pending": pending,
        "implemented": implemented,
        "by_type": by_type
    }))
}

#[cfg(test)]
fn seed_test_suggestion(id: &str, site: &str) -> AIOpsSuggestion {
    AIOpsSuggestion {
        id: id.to_string(),
        suggestion_type: SuggestionType::PerformanceImprovement,
        title: format!("Test suggestion {}", id),
        description: "Test suggestion for unit tests".into(),
        affected_components: vec!["test-component".into()],
        estimated_savings: Some(100.0),
        confidence_score: 0.85,
        status: SuggestionStatus::New,
        reviewer: None,
        rejection_reason: None,
        implementation_plan: None,
        site: site.to_string(),
        created_at: "2026-06-01T00:00:00Z".into(),
        updated_at: "2026-06-01T00:00:00Z".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_suggestions_for_love() {
        let result = generate_suggestions("LOVE").unwrap();
        assert_eq!(result["site"], "LOVE");
        assert_eq!(result["source"], "dry-run");
        let suggestions = result["suggestions"].as_array().unwrap();
        assert!(suggestions.len() >= 3);
    }

    #[test]
    fn test_generate_suggestions_for_bur1() {
        let result = generate_suggestions("BUR1").unwrap();
        assert_eq!(result["site"], "BUR1");
        let suggestions = result["suggestions"].as_array().unwrap();
        assert!(suggestions.len() >= 2);
    }

    #[test]
    fn test_review_then_accept_suggestion() {
        let tid = "test-lc-001";
        aiops_store().lock().unwrap().push(seed_test_suggestion(tid, "LOVE"));

        let review = review_suggestion(tid, "alice").unwrap();
        assert_eq!(review["status"], "reviewed");
        assert_eq!(review["reviewer"], "alice");

        let accept = accept_suggestion(tid).unwrap();
        assert_eq!(accept["status"], "accepted");
        assert!(accept["implementation_plan"].as_str().unwrap().contains("Implementation plan"));
    }

    #[test]
    fn test_reject_suggestion() {
        let tid = "test-rej-001";
        aiops_store().lock().unwrap().push(seed_test_suggestion(tid, "LOVE"));

        let reject = reject_suggestion(tid, "Insufficient data for cost projection").unwrap();
        assert_eq!(reject["status"], "rejected");
        assert!(reject["rejection_reason"].as_str().unwrap().contains("Insufficient data"));
    }

    #[test]
    fn test_implement_suggestion_requires_accepted() {
        let tid = "test-imp-001";
        aiops_store().lock().unwrap().push(seed_test_suggestion(tid, "LOVE"));

        // Should fail — not reviewed/accepted yet
        let result = implement_suggestion(tid);
        assert!(result.is_err());

        // Now review + accept + implement
        review_suggestion(tid, "bob").unwrap();
        accept_suggestion(tid).unwrap();
        let implement = implement_suggestion(tid).unwrap();
        assert_eq!(implement["status"], "implemented");
    }

    #[test]
    fn test_get_suggestions_by_type_rightsizing() {
        let result = get_suggestions_by_type("right-sizing").unwrap();
        assert_eq!(result["suggestion_type"], "right-sizing");
        assert!(result["count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_get_suggestions_by_type_cost_optimization() {
        let result = get_suggestions_by_type("cost-optimization").unwrap();
        assert_eq!(result["suggestion_type"], "cost-optimization");
        assert!(result["count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_get_savings_summary_format() {
        let result = get_savings_summary("LOVE").unwrap();
        assert_eq!(result["site"], "LOVE");
        assert!(result["accepted_count"].as_u64().is_some());
        assert!(result["total_potential_savings"].as_f64().unwrap() >= 0.0);
        assert!(result.get("breakdown").is_some());
    }

    #[test]
    fn test_get_suggestion_stats() {
        let result = get_suggestion_stats("LOVE").unwrap();
        assert_eq!(result["site"], "LOVE");
        assert!(result["total"].as_u64().unwrap() >= 3);
        assert!(result.get("by_type").is_some());
        let accepted = result["accepted"].as_u64().unwrap();
        let rejected = result["rejected"].as_u64().unwrap();
        let pending = result["pending"].as_u64().unwrap();
        let implemented = result["implemented"].as_u64().unwrap();
        assert_eq!(
            accepted + rejected + pending + implemented,
            result["total"].as_u64().unwrap()
        );
    }

    #[test]
    fn test_reject_already_accepted_fails() {
        let tid = "test-rej-accepted-001";
        aiops_store().lock().unwrap().push(seed_test_suggestion(tid, "LOVE"));

        review_suggestion(tid, "alice").unwrap();
        accept_suggestion(tid).unwrap();

        let result = reject_suggestion(tid, "Changed my mind");
        assert!(result.is_err());
    }

    #[test]
    fn test_suggestion_type_display() {
        assert_eq!(SuggestionType::RightSizing.to_string(), "right-sizing");
        assert_eq!(SuggestionType::CostOptimization.to_string(), "cost-optimization");
        assert_eq!(SuggestionType::Migration.to_string(), "migration");
        assert_eq!(SuggestionType::Consolidation.to_string(), "consolidation");
        assert_eq!(SuggestionType::RiskReduction.to_string(), "risk-reduction");
        assert_eq!(SuggestionType::PerformanceImprovement.to_string(), "performance-improvement");
    }

    #[test]
    fn test_suggestion_status_display() {
        assert_eq!(SuggestionStatus::New.to_string(), "new");
        assert_eq!(SuggestionStatus::Reviewed.to_string(), "reviewed");
        assert_eq!(SuggestionStatus::Accepted.to_string(), "accepted");
        assert_eq!(SuggestionStatus::Rejected.to_string(), "rejected");
        assert_eq!(SuggestionStatus::Implemented.to_string(), "implemented");
    }

    #[test]
    fn test_full_lifecycle() {
        let tid = "test-lifecycle-001";
        aiops_store().lock().unwrap().push(seed_test_suggestion(tid, "BUR1"));

        review_suggestion(tid, "carol").unwrap();
        accept_suggestion(tid).unwrap();
        let implement = implement_suggestion(tid).unwrap();
        assert_eq!(implement["status"], "implemented");

        let stats = get_suggestion_stats("BUR1").unwrap();
        assert!(stats["implemented"].as_u64().unwrap() >= 1);
    }
}
