use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

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

/// Parse the PascalCase DB form into a SuggestionType.
/// DB CHECK: 'RightSizing'|'Migration'|'Consolidation'|'RiskReduction'|
///           'CostOptimization'|'PerformanceImprovement'
pub fn suggestion_type_from_db(raw: &str) -> Result<SuggestionType, String> {
    match raw {
        "RightSizing" => Ok(SuggestionType::RightSizing),
        "Migration" => Ok(SuggestionType::Migration),
        "Consolidation" => Ok(SuggestionType::Consolidation),
        "RiskReduction" => Ok(SuggestionType::RiskReduction),
        "CostOptimization" => Ok(SuggestionType::CostOptimization),
        "PerformanceImprovement" => Ok(SuggestionType::PerformanceImprovement),
        other => Err(format!("unknown suggestion_type DB value: '{other}'")),
    }
}

/// Return the PascalCase DB form for a SuggestionType.
pub fn suggestion_type_to_db(t: &SuggestionType) -> &'static str {
    match t {
        SuggestionType::RightSizing => "RightSizing",
        SuggestionType::Migration => "Migration",
        SuggestionType::Consolidation => "Consolidation",
        SuggestionType::RiskReduction => "RiskReduction",
        SuggestionType::CostOptimization => "CostOptimization",
        SuggestionType::PerformanceImprovement => "PerformanceImprovement",
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

/// Parse the PascalCase DB form into a SuggestionStatus.
/// DB CHECK: 'New'|'Reviewed'|'Accepted'|'Rejected'|'Implemented'
pub fn suggestion_status_from_db(raw: &str) -> Result<SuggestionStatus, String> {
    match raw {
        "New" => Ok(SuggestionStatus::New),
        "Reviewed" => Ok(SuggestionStatus::Reviewed),
        "Accepted" => Ok(SuggestionStatus::Accepted),
        "Rejected" => Ok(SuggestionStatus::Rejected),
        "Implemented" => Ok(SuggestionStatus::Implemented),
        other => Err(format!("unknown suggestion_status DB value: '{other}'")),
    }
}

/// Return the PascalCase DB form for a SuggestionStatus.
pub fn suggestion_status_to_db(s: &SuggestionStatus) -> &'static str {
    match s {
        SuggestionStatus::New => "New",
        SuggestionStatus::Reviewed => "Reviewed",
        SuggestionStatus::Accepted => "Accepted",
        SuggestionStatus::Rejected => "Rejected",
        SuggestionStatus::Implemented => "Implemented",
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

// ─── Pure read functions (operate on slices, never mutate global state) ────────

/// List suggestions filtered by site. Returns empty vec when no data.
pub fn generate_suggestions(site: &str, all: &[AIOpsSuggestion]) -> Value {
    let suggestions: Vec<Value> = all
        .iter()
        .filter(|s| s.site == site)
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

    json!({
        "source": "db",
        "site": site,
        "total_suggestions": suggestions.len(),
        "suggestions": suggestions
    })
}

/// Filter suggestions by display type string (e.g. "right-sizing").
pub fn get_suggestions_by_type(suggestion_type: &str, all: &[AIOpsSuggestion]) -> Value {
    let suggestions: Vec<Value> = all
        .iter()
        .filter(|s| s.suggestion_type.to_string() == suggestion_type)
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

    json!({
        "source": "db",
        "suggestion_type": suggestion_type,
        "count": suggestions.len(),
        "suggestions": suggestions
    })
}

/// Summarize accepted savings for a site.
pub fn get_savings_summary(site: &str, all: &[AIOpsSuggestion]) -> Value {
    let accepted: Vec<&AIOpsSuggestion> = all
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

    json!({
        "source": "db",
        "site": site,
        "total_potential_savings": (total_savings * 100.0).round() / 100.0,
        "accepted_count": accepted.len(),
        "breakdown": breakdown
    })
}

/// Count suggestions by status and type for a site.
pub fn get_suggestion_stats(site: &str, all: &[AIOpsSuggestion]) -> Value {
    let site_suggestions: Vec<&AIOpsSuggestion> = all.iter().filter(|s| s.site == site).collect();

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
        site_suggestions.iter().fold(HashMap::new(), |mut acc, s| {
            *acc.entry(s.suggestion_type.to_string()).or_default() += 1;
            acc
        });

    json!({
        "source": "db",
        "site": site,
        "total": site_suggestions.len(),
        "accepted": accepted,
        "rejected": rejected,
        "pending": pending,
        "implemented": implemented,
        "by_type": by_type
    })
}

// ─── Pure lifecycle guard functions ───────────────────────────────────────────
//
// Each guard validates that a loaded suggestion permits the requested
// transition. They return the expected DB status string for the CAS WHERE
// clause, or an error message for 409.

/// Guard: suggestion must be `New` to transition to `Reviewed`.
/// Returns Ok(expected_db_status) on success.
pub fn guard_review(suggestion: &AIOpsSuggestion) -> Result<&'static str, String> {
    if suggestion.status != SuggestionStatus::New {
        return Err(format!(
            "Suggestion '{}' is already {}",
            suggestion.id, suggestion.status
        ));
    }
    Ok(suggestion_status_to_db(&SuggestionStatus::New))
}

/// Guard: suggestion must be `Reviewed` to transition to `Accepted`.
pub fn guard_accept(suggestion: &AIOpsSuggestion) -> Result<&'static str, String> {
    if suggestion.status != SuggestionStatus::Reviewed {
        return Err(format!(
            "Suggestion '{}' must be reviewed before accepting (current status: {})",
            suggestion.id, suggestion.status
        ));
    }
    Ok(suggestion_status_to_db(&SuggestionStatus::Reviewed))
}

/// Guard: suggestion must be `New` or `Reviewed` to transition to `Rejected`.
pub fn guard_reject(suggestion: &AIOpsSuggestion) -> Result<&'static str, String> {
    if suggestion.status != SuggestionStatus::New && suggestion.status != SuggestionStatus::Reviewed
    {
        return Err(format!(
            "Suggestion '{}' cannot be rejected (current status: {})",
            suggestion.id, suggestion.status
        ));
    }
    Ok(suggestion_status_to_db(&suggestion.status))
}

/// Guard: suggestion must be `Accepted` to transition to `Implemented`.
pub fn guard_implement(suggestion: &AIOpsSuggestion) -> Result<&'static str, String> {
    if suggestion.status != SuggestionStatus::Accepted {
        return Err(format!(
            "Suggestion '{}' must be accepted before implementation (current status: {})",
            suggestion.id, suggestion.status
        ));
    }
    Ok(suggestion_status_to_db(&SuggestionStatus::Accepted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_suggestion(id: &str, site: &str, status: SuggestionStatus) -> AIOpsSuggestion {
        AIOpsSuggestion {
            id: id.to_string(),
            suggestion_type: SuggestionType::PerformanceImprovement,
            title: format!("Test suggestion {id}"),
            description: "Test suggestion for unit tests".into(),
            affected_components: vec!["test-component".into()],
            estimated_savings: Some(100.0),
            confidence_score: 0.85,
            status,
            reviewer: None,
            rejection_reason: None,
            implementation_plan: None,
            site: site.to_string(),
            created_at: "2026-06-01T00:00:00Z".into(),
            updated_at: "2026-06-01T00:00:00Z".into(),
        }
    }

    fn make_suggestions_set() -> Vec<AIOpsSuggestion> {
        vec![
            AIOpsSuggestion {
                id: "aiops-0001".into(),
                suggestion_type: SuggestionType::RightSizing,
                title: "Downsize defra-web-01".into(),
                description: "desc".into(),
                affected_components: vec!["defra-web-01".into(), "defra-web-cluster".into()],
                estimated_savings: Some(192.00),
                confidence_score: 0.89,
                status: SuggestionStatus::New,
                reviewer: None,
                rejection_reason: None,
                implementation_plan: None,
                site: "DEFRA".into(),
                created_at: "2026-06-08T08:00:00Z".into(),
                updated_at: "2026-06-08T08:00:00Z".into(),
            },
            AIOpsSuggestion {
                id: "aiops-0002".into(),
                suggestion_type: SuggestionType::CostOptimization,
                title: "Shutdown idle dev VMs".into(),
                description: "desc".into(),
                affected_components: vec!["defra-dev-01".into()],
                estimated_savings: Some(348.40),
                confidence_score: 0.95,
                status: SuggestionStatus::Accepted,
                reviewer: Some("alice".into()),
                rejection_reason: None,
                implementation_plan: Some("plan".into()),
                site: "DEFRA".into(),
                created_at: "2026-06-09T12:00:00Z".into(),
                updated_at: "2026-06-09T12:00:00Z".into(),
            },
            AIOpsSuggestion {
                id: "aiops-0003".into(),
                suggestion_type: SuggestionType::Migration,
                title: "Migrate defra-legacy-01".into(),
                description: "desc".into(),
                affected_components: vec!["defra-legacy-01".into()],
                estimated_savings: None,
                confidence_score: 0.82,
                status: SuggestionStatus::New,
                reviewer: None,
                rejection_reason: None,
                implementation_plan: None,
                site: "DEFRA".into(),
                created_at: "2026-06-10T09:00:00Z".into(),
                updated_at: "2026-06-10T09:00:00Z".into(),
            },
            AIOpsSuggestion {
                id: "aiops-0004".into(),
                suggestion_type: SuggestionType::Consolidation,
                title: "Consolidate gblon VMs".into(),
                description: "desc".into(),
                affected_components: vec!["gblon-web-01".into()],
                estimated_savings: Some(1280.00),
                confidence_score: 0.78,
                status: SuggestionStatus::New,
                reviewer: None,
                rejection_reason: None,
                implementation_plan: None,
                site: "GBLON".into(),
                created_at: "2026-06-11T14:00:00Z".into(),
                updated_at: "2026-06-11T14:00:00Z".into(),
            },
            AIOpsSuggestion {
                id: "aiops-0005".into(),
                suggestion_type: SuggestionType::RiskReduction,
                title: "Update backup policy".into(),
                description: "desc".into(),
                affected_components: vec!["gblon-dr-01".into()],
                estimated_savings: None,
                confidence_score: 0.97,
                status: SuggestionStatus::New,
                reviewer: None,
                rejection_reason: None,
                implementation_plan: None,
                site: "GBLON".into(),
                created_at: "2026-06-12T16:00:00Z".into(),
                updated_at: "2026-06-12T16:00:00Z".into(),
            },
        ]
    }

    // ─── enum DB roundtrip ────────────────────────────────────────────────────

    #[test]
    fn suggestion_type_db_roundtrip() {
        let types = [
            (SuggestionType::RightSizing, "RightSizing"),
            (SuggestionType::Migration, "Migration"),
            (SuggestionType::Consolidation, "Consolidation"),
            (SuggestionType::RiskReduction, "RiskReduction"),
            (SuggestionType::CostOptimization, "CostOptimization"),
            (
                SuggestionType::PerformanceImprovement,
                "PerformanceImprovement",
            ),
        ];
        for (variant, db_str) in &types {
            assert_eq!(suggestion_type_to_db(variant), *db_str);
            assert_eq!(
                suggestion_type_from_db(db_str).unwrap(),
                *variant,
                "from_db failed for {db_str}"
            );
        }
        assert!(suggestion_type_from_db("right_sizing").is_err());
        assert!(suggestion_type_from_db("right-sizing").is_err());
    }

    #[test]
    fn suggestion_status_db_roundtrip() {
        let statuses = [
            (SuggestionStatus::New, "New"),
            (SuggestionStatus::Reviewed, "Reviewed"),
            (SuggestionStatus::Accepted, "Accepted"),
            (SuggestionStatus::Rejected, "Rejected"),
            (SuggestionStatus::Implemented, "Implemented"),
        ];
        for (variant, db_str) in &statuses {
            assert_eq!(suggestion_status_to_db(variant), *db_str);
            assert_eq!(
                suggestion_status_from_db(db_str).unwrap(),
                *variant,
                "from_db failed for {db_str}"
            );
        }
        assert!(suggestion_status_from_db("new").is_err());
    }

    // ─── Display (API surface) ────────────────────────────────────────────────

    #[test]
    fn suggestion_type_display() {
        assert_eq!(SuggestionType::RightSizing.to_string(), "right-sizing");
        assert_eq!(
            SuggestionType::CostOptimization.to_string(),
            "cost-optimization"
        );
        assert_eq!(SuggestionType::Migration.to_string(), "migration");
        assert_eq!(SuggestionType::Consolidation.to_string(), "consolidation");
        assert_eq!(SuggestionType::RiskReduction.to_string(), "risk-reduction");
        assert_eq!(
            SuggestionType::PerformanceImprovement.to_string(),
            "performance-improvement"
        );
    }

    #[test]
    fn suggestion_status_display() {
        assert_eq!(SuggestionStatus::New.to_string(), "new");
        assert_eq!(SuggestionStatus::Reviewed.to_string(), "reviewed");
        assert_eq!(SuggestionStatus::Accepted.to_string(), "accepted");
        assert_eq!(SuggestionStatus::Rejected.to_string(), "rejected");
        assert_eq!(SuggestionStatus::Implemented.to_string(), "implemented");
    }

    // ─── generate_suggestions (list by site) ─────────────────────────────────

    #[test]
    fn generate_suggestions_filters_by_site() {
        let all = make_suggestions_set();
        let result = generate_suggestions("DEFRA", &all);
        assert_eq!(result["site"], "DEFRA");
        assert_eq!(result["source"], "db");
        let suggestions = result["suggestions"].as_array().unwrap();
        assert_eq!(suggestions.len(), 3, "DEFRA has 3 suggestions in the set");
    }

    #[test]
    fn generate_suggestions_gblon() {
        let all = make_suggestions_set();
        let result = generate_suggestions("GBLON", &all);
        assert_eq!(result["site"], "GBLON");
        let suggestions = result["suggestions"].as_array().unwrap();
        assert_eq!(suggestions.len(), 2);
    }

    #[test]
    fn generate_suggestions_unknown_site_returns_empty() {
        let all = make_suggestions_set();
        let result = generate_suggestions("UNKNOWN", &all);
        assert_eq!(result["total_suggestions"], 0);
        assert!(result["suggestions"].as_array().unwrap().is_empty());
    }

    // ─── get_suggestions_by_type ──────────────────────────────────────────────

    #[test]
    fn get_by_type_rightsizing() {
        let all = make_suggestions_set();
        let result = get_suggestions_by_type("right-sizing", &all);
        assert_eq!(result["suggestion_type"], "right-sizing");
        assert_eq!(result["count"], 1);
    }

    #[test]
    fn get_by_type_cost_optimization() {
        let all = make_suggestions_set();
        let result = get_suggestions_by_type("cost-optimization", &all);
        assert_eq!(result["suggestion_type"], "cost-optimization");
        assert_eq!(result["count"], 1);
    }

    #[test]
    fn get_by_type_unknown_returns_empty() {
        let all = make_suggestions_set();
        let result = get_suggestions_by_type("does-not-exist", &all);
        assert_eq!(result["count"], 0);
    }

    // ─── get_savings_summary ──────────────────────────────────────────────────

    #[test]
    fn savings_summary_defra_accepted_count_and_total() {
        let all = make_suggestions_set();
        let result = get_savings_summary("DEFRA", &all);
        assert_eq!(result["site"], "DEFRA");
        // Only aiops-0002 is Accepted
        assert_eq!(result["accepted_count"], 1);
        let total = result["total_potential_savings"].as_f64().unwrap();
        // 348.40 rounded to 2 decimals
        assert!((total - 348.40).abs() < 0.01);
        assert!(result.get("breakdown").is_some());
    }

    #[test]
    fn savings_summary_no_accepted_returns_zero() {
        let all = make_suggestions_set();
        let result = get_savings_summary("GBLON", &all);
        assert_eq!(result["accepted_count"], 0);
        assert_eq!(result["total_potential_savings"], 0.0);
    }

    // ─── get_suggestion_stats ─────────────────────────────────────────────────

    #[test]
    fn stats_totals_add_up() {
        let all = make_suggestions_set();
        let result = get_suggestion_stats("DEFRA", &all);
        assert_eq!(result["site"], "DEFRA");
        let total = result["total"].as_u64().unwrap();
        let accepted = result["accepted"].as_u64().unwrap();
        let rejected = result["rejected"].as_u64().unwrap();
        let pending = result["pending"].as_u64().unwrap();
        let implemented = result["implemented"].as_u64().unwrap();
        assert_eq!(accepted + rejected + pending + implemented, total);
        assert_eq!(total, 3);
        assert_eq!(accepted, 1);
    }

    #[test]
    fn stats_by_type_present() {
        let all = make_suggestions_set();
        let result = get_suggestion_stats("DEFRA", &all);
        assert!(result.get("by_type").is_some());
    }

    // ─── lifecycle guards ─────────────────────────────────────────────────────

    #[test]
    fn guard_review_new_ok() {
        let s = make_suggestion("t1", "DEFRA", SuggestionStatus::New);
        assert_eq!(guard_review(&s).unwrap(), "New");
    }

    #[test]
    fn guard_review_already_reviewed_err() {
        let s = make_suggestion("t2", "DEFRA", SuggestionStatus::Reviewed);
        assert!(guard_review(&s).is_err());
    }

    #[test]
    fn guard_accept_reviewed_ok() {
        let s = make_suggestion("t3", "DEFRA", SuggestionStatus::Reviewed);
        assert_eq!(guard_accept(&s).unwrap(), "Reviewed");
    }

    #[test]
    fn guard_accept_new_err() {
        let s = make_suggestion("t4", "DEFRA", SuggestionStatus::New);
        assert!(guard_accept(&s).is_err());
    }

    #[test]
    fn guard_reject_new_ok() {
        let s = make_suggestion("t5", "DEFRA", SuggestionStatus::New);
        assert_eq!(guard_reject(&s).unwrap(), "New");
    }

    #[test]
    fn guard_reject_reviewed_ok() {
        let s = make_suggestion("t6", "DEFRA", SuggestionStatus::Reviewed);
        assert_eq!(guard_reject(&s).unwrap(), "Reviewed");
    }

    #[test]
    fn guard_reject_accepted_err() {
        let s = make_suggestion("t7", "DEFRA", SuggestionStatus::Accepted);
        assert!(guard_reject(&s).is_err());
    }

    #[test]
    fn guard_implement_accepted_ok() {
        let s = make_suggestion("t8", "DEFRA", SuggestionStatus::Accepted);
        assert_eq!(guard_implement(&s).unwrap(), "Accepted");
    }

    #[test]
    fn guard_implement_new_err() {
        let s = make_suggestion("t9", "DEFRA", SuggestionStatus::New);
        assert!(guard_implement(&s).is_err());
    }
}
