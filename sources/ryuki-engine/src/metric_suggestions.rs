//! Pure AIOps suggestion generation from metric findings (#36).
//!
//! Turns the anomaly + waste findings of [`crate::metric_anomaly`] into
//! actionable [`GeneratedSuggestion`]s ready to persist as `aiops_suggestions`
//! rows. Pure and deterministic — no IO, no clock — so the mapping (which
//! finding becomes which suggestion type, at what confidence) is fully
//! unit-testable. The API layer persists the result and dedups it.

use crate::metric_anomaly::{Anomaly, WasteFinding, WasteKind};
use crate::metric_forecast::SeriesSummary;

/// A suggestion derived from metric findings, shaped to build an
/// `aiops_suggestions` row. `suggestion_type` is one of the values that table's
/// CHECK constraint allows; `confidence_score` is in `[0, 1]`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct GeneratedSuggestion {
    pub suggestion_type: String,
    pub title: String,
    pub description: String,
    pub confidence_score: f64,
    /// Left `None` here — there is no cost model yet (a chargeback model, #46,
    /// would populate it). Better an honest `None` than a fabricated number.
    pub estimated_savings: Option<f64>,
}

/// Generate suggestions from a metric series' findings. Waste becomes a
/// rightsizing/decommission suggestion; anomalies become an investigation
/// suggestion. Returns an empty vec when nothing is actionable. `metric_key` is
/// a validated operator identifier (the caller bounds its length/charset).
pub fn suggest_from_findings(
    metric_key: &str,
    _summary: Option<&SeriesSummary>,
    anomalies: &[Anomaly],
    waste: Option<&WasteFinding>,
) -> Vec<GeneratedSuggestion> {
    let mut out = Vec::new();

    if let Some(w) = waste {
        let (suggestion_type, base_conf, verb) = match w.kind {
            WasteKind::Idle => ("CostOptimization", 0.9, "decommission idle"),
            WasteKind::Underutilized => ("RightSizing", 0.6, "rightsize underused"),
        };
        // Confidence rises with how much of the recent window was wasteful, but
        // stays under 1.0 (the table CHECK bounds it to [0, 1]).
        let confidence = (base_conf + (w.fraction_below - 0.5).max(0.0) * 0.2).clamp(0.0, 0.99);
        out.push(GeneratedSuggestion {
            suggestion_type: suggestion_type.to_string(),
            title: format!("Review and {verb} '{metric_key}'"),
            description: format!(
                "{:.0}% of the most recent {} samples for '{metric_key}' were at or below \
                 the waste threshold ({:.2}). Consider acting to {verb} this resource.",
                w.fraction_below * 100.0,
                w.sample_count,
                w.threshold
            ),
            confidence_score: confidence,
            estimated_savings: None,
        });
    }

    if !anomalies.is_empty() {
        // Confidence rises lightly with the strongest deviation, capped.
        let max_z = anomalies
            .iter()
            .map(|a| a.z_score.abs())
            .fold(0.0_f64, f64::max);
        let confidence = (0.5 + max_z / 10.0).clamp(0.0, 0.95);
        out.push(GeneratedSuggestion {
            suggestion_type: "RiskReduction".to_string(),
            title: format!(
                "Investigate {} anomaly(ies) in '{metric_key}'",
                anomalies.len()
            ),
            description: format!(
                "{} sample(s) in '{metric_key}' deviate sharply from the series baseline \
                 (max |z| {:.1}). Investigate for a fault, misconfiguration, or workload change.",
                anomalies.len(),
                max_z
            ),
            confidence_score: confidence,
            estimated_savings: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anomaly(z: f64) -> Anomaly {
        Anomaly {
            t: 0.0,
            value: 100.0,
            z_score: z,
        }
    }

    fn waste(kind: WasteKind, fraction_below: f64) -> WasteFinding {
        WasteFinding {
            kind,
            fraction_below,
            threshold: 10.0,
            sample_count: 5,
        }
    }

    #[test]
    fn no_findings_yields_no_suggestions() {
        assert!(suggest_from_findings("cpu", None, &[], None).is_empty());
    }

    #[test]
    fn idle_waste_yields_high_confidence_cost_optimization() {
        let w = waste(WasteKind::Idle, 1.0);
        let s = suggest_from_findings("cpu", None, &[], Some(&w));
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].suggestion_type, "CostOptimization");
        assert!(s[0].confidence_score >= 0.9 && s[0].confidence_score <= 1.0);
        assert!(s[0].title.contains("cpu"));
    }

    #[test]
    fn underutilized_waste_yields_rightsizing() {
        let w = waste(WasteKind::Underutilized, 0.8);
        let s = suggest_from_findings("disk", None, &[], Some(&w));
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].suggestion_type, "RightSizing");
        assert!(s[0].confidence_score < 0.99);
    }

    #[test]
    fn anomalies_yield_risk_reduction_scaled_by_z() {
        let s = suggest_from_findings("lat", None, &[anomaly(2.0), anomaly(8.0)], None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].suggestion_type, "RiskReduction");
        assert!(s[0].title.contains('2'), "two anomalies named");
        // max |z| = 8 → 0.5 + 0.8 = 1.3, capped at 0.95.
        assert!((s[0].confidence_score - 0.95).abs() < 1e-9);
    }

    #[test]
    fn both_findings_yield_two_suggestions() {
        let w = waste(WasteKind::Underutilized, 0.7);
        let s = suggest_from_findings("mem", None, &[anomaly(5.0)], Some(&w));
        assert_eq!(s.len(), 2);
        // Every confidence is within the table's CHECK bound.
        assert!(
            s.iter()
                .all(|x| x.confidence_score >= 0.0 && x.confidence_score <= 1.0)
        );
    }
}
