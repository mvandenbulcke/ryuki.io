//! Pure budget-threshold evaluation over a metric series (#53).
//!
//! A budget is a threshold on a metric (e.g. "monthly cost must stay under
//! $10k", or "free capacity must stay above 20%"). This evaluates a budget
//! against both the LATEST observed value and the FORECAST peak, so an operator
//! is alerted not only when a budget is already breached but when the trend is
//! about to breach it. Pure and deterministic — the API supplies the series
//! summary and the projected peak (from [`crate::metric_forecast`]).

use crate::metric_forecast::SeriesSummary;

/// Which side of the threshold is a breach. `Above` = alert when the value
/// exceeds the threshold (a cost/usage cap). `Below` = alert when the value
/// falls under the threshold (a capacity/headroom floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetComparison {
    Above,
    Below,
}

impl BudgetComparison {
    /// Parse the stored/string form; unknown input defaults to `Above` (the
    /// common cost-cap case) so a row can never become unevaluable.
    pub fn from_str_or_above(raw: &str) -> Self {
        match raw {
            "below" => BudgetComparison::Below,
            _ => BudgetComparison::Above,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BudgetComparison::Above => "above",
            BudgetComparison::Below => "below",
        }
    }

    /// True when `value` breaches the threshold for this comparison. A
    /// non-finite value never breaches (it is treated as no signal).
    pub fn breaches(self, value: f64, threshold: f64) -> bool {
        if !value.is_finite() || !threshold.is_finite() {
            return false;
        }
        match self {
            BudgetComparison::Above => value > threshold,
            BudgetComparison::Below => value < threshold,
        }
    }
}

/// The result of evaluating one budget against a series.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct BudgetEvaluation {
    /// The latest observed value breaches the threshold right now.
    pub breached_now: bool,
    /// The forecast peak is projected to breach the threshold.
    pub breached_projected: bool,
    /// The latest observed value (`None` when the series is empty).
    pub latest: Option<f64>,
    /// The worst-case forecast value over the horizon for this comparison — the
    /// projected MAX for an `above` cap, the projected MIN for a `below` floor.
    /// `None` when not projectable.
    pub projected_extreme: Option<f64>,
    pub threshold: f64,
    pub comparison: BudgetComparison,
}

/// Evaluate a budget. `summary` carries the latest observed value; `projected_peak`
/// is the worst-case forecast value over the planning horizon (the max for an
/// `Above` budget, the min for a `Below` budget — the caller picks the relevant
/// extreme). A budget with a non-finite threshold never breaches.
pub fn evaluate_budget(
    threshold: f64,
    comparison: BudgetComparison,
    summary: Option<&SeriesSummary>,
    projected_extreme: Option<f64>,
) -> BudgetEvaluation {
    let latest = summary.map(|s| s.latest);
    let breached_now = latest.is_some_and(|v| comparison.breaches(v, threshold));
    let breached_projected = projected_extreme.is_some_and(|v| comparison.breaches(v, threshold));
    BudgetEvaluation {
        breached_now,
        breached_projected,
        latest,
        projected_extreme,
        threshold,
        comparison,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(latest: f64) -> SeriesSummary {
        SeriesSummary {
            count: 3,
            min: 0.0,
            max: latest,
            mean: latest,
            stddev: 0.0,
            latest,
        }
    }

    #[test]
    fn comparison_parses_and_renders() {
        assert_eq!(
            BudgetComparison::from_str_or_above("below"),
            BudgetComparison::Below
        );
        assert_eq!(
            BudgetComparison::from_str_or_above("above"),
            BudgetComparison::Above
        );
        assert_eq!(
            BudgetComparison::from_str_or_above("garbage"),
            BudgetComparison::Above
        );
        assert_eq!(BudgetComparison::Below.as_str(), "below");
    }

    #[test]
    fn above_breaches_when_value_exceeds_threshold() {
        let c = BudgetComparison::Above;
        assert!(c.breaches(11.0, 10.0));
        assert!(!c.breaches(10.0, 10.0), "equality is not a breach");
        assert!(!c.breaches(9.0, 10.0));
    }

    #[test]
    fn below_breaches_when_value_under_threshold() {
        let c = BudgetComparison::Below;
        assert!(c.breaches(9.0, 10.0));
        assert!(!c.breaches(10.0, 10.0));
        assert!(!c.breaches(11.0, 10.0));
    }

    #[test]
    fn nonfinite_never_breaches() {
        assert!(!BudgetComparison::Above.breaches(f64::NAN, 10.0));
        assert!(!BudgetComparison::Above.breaches(f64::INFINITY, 10.0));
        assert!(!BudgetComparison::Above.breaches(11.0, f64::NAN));
    }

    #[test]
    fn evaluate_flags_current_and_projected_separately() {
        // Latest 8 (under), projected peak 12 (over) for an Above budget of 10.
        let e = evaluate_budget(
            10.0,
            BudgetComparison::Above,
            Some(&summary(8.0)),
            Some(12.0),
        );
        assert!(!e.breached_now, "latest 8 is under 10");
        assert!(e.breached_projected, "projected 12 is over 10");
        assert_eq!(e.latest, Some(8.0));
        assert_eq!(e.projected_extreme, Some(12.0));
    }

    #[test]
    fn evaluate_with_no_data_breaches_nothing() {
        let e = evaluate_budget(10.0, BudgetComparison::Above, None, None);
        assert!(!e.breached_now && !e.breached_projected);
        assert_eq!(e.latest, None);
        assert_eq!(e.projected_extreme, None);
    }
}
