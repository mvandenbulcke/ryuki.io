//! Pure what-if capacity & cost planning over a metric series (#37).
//!
//! Builds on [`crate::metric_forecast`]: project the series forward, apply a
//! hypothetical growth factor (e.g. 1.2 = "what if load grows 20%"), and report
//! whether — and when — the projection would breach a capacity/cost ceiling.
//! Pure and deterministic (no IO, no clock); the API layer supplies the series
//! and the planning knobs.

use crate::metric_forecast::{MetricPoint, project_forward};

/// The outcome of a what-if projection against a ceiling.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct WhatIfResult {
    /// The growth-adjusted projected points.
    pub projected: Vec<MetricPoint>,
    pub ceiling: f64,
    pub growth_factor: f64,
    /// True when any projected point exceeds the ceiling.
    pub breaches: bool,
    /// The `t` of the FIRST projected point above the ceiling, if any.
    pub first_breach_t: Option<f64>,
    /// The largest projected value over the horizon (`None` for an empty
    /// projection — e.g. no input data).
    pub peak_projected: Option<f64>,
    /// `ceiling - peak_projected` (`None` when there is no projection). Negative
    /// when the peak is above the ceiling.
    pub headroom: Option<f64>,
}

/// Project the series forward `horizon` steps of `step`, scale each projected
/// value by `growth_factor` (a hypothetical load/cost multiplier), and test the
/// result against `ceiling`. Returns an empty/neutral result when the inputs are
/// unusable (no data, non-positive/non-finite step or horizon 0) or when any
/// knob is non-finite — a meaningless plan reports no breach rather than a bogus
/// one. `growth_factor` is clamped to be non-negative (a negative multiplier is
/// meaningless for load/cost).
pub fn what_if(
    points: &[MetricPoint],
    step: f64,
    horizon: usize,
    growth_factor: f64,
    ceiling: f64,
) -> WhatIfResult {
    // Any non-finite knob makes the plan meaningless → a neutral result, NOT a
    // bogus breach. (The API rejects non-finite knobs before this, but the pure
    // contract is "non-finite knob ⇒ neutral".)
    if !growth_factor.is_finite() || !ceiling.is_finite() {
        return WhatIfResult {
            projected: Vec::new(),
            ceiling,
            growth_factor,
            breaches: false,
            first_breach_t: None,
            peak_projected: None,
            headroom: None,
        };
    }
    let growth = growth_factor.max(0.0); // negative load/cost growth is meaningless
    let neutral = WhatIfResult {
        projected: Vec::new(),
        ceiling,
        growth_factor: growth,
        breaches: false,
        first_breach_t: None,
        peak_projected: None,
        headroom: None,
    };

    let base = project_forward(points, step, horizon);
    if base.is_empty() {
        return neutral;
    }
    // Scale each projection by the growth factor. CRUCIAL: do NOT drop an
    // overflow (`value * growth` → ±Inf). An unbounded projection breaches any
    // finite ceiling, so it must register as a breach — not silently vanish into
    // a neutral "no breach" result.
    let projected: Vec<MetricPoint> = base
        .iter()
        .map(|p| MetricPoint {
            t: p.t,
            value: p.value * growth,
        })
        .collect();

    // A breach is the first projected point that overflows (non-finite, i.e.
    // unbounded) OR strictly exceeds the ceiling. Equality is NOT a breach
    // (zero headroom, exactly at the limit).
    let first_breach_t = projected
        .iter()
        .find(|p| !p.value.is_finite() || p.value > ceiling)
        .map(|p| p.t);
    let overflowed = projected.iter().any(|p| !p.value.is_finite());
    let finite_peak = projected
        .iter()
        .map(|p| p.value)
        .filter(|v| v.is_finite())
        .fold(f64::NEG_INFINITY, f64::max);
    // An overflowed (unbounded) projection has no finite peak or headroom.
    let peak_projected = if overflowed || !finite_peak.is_finite() {
        None
    } else {
        Some(finite_peak)
    };
    // Guard the subtraction itself against overflow to a non-finite headroom.
    let headroom = peak_projected
        .map(|pk| ceiling - pk)
        .filter(|h| h.is_finite());

    WhatIfResult {
        projected,
        ceiling,
        growth_factor: growth,
        breaches: first_breach_t.is_some(),
        first_breach_t,
        peak_projected,
        headroom,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pts(raw: &[(f64, f64)]) -> Vec<MetricPoint> {
        raw.iter()
            .map(|&(t, value)| MetricPoint { t, value })
            .collect()
    }

    // A rising line: value = 10*t, so projections climb predictably.
    fn rising() -> Vec<MetricPoint> {
        pts(&[(0.0, 0.0), (1.0, 10.0), (2.0, 20.0), (3.0, 30.0)])
    }

    #[test]
    fn no_data_is_neutral() {
        let r = what_if(&[], 1.0, 3, 1.0, 100.0);
        assert!(r.projected.is_empty());
        assert!(!r.breaches);
        assert_eq!(r.peak_projected, None);
        assert_eq!(r.headroom, None);
    }

    #[test]
    fn projects_and_detects_breach() {
        // value = 10*t; project t=4,5,6 → 40,50,60. Ceiling 45 → breach at t=5.
        let r = what_if(&rising(), 1.0, 3, 1.0, 45.0);
        assert_eq!(r.projected.len(), 3);
        assert!(r.breaches);
        assert_eq!(r.first_breach_t, Some(5.0));
        assert_eq!(r.peak_projected, Some(60.0));
        assert!((r.headroom.unwrap() - (45.0 - 60.0)).abs() < 1e-9);
    }

    #[test]
    fn no_breach_when_under_ceiling() {
        let r = what_if(&rising(), 1.0, 3, 1.0, 1000.0);
        assert!(!r.breaches);
        assert_eq!(r.first_breach_t, None);
        assert!(r.headroom.unwrap() > 0.0);
    }

    #[test]
    fn growth_factor_scales_the_projection() {
        // Doubling the projected load pushes the peak from 60 to 120.
        let r = what_if(&rising(), 1.0, 3, 2.0, 1000.0);
        assert_eq!(r.peak_projected, Some(120.0));
        assert_eq!(r.growth_factor, 2.0);
    }

    #[test]
    fn negative_growth_is_clamped_to_zero() {
        let r = what_if(&rising(), 1.0, 3, -5.0, 100.0);
        assert_eq!(r.growth_factor, 0.0);
        // All projected values become 0 → no breach, peak 0.
        assert_eq!(r.peak_projected, Some(0.0));
        assert!(!r.breaches);
    }

    #[test]
    fn nonfinite_knobs_are_neutral() {
        // Both a non-finite growth and a non-finite ceiling produce an empty,
        // no-breach result (not a bogus breach).
        let g = what_if(&rising(), 1.0, 3, f64::NAN, 100.0);
        assert!(
            g.projected.is_empty() && !g.breaches,
            "non-finite growth is neutral"
        );
        let c = what_if(&rising(), 1.0, 3, 1.0, f64::INFINITY);
        assert!(
            c.projected.is_empty() && !c.breaches,
            "non-finite ceiling is neutral"
        );
    }

    #[test]
    fn overflow_counts_as_breach_not_neutral() {
        // A finite-but-enormous growth overflows the projection to +Inf. That is
        // an unbounded projection — it must register as a BREACH, never get
        // filtered into a neutral "no breach" result.
        let r = what_if(&rising(), 1.0, 3, f64::MAX, 100.0);
        assert!(
            r.breaches,
            "an overflowed projection breaches any finite ceiling"
        );
        assert!(r.first_breach_t.is_some());
        assert_eq!(
            r.peak_projected, None,
            "an unbounded projection has no finite peak"
        );
        assert_eq!(r.headroom, None);
    }

    #[test]
    fn exactly_at_ceiling_is_not_a_breach() {
        // Projection peaks at exactly 60; a ceiling of 60 is zero headroom, not a
        // breach (breach is strictly greater-than).
        let r = what_if(&rising(), 1.0, 3, 1.0, 60.0);
        assert!(
            !r.breaches,
            "a value exactly at the ceiling is not a breach"
        );
        assert_eq!(r.first_breach_t, None);
        assert!((r.headroom.unwrap() - 0.0).abs() < 1e-9);
    }
}
