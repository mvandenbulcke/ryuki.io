//! Pure SLO / error-budget math (#25).
//!
//! An SLO is a target reliability (e.g. 0.999) over a window. Given the count of
//! GOOD events and TOTAL events in the window, this computes the attainment (the
//! SLI), the error budget (the allowed bad fraction `1 - target`), how much of
//! that budget has been consumed, and whether the SLO is currently met. Pure and
//! deterministic — the API supplies the good/total counts (summed from the
//! `metric_samples` substrate) and the target.

/// The evaluated state of one SLO over its window.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct SloStatus {
    pub target: f64,
    pub good: f64,
    pub total: f64,
    /// The SLI: `good / total`.
    pub attainment: f64,
    /// The allowed bad fraction: `1 - target`.
    pub error_budget: f64,
    /// Fraction of the error budget consumed: `(1 - attainment) / error_budget`.
    /// `> 1.0` means the budget is exhausted (the SLO is breached).
    pub budget_consumed_fraction: f64,
    /// `1 - budget_consumed_fraction` — NEGATIVE once the budget is overspent.
    pub budget_remaining_fraction: f64,
    /// True when the attainment meets or exceeds the target.
    pub compliant: bool,
}

/// Compute the SLO status from event counts. Returns `None` for non-finite
/// inputs, a non-positive total, a `good` outside `[0, total]`, or a `target`
/// outside the open interval `(0, 1)` — all of which make the SLO meaningless.
pub fn compute_slo(good: f64, total: f64, target: f64) -> Option<SloStatus> {
    if !good.is_finite() || !total.is_finite() || !target.is_finite() {
        return None;
    }
    if total <= 0.0 || good < 0.0 || good > total {
        return None;
    }
    if !(target > 0.0 && target < 1.0) {
        return None;
    }
    let attainment = good / total;
    let error_budget = 1.0 - target;
    let observed_bad = 1.0 - attainment;
    let budget_consumed_fraction = observed_bad / error_budget;
    Some(SloStatus {
        target,
        good,
        total,
        attainment,
        error_budget,
        budget_consumed_fraction,
        budget_remaining_fraction: 1.0 - budget_consumed_fraction,
        compliant: attainment >= target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_attainment_full_budget() {
        // 1000/1000 against a 99.9% target: 100% attainment, budget untouched.
        let s = compute_slo(1000.0, 1000.0, 0.999).unwrap();
        assert!((s.attainment - 1.0).abs() < 1e-9);
        assert!((s.error_budget - 0.001).abs() < 1e-9);
        assert!((s.budget_consumed_fraction - 0.0).abs() < 1e-9);
        assert!((s.budget_remaining_fraction - 1.0).abs() < 1e-9);
        assert!(s.compliant);
    }

    #[test]
    fn exactly_at_target_is_compliant_budget_exhausted() {
        // 999/1000 = 99.9% exactly meets a 0.999 target: budget fully consumed
        // but not overspent, and still compliant (>=).
        let s = compute_slo(999.0, 1000.0, 0.999).unwrap();
        assert!((s.attainment - 0.999).abs() < 1e-9);
        assert!((s.budget_consumed_fraction - 1.0).abs() < 1e-6);
        assert!(s.budget_remaining_fraction.abs() < 1e-6);
        assert!(s.compliant, "exactly at target is compliant");
    }

    #[test]
    fn breach_overspends_budget_and_is_not_compliant() {
        // 998/1000 = 99.8% misses a 0.999 target: budget overspent (2x), remaining
        // goes negative, not compliant.
        let s = compute_slo(998.0, 1000.0, 0.999).unwrap();
        assert!(!s.compliant);
        assert!(s.budget_consumed_fraction > 1.0, "budget exhausted");
        assert!(s.budget_remaining_fraction < 0.0, "remaining is negative");
    }

    #[test]
    fn half_budget_consumed() {
        // 9995/10000 = 99.95% against 0.999: observed bad 0.0005, budget 0.001 →
        // half the budget consumed.
        let s = compute_slo(9995.0, 10000.0, 0.999).unwrap();
        assert!((s.budget_consumed_fraction - 0.5).abs() < 1e-6);
        assert!(s.compliant);
    }

    #[test]
    fn invalid_inputs_are_none() {
        assert!(compute_slo(10.0, 0.0, 0.99).is_none(), "zero total");
        assert!(compute_slo(11.0, 10.0, 0.99).is_none(), "good > total");
        assert!(compute_slo(-1.0, 10.0, 0.99).is_none(), "negative good");
        assert!(compute_slo(5.0, 10.0, 0.0).is_none(), "target 0");
        assert!(compute_slo(5.0, 10.0, 1.0).is_none(), "target 1");
        assert!(compute_slo(f64::NAN, 10.0, 0.99).is_none(), "NaN good");
    }
}
