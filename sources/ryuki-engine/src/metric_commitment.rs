//! Pure reserved-capacity / commitment cost modeling (#54).
//!
//! Given a representative usage level (typically the mean or forecast of a
//! metric series, #34) and the rates for on-demand vs committed capacity, this
//! models the cost of committing to a reserved level: you pay the commitment
//! rate for the committed units regardless of use, plus the on-demand rate for
//! any overflow above the commitment. It reports the savings vs pure on-demand
//! and whether committing is worthwhile. Pure and deterministic — the API
//! supplies the usage estimate and the rates.

/// The modeled outcome of a commitment vs pure on-demand.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct CommitmentModel {
    pub usage: f64,
    pub committed_units: f64,
    pub on_demand_rate: f64,
    pub commitment_rate: f64,
    /// Cost of serving all usage at the on-demand rate.
    pub on_demand_cost: f64,
    /// Cost with the commitment: committed units at the commitment rate, plus
    /// any usage above the commitment at the on-demand rate.
    pub committed_cost: f64,
    /// `on_demand_cost - committed_cost` (positive = the commitment saves money).
    pub savings: f64,
    /// True when the commitment is cheaper than pure on-demand.
    pub recommended: bool,
    /// Fraction of the committed capacity actually used, in `[0, 1]` — a low
    /// value means the commitment is oversized (paying for idle reserved units).
    pub commitment_utilization: f64,
}

/// Model a commitment. Returns `None` when any input is non-finite or negative
/// (a meaningless plan). A zero commitment yields zero savings (it reduces to
/// pure on-demand), correctly never recommended.
pub fn model_commitment(
    usage: f64,
    on_demand_rate: f64,
    commitment_rate: f64,
    committed_units: f64,
) -> Option<CommitmentModel> {
    for v in [usage, on_demand_rate, commitment_rate, committed_units] {
        if !v.is_finite() || v < 0.0 {
            return None;
        }
    }
    let used_committed = usage.min(committed_units);
    let overflow = (usage - committed_units).max(0.0);
    let on_demand_cost = usage * on_demand_rate;
    let committed_cost = committed_units * commitment_rate + overflow * on_demand_rate;
    // Numerically stable savings: `usage - overflow == min(usage, committed)`, so
    // this reduces to a difference of COMMITTED-scale terms, never the
    // subtraction of two huge usage-scale totals (which would cancel to a wrong
    // 0 — or flip sign — for very large inputs).
    let savings = used_committed * on_demand_rate - committed_units * commitment_rate;
    // Finite inputs can still overflow to non-finite costs; reject the plan
    // rather than emit NaN/Inf.
    if !on_demand_cost.is_finite() || !committed_cost.is_finite() || !savings.is_finite() {
        return None;
    }
    let commitment_utilization = if committed_units > 0.0 {
        used_committed / committed_units
    } else {
        0.0
    };
    Some(CommitmentModel {
        usage,
        committed_units,
        on_demand_rate,
        commitment_rate,
        on_demand_cost,
        committed_cost,
        savings,
        recommended: savings > 0.0,
        commitment_utilization,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_utilization_commitment_saves() {
        // usage 100 fully covered by a 100-unit commitment at 0.6 vs 1.0.
        let m = model_commitment(100.0, 1.0, 0.6, 100.0).unwrap();
        assert!((m.on_demand_cost - 100.0).abs() < 1e-9);
        assert!((m.committed_cost - 60.0).abs() < 1e-9);
        assert!((m.savings - 40.0).abs() < 1e-9);
        assert!(m.recommended);
        assert!((m.commitment_utilization - 1.0).abs() < 1e-9);
    }

    #[test]
    fn over_commitment_wastes_money() {
        // Commit 100 but only use 50 → pay 60 vs 50 on-demand: a loss.
        let m = model_commitment(50.0, 1.0, 0.6, 100.0).unwrap();
        assert!((m.committed_cost - 60.0).abs() < 1e-9);
        assert!((m.on_demand_cost - 50.0).abs() < 1e-9);
        assert!(m.savings < 0.0);
        assert!(!m.recommended, "an oversized commitment is not recommended");
        assert!((m.commitment_utilization - 0.5).abs() < 1e-9);
    }

    #[test]
    fn overflow_above_commitment_is_on_demand() {
        // Use 150, commit 100: 60 (committed) + 50 (overflow on-demand) = 110 vs 150.
        let m = model_commitment(150.0, 1.0, 0.6, 100.0).unwrap();
        assert!((m.committed_cost - 110.0).abs() < 1e-9);
        assert!((m.savings - 40.0).abs() < 1e-9);
        assert!(m.recommended);
        assert!(
            (m.commitment_utilization - 1.0).abs() < 1e-9,
            "fully used commitment"
        );
    }

    #[test]
    fn zero_commitment_is_neutral() {
        let m = model_commitment(100.0, 1.0, 0.6, 0.0).unwrap();
        assert!((m.savings - 0.0).abs() < 1e-9, "no commitment = no savings");
        assert!(!m.recommended);
        assert_eq!(m.commitment_utilization, 0.0);
    }

    #[test]
    fn invalid_inputs_are_none() {
        assert!(model_commitment(f64::NAN, 1.0, 0.6, 100.0).is_none());
        assert!(model_commitment(100.0, -1.0, 0.6, 100.0).is_none());
        assert!(model_commitment(100.0, 1.0, f64::INFINITY, 100.0).is_none());
        assert!(model_commitment(-5.0, 1.0, 0.6, 100.0).is_none());
    }

    #[test]
    fn savings_is_exact_for_huge_usage() {
        // usage 1e16, commit 1 unit: savings = min(1e16,1)*1.0 - 1*0.6 = 0.4.
        // A naive on_demand_cost - committed_cost would cancel ~1e16 totals to 0.
        let m = model_commitment(1e16, 1.0, 0.6, 1.0).unwrap();
        assert!(
            (m.savings - 0.4).abs() < 1e-9,
            "stable savings, got {}",
            m.savings
        );
        assert!(m.recommended);
    }

    #[test]
    fn overflowed_cost_is_rejected() {
        // f64::MAX * f64::MAX overflows on_demand_cost to +Inf → uncomputable.
        assert!(model_commitment(f64::MAX, f64::MAX, 1.0, 1.0).is_none());
    }
}
