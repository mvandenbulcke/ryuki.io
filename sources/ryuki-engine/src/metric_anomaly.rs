//! Pure anomaly + waste detection over a metric series (#35).
//!
//! Builds directly on [`crate::metric_forecast`]: an anomaly is a sample whose
//! leave-one-out z-score (distance, in standard deviations, from the baseline of
//! the OTHER samples) exceeds a threshold; waste is a series that sits at or
//! below a low-utilization
//! threshold for a large enough fraction of its samples. Both are pure,
//! deterministic functions over `(t, value)` points — no IO, no clock — so the
//! AIOps suggestion engine (#36) and budget alerts (#53/#54) can consume them
//! and they stay fully unit-testable.

use crate::metric_forecast::MetricPoint;

/// A sample that deviates from the series mean by at least the z-threshold.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Anomaly {
    /// Time coordinate of the anomalous sample (unix seconds, as supplied).
    pub t: f64,
    pub value: f64,
    /// Signed leave-one-out z-score: `(value - mean_others) / stddev_others`,
    /// where the baseline excludes this sample. Positive = a spike above the
    /// baseline, negative = a dip below it. Capped to ±1000 for a zero-variance
    /// baseline.
    pub z_score: f64,
}

/// How a series reads as wasteful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WasteKind {
    /// Every sample is at/below the threshold — effectively unused.
    Idle,
    /// A large fraction (but not all) of samples are at/below the threshold.
    Underutilized,
}

/// A waste finding over a series.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct WasteFinding {
    pub kind: WasteKind,
    /// Fraction of samples at or below `threshold`, in `[0, 1]`.
    pub fraction_below: f64,
    pub threshold: f64,
    pub sample_count: usize,
}

/// Smallest series for which detection is meaningful. Below this, mean/stddev
/// are too noisy to call an anomaly, and a "waste" verdict would be premature.
pub const MIN_SAMPLES_FOR_DETECTION: usize = 3;

/// Largest z-score the detector will report. A zero-variance leave-one-out
/// baseline (every OTHER sample identical) makes a deviating point infinitely
/// anomalous; we cap that to a large finite, JSON-serialisable value so the
/// response never carries a non-finite z-score.
const MAX_Z: f64 = 1000.0;

/// Detect anomalies: samples whose absolute z-score is at least `z_threshold`.
///
/// The z-score is computed LEAVE-ONE-OUT — each sample is compared against the
/// mean/stddev of the OTHER samples, not the whole series including itself. This
/// matters: an in-sample population z-score is bounded by `sqrt(n-1)`, so a
/// 3-sigma threshold would be unreachable for a short series (n < 10) and
/// anomaly detection would silently never fire. Leave-one-out unbounds the
/// score, so a real spike clears the default threshold even on a small series.
///
/// Returns an empty vec when there are too few samples, or when `z_threshold` is
/// non-positive or non-finite (a meaningless threshold detects nothing rather
/// than flagging everything). A point sitting exactly on the others' mean has
/// z 0 and is never flagged.
pub fn detect_anomalies(points: &[MetricPoint], z_threshold: f64) -> Vec<Anomaly> {
    if z_threshold <= 0.0 || !z_threshold.is_finite() {
        return Vec::new();
    }
    // Exclude any sample that would poison the running totals from BOTH the
    // baseline and the output: NaN / ±inf, AND a finite value so extreme that its
    // SQUARE overflows to ±inf (|v| ≳ 1.34e154). Either kind otherwise makes
    // `sum`/`sum_sq` non-finite → every leave-one-out z is NaN/inf →
    // `z.abs() >= z_threshold` is false everywhere → anomaly detection is SILENTLY
    // muted for the entire series (the real spike is missed). Checking
    // `(v*v).is_finite()` covers both the value and its square in one predicate.
    // Ingest rejects non-finite values, so this is defense-in-depth against any
    // non-ingest write path (float8 columns accept NaN and any finite magnitude).
    let finite: Vec<&MetricPoint> = points
        .iter()
        .filter(|p| p.value.is_finite() && (p.value * p.value).is_finite())
        .collect();
    if finite.len() < MIN_SAMPLES_FOR_DETECTION {
        return Vec::new();
    }
    let n = finite.len() as f64;
    let sum: f64 = finite.iter().map(|p| p.value).sum();
    let sum_sq: f64 = finite.iter().map(|p| p.value * p.value).sum();
    finite
        .iter()
        .filter_map(|p| {
            let x = p.value;
            // Mean and population variance of the OTHER (n-1) samples, in O(1)
            // from the running totals.
            let mean_others = (sum - x) / (n - 1.0);
            let var_others = ((sum_sq - x * x) / (n - 1.0)) - mean_others * mean_others;
            let std_others = var_others.max(0.0).sqrt();
            let z = if std_others > 0.0 {
                (x - mean_others) / std_others
            } else if x != mean_others {
                // The other samples are identical: any deviation is a clear,
                // effectively-infinite anomaly. Cap to a finite sentinel.
                (x - mean_others).signum() * MAX_Z
            } else {
                0.0
            };
            let z = z.clamp(-MAX_Z, MAX_Z);
            if z.abs() >= z_threshold {
                Some(Anomaly {
                    t: p.t,
                    value: x,
                    z_score: z,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Detect waste: flag the series when at least `min_fraction` of its samples are
/// at or below `threshold`. Returns `None` for too-few samples or when the
/// fraction is below `min_fraction`. `Idle` when every sample is at/below the
/// threshold, otherwise `Underutilized`. `min_fraction` is clamped to `[0, 1]`.
pub fn detect_waste(
    points: &[MetricPoint],
    threshold: f64,
    min_fraction: f64,
) -> Option<WasteFinding> {
    if points.len() < MIN_SAMPLES_FOR_DETECTION {
        return None;
    }
    // A non-finite threshold or fraction is meaningless; never flag waste off it
    // (NaN survives `clamp` and would make the `<` comparison falsely false).
    if !threshold.is_finite() || !min_fraction.is_finite() {
        return None;
    }
    let min_fraction = min_fraction.clamp(0.0, 1.0);
    let below = points.iter().filter(|p| p.value <= threshold).count();
    let fraction_below = below as f64 / points.len() as f64;
    if fraction_below < min_fraction {
        return None;
    }
    let kind = if below == points.len() {
        WasteKind::Idle
    } else {
        WasteKind::Underutilized
    };
    Some(WasteFinding {
        kind,
        fraction_below,
        threshold,
        sample_count: points.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pts(raw: &[(f64, f64)]) -> Vec<MetricPoint> {
        raw.iter()
            .map(|&(t, value)| MetricPoint { t, value })
            .collect()
    }

    #[test]
    fn too_few_samples_yield_nothing() {
        assert!(detect_anomalies(&pts(&[(0.0, 1.0), (1.0, 99.0)]), 2.0).is_empty());
        assert!(detect_waste(&pts(&[(0.0, 0.0), (1.0, 0.0)]), 1.0, 0.5).is_none());
    }

    #[test]
    fn flat_series_has_no_anomalies() {
        // Zero variance → nothing can be anomalous.
        assert!(detect_anomalies(&pts(&[(0.0, 5.0), (1.0, 5.0), (2.0, 5.0)]), 1.0).is_empty());
    }

    #[test]
    fn spike_is_flagged_as_anomaly() {
        // A clear outlier among an otherwise level series.
        let series = pts(&[
            (0.0, 10.0),
            (1.0, 10.0),
            (2.0, 10.0),
            (3.0, 10.0),
            (4.0, 100.0),
        ]);
        let found = detect_anomalies(&series, 1.5);
        assert_eq!(found.len(), 1, "exactly the spike is anomalous");
        assert_eq!(found[0].value, 100.0);
        assert!(found[0].z_score > 0.0, "a spike has a positive z-score");
    }

    #[test]
    fn non_finite_sample_does_not_mute_detection() {
        // Regression: a single NaN (or ±inf) sample used to poison sum/sum_sq so
        // every z-score was NaN and the real 10→100 spike was silently missed.
        // The NaN is excluded from the baseline and output; the spike is still found.
        let series = pts(&[
            (0.0, 10.0),
            (1.0, 10.0),
            (2.0, f64::NAN),
            (3.0, 10.0),
            (4.0, 100.0),
        ]);
        let found = detect_anomalies(&series, 1.5);
        assert_eq!(
            found.len(),
            1,
            "the spike must still be detected: {found:?}"
        );
        assert_eq!(found[0].value, 100.0);
        assert!(
            found[0].z_score.is_finite(),
            "reported z-score must be finite"
        );
        // An infinity is likewise excluded (not treated as a giant spike).
        let series_inf = pts(&[
            (0.0, 10.0),
            (1.0, 10.0),
            (2.0, f64::INFINITY),
            (3.0, 10.0),
            (4.0, 100.0),
        ]);
        let found_inf = detect_anomalies(&series_inf, 1.5);
        assert_eq!(found_inf.len(), 1);
        assert_eq!(found_inf[0].value, 100.0);
    }

    #[test]
    fn all_non_finite_yields_nothing() {
        // After filtering, too few finite samples → no detection (no panic/NaN).
        let series = pts(&[(0.0, f64::NAN), (1.0, f64::NAN), (2.0, 10.0)]);
        assert!(detect_anomalies(&series, 1.5).is_empty());
    }

    #[test]
    fn square_overflowing_value_does_not_mute_detection() {
        // A finite value whose SQUARE overflows to +inf (1e200² = inf) would poison
        // sum_sq and mute the whole series. It must be excluded like a non-finite,
        // leaving the real 10→100 spike detectable.
        let series = pts(&[
            (0.0, 10.0),
            (1.0, 10.0),
            (2.0, 1e200),
            (3.0, 10.0),
            (4.0, 100.0),
        ]);
        let found = detect_anomalies(&series, 1.5);
        assert_eq!(
            found.len(),
            1,
            "the spike must still be detected: {found:?}"
        );
        assert_eq!(found[0].value, 100.0);
        assert!(found[0].z_score.is_finite());
    }

    #[test]
    fn on_mean_point_is_never_flagged() {
        // For [9, 10, 11], the leave-one-out baseline for the middle point is
        // {9, 11} (mean 10) → z 0, never flagged; the two outer points sit ±3
        // sigma from their own leave-one-out baselines and are flagged.
        let series = pts(&[(0.0, 9.0), (1.0, 10.0), (2.0, 11.0)]);
        let found = detect_anomalies(&series, 2.0);
        assert!(
            found.iter().all(|a| a.value != 10.0),
            "the on-mean point is never anomalous"
        );
        assert_eq!(found.len(), 2, "both deviating points are flagged");
    }

    #[test]
    fn non_positive_or_nonfinite_threshold_detects_nothing() {
        let series = pts(&[(0.0, 1.0), (1.0, 1.0), (2.0, 1.0), (3.0, 50.0)]);
        assert!(detect_anomalies(&series, 0.0).is_empty(), "zero threshold");
        assert!(
            detect_anomalies(&series, -1.0).is_empty(),
            "negative threshold"
        );
        assert!(
            detect_anomalies(&series, f64::NAN).is_empty(),
            "NaN threshold"
        );
    }

    #[test]
    fn default_threshold_flags_spike_in_small_series() {
        // The key fix: with leave-one-out, a 3-sigma threshold is reachable even
        // for n = 5. An in-sample population z here caps at 2.0 and would miss
        // the spike at the default threshold.
        let series = pts(&[
            (0.0, 10.0),
            (1.0, 10.0),
            (2.0, 10.0),
            (3.0, 10.0),
            (4.0, 100.0),
        ]);
        let found = detect_anomalies(&series, 3.0);
        assert_eq!(found.len(), 1, "the spike clears the default threshold");
        assert_eq!(found[0].value, 100.0);
    }

    #[test]
    fn nonfinite_waste_params_never_flag() {
        let series = pts(&[(0.0, 0.0), (1.0, 0.0), (2.0, 0.0)]);
        assert!(
            detect_waste(&series, f64::NAN, 0.5).is_none(),
            "NaN threshold"
        );
        assert!(
            detect_waste(&series, 1.0, f64::NAN).is_none(),
            "NaN fraction"
        );
    }

    #[test]
    fn idle_series_is_waste_idle() {
        let series = pts(&[(0.0, 0.0), (1.0, 0.0), (2.0, 0.0)]);
        let w = detect_waste(&series, 0.0, 0.5).unwrap();
        assert_eq!(w.kind, WasteKind::Idle);
        assert!((w.fraction_below - 1.0).abs() < 1e-9);
    }

    #[test]
    fn mostly_low_series_is_underutilized() {
        // 4 of 5 at/below 10 → 0.8 >= 0.6 → underutilized (not idle).
        let series = pts(&[(0.0, 5.0), (1.0, 8.0), (2.0, 3.0), (3.0, 9.0), (4.0, 90.0)]);
        let w = detect_waste(&series, 10.0, 0.6).unwrap();
        assert_eq!(w.kind, WasteKind::Underutilized);
        assert!((w.fraction_below - 0.8).abs() < 1e-9);
        assert_eq!(w.sample_count, 5);
    }

    #[test]
    fn healthy_series_is_not_waste() {
        let series = pts(&[(0.0, 70.0), (1.0, 80.0), (2.0, 75.0)]);
        assert!(detect_waste(&series, 10.0, 0.5).is_none());
    }
}
