//! Pure time-series math for metric history + forecasting (#34).
//!
//! This is the analytics substrate the AIOps chain builds on: anomaly detection
//! (#35) reads the summary's mean/stddev, suggestion generation (#36) and
//! what-if planning (#37) read the linear forecast, and budget alerts (#53/#54)
//! compare a projected value against a threshold. It holds ONLY pure functions
//! over a series of `(t, value)` points — no IO, no clock, no storage — so every
//! decision is deterministic and unit-testable. The IO (persisting and querying
//! `metric_samples`) lives in the API crate.
//!
//! `t` is a numeric time coordinate (the caller passes observation time as unix
//! seconds, f64); only differences and ordering matter to the math.

/// One observed sample: a time coordinate and its value.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct MetricPoint {
    pub t: f64,
    pub value: f64,
}

/// Descriptive statistics over a series. `stddev` is the population standard
/// deviation; `latest` is the value of the point with the greatest `t`.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct SeriesSummary {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
    pub latest: f64,
}

/// Coarse trend direction, derived from the least-squares slope. The thresholds
/// are on the raw slope (value units per unit `t`); `Flat` absorbs slopes within
/// `epsilon` of zero so noise around a level series does not read as a trend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Trend {
    Increasing,
    Decreasing,
    Flat,
}

/// Summarize a series. Returns `None` for an empty series (nothing to describe).
pub fn summarize(points: &[MetricPoint]) -> Option<SeriesSummary> {
    if points.is_empty() {
        return None;
    }
    let count = points.len();
    let mean = points.iter().map(|p| p.value).sum::<f64>() / count as f64;
    let variance = points.iter().map(|p| (p.value - mean).powi(2)).sum::<f64>() / count as f64;
    let min = points.iter().map(|p| p.value).fold(f64::INFINITY, f64::min);
    let max = points
        .iter()
        .map(|p| p.value)
        .fold(f64::NEG_INFINITY, f64::max);
    // `latest` = value at the greatest t (the series may be unordered).
    let latest = points
        .iter()
        .max_by(|a, b| a.t.total_cmp(&b.t))
        .map(|p| p.value)
        .unwrap_or(mean);
    Some(SeriesSummary {
        count,
        min,
        max,
        mean,
        stddev: variance.sqrt(),
        latest,
    })
}

/// Least-squares linear fit `value ≈ slope * t + intercept`. Returns `None` when
/// there are fewer than two points or every point shares the same `t` (no
/// variance in `t` → the slope is undefined). Ignores non-finite inputs' effect
/// only insofar as the caller is responsible for passing finite samples.
pub fn linear_fit(points: &[MetricPoint]) -> Option<(f64, f64)> {
    if points.len() < 2 {
        return None;
    }
    let n = points.len() as f64;
    let mean_t = points.iter().map(|p| p.t).sum::<f64>() / n;
    let mean_v = points.iter().map(|p| p.value).sum::<f64>() / n;
    let mut s_tt = 0.0;
    let mut s_tv = 0.0;
    for p in points {
        let dt = p.t - mean_t;
        s_tt += dt * dt;
        s_tv += dt * (p.value - mean_v);
    }
    if s_tt == 0.0 {
        return None; // all points at the same t
    }
    let slope = s_tv / s_tt;
    let intercept = mean_v - slope * mean_t;
    Some((slope, intercept))
}

/// Trend direction from the least-squares slope. A series that cannot be fit
/// (too few points / no `t` variance) reads as `Flat`. `epsilon` is the slope
/// magnitude below which the series is considered level.
pub fn trend(points: &[MetricPoint], epsilon: f64) -> Trend {
    match linear_fit(points) {
        Some((slope, _)) if slope > epsilon => Trend::Increasing,
        Some((slope, _)) if slope < -epsilon => Trend::Decreasing,
        _ => Trend::Flat,
    }
}

/// Project `count` future points, each `step` beyond the last observed `t`,
/// using the linear fit. When the series cannot be fit (fewer than two points or
/// no `t` variance) this falls back to a NAIVE flat forecast at the latest
/// value — a sensible default for the AIOps consumers rather than no data. An
/// empty series, a non-positive `step`, or `count == 0` yields no projection.
pub fn project_forward(points: &[MetricPoint], step: f64, count: usize) -> Vec<MetricPoint> {
    if points.is_empty() || count == 0 || step <= 0.0 || !step.is_finite() {
        return Vec::new();
    }
    let last_t = points.iter().map(|p| p.t).fold(f64::NEG_INFINITY, f64::max);
    let fit = linear_fit(points);
    let n = points.len() as f64;
    let mean_t = points.iter().map(|p| p.t).sum::<f64>() / n;
    let mean_v = points.iter().map(|p| p.value).sum::<f64>() / n;
    // Naive fallback value when there is no usable fit: the latest observation.
    let latest = points
        .iter()
        .max_by(|a, b| a.t.total_cmp(&b.t))
        .map(|p| p.value)
        .unwrap_or(0.0);
    (1..=count)
        .map(|i| {
            let t = last_t + step * i as f64;
            let value = match fit {
                // Centered projection (mean_v + slope*(t - mean_t)) instead of
                // slope*t + intercept: the offset (t - mean_t) is small, which
                // avoids the catastrophic cancellation that slope*t + intercept
                // can suffer when t is a large unix-seconds coordinate.
                Some((slope, _)) => mean_v + slope * (t - mean_t),
                None => latest,
            };
            MetricPoint { t, value }
        })
        // Drop any non-finite projection rather than emit NaN/Inf to consumers
        // (a defensive guard against absurd-but-finite inputs overflowing).
        .filter(|p| p.t.is_finite() && p.value.is_finite())
        .collect()
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
    fn summarize_empty_is_none() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn summarize_computes_stats() {
        let s = summarize(&pts(&[(0.0, 2.0), (1.0, 4.0), (2.0, 6.0)])).unwrap();
        assert_eq!(s.count, 3);
        assert_eq!(s.min, 2.0);
        assert_eq!(s.max, 6.0);
        assert!((s.mean - 4.0).abs() < 1e-9);
        // population stddev of [2,4,6] = sqrt(8/3) ≈ 1.632993...
        assert!((s.stddev - (8.0_f64 / 3.0).sqrt()).abs() < 1e-9);
        assert_eq!(s.latest, 6.0, "latest = value at greatest t");
    }

    #[test]
    fn latest_tracks_greatest_t_even_unordered() {
        let s = summarize(&pts(&[(2.0, 6.0), (0.0, 2.0), (1.0, 4.0)])).unwrap();
        assert_eq!(s.latest, 6.0);
    }

    #[test]
    fn linear_fit_recovers_known_line() {
        // value = 2*t + 0
        let (slope, intercept) =
            linear_fit(&pts(&[(0.0, 0.0), (1.0, 2.0), (2.0, 4.0), (3.0, 6.0)])).unwrap();
        assert!((slope - 2.0).abs() < 1e-9);
        assert!((intercept - 0.0).abs() < 1e-9);
    }

    #[test]
    fn linear_fit_degenerate_cases_are_none() {
        assert!(linear_fit(&pts(&[(1.0, 5.0)])).is_none(), "one point");
        assert!(
            linear_fit(&pts(&[(3.0, 1.0), (3.0, 9.0)])).is_none(),
            "no t variance"
        );
    }

    #[test]
    fn trend_classifies_by_slope() {
        assert_eq!(
            trend(&pts(&[(0.0, 0.0), (1.0, 2.0)]), 0.01),
            Trend::Increasing
        );
        assert_eq!(
            trend(&pts(&[(0.0, 5.0), (1.0, 3.0)]), 0.01),
            Trend::Decreasing
        );
        assert_eq!(trend(&pts(&[(0.0, 5.0), (1.0, 5.0)]), 0.01), Trend::Flat);
        assert_eq!(
            trend(&pts(&[(1.0, 5.0)]), 0.01),
            Trend::Flat,
            "unfittable → flat"
        );
    }

    #[test]
    fn project_forward_extends_the_line() {
        let f = project_forward(
            &pts(&[(0.0, 0.0), (1.0, 2.0), (2.0, 4.0), (3.0, 6.0)]),
            1.0,
            2,
        );
        assert_eq!(f.len(), 2);
        assert!((f[0].t - 4.0).abs() < 1e-9 && (f[0].value - 8.0).abs() < 1e-9);
        assert!((f[1].t - 5.0).abs() < 1e-9 && (f[1].value - 10.0).abs() < 1e-9);
    }

    #[test]
    fn project_forward_naive_when_unfittable() {
        // Single point → flat forecast at its value.
        let f = project_forward(&pts(&[(10.0, 7.0)]), 5.0, 2);
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0],
            MetricPoint {
                t: 15.0,
                value: 7.0
            }
        );
        assert_eq!(
            f[1],
            MetricPoint {
                t: 20.0,
                value: 7.0
            }
        );
    }

    #[test]
    fn project_forward_guards_bad_args() {
        let series = pts(&[(0.0, 1.0), (1.0, 2.0)]);
        assert!(project_forward(&series, 1.0, 0).is_empty(), "count 0");
        assert!(project_forward(&series, 0.0, 3).is_empty(), "step 0");
        assert!(
            project_forward(&series, -1.0, 3).is_empty(),
            "negative step"
        );
        assert!(project_forward(&[], 1.0, 3).is_empty(), "empty series");
    }
}
