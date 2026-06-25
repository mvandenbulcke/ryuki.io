//! Pure dependency self-health aggregation (#6).
//!
//! The binary `/ready` probe answers "can this replica serve?". This models the
//! finer question "which DEPENDENCY is unhealthy?": the API probes each backing
//! dependency (database, migrations, scheduler liveness, …) and this module
//! folds the per-dependency results into one overall verdict.
//!
//! Alerting-safe by construction: a probe that ERRORED is reported `down`, never
//! silently healthy, and an EMPTY probe set is `unhealthy` — absence of evidence
//! must never read as health. Pure: the API performs the IO and passes results
//! in.

use serde::Serialize;

/// Health of a single backing dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyHealth {
    /// Probed and fully functional.
    Healthy,
    /// Probed and impaired but not fully unavailable (e.g. scheduler lagging).
    Degraded,
    /// Probed and unavailable, or the probe itself failed.
    Down,
}

impl DependencyHealth {
    pub fn as_str(&self) -> &'static str {
        match self {
            DependencyHealth::Healthy => "healthy",
            DependencyHealth::Degraded => "degraded",
            DependencyHealth::Down => "down",
        }
    }
}

/// One probed dependency.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DependencyProbe {
    pub name: String,
    pub health: DependencyHealth,
    /// Short, non-sensitive explanation (never raw errors/secrets).
    pub detail: Option<String>,
}

impl DependencyProbe {
    pub fn healthy(name: impl Into<String>) -> Self {
        DependencyProbe {
            name: name.into(),
            health: DependencyHealth::Healthy,
            detail: None,
        }
    }

    pub fn degraded(name: impl Into<String>, detail: impl Into<String>) -> Self {
        DependencyProbe {
            name: name.into(),
            health: DependencyHealth::Degraded,
            detail: Some(detail.into()),
        }
    }

    pub fn down(name: impl Into<String>, detail: impl Into<String>) -> Self {
        DependencyProbe {
            name: name.into(),
            health: DependencyHealth::Down,
            detail: Some(detail.into()),
        }
    }
}

/// The aggregate verdict across all probed dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

impl OverallHealth {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverallHealth::Healthy => "healthy",
            OverallHealth::Degraded => "degraded",
            OverallHealth::Unhealthy => "unhealthy",
        }
    }

    /// Whether the platform can still serve (healthy or degraded). The API maps
    /// this to the HTTP status (200 vs 503).
    pub fn is_serving(&self) -> bool {
        matches!(self, OverallHealth::Healthy | OverallHealth::Degraded)
    }
}

/// Fold per-dependency probes into one verdict. ANY `down` ⇒ `unhealthy`; else
/// ANY `degraded` ⇒ `degraded`; else `healthy`. An EMPTY set is `unhealthy` — no
/// evidence of health must never be reported as healthy.
pub fn aggregate(probes: &[DependencyProbe]) -> OverallHealth {
    if probes.is_empty() {
        return OverallHealth::Unhealthy;
    }
    if probes.iter().any(|p| p.health == DependencyHealth::Down) {
        return OverallHealth::Unhealthy;
    }
    if probes
        .iter()
        .any(|p| p.health == DependencyHealth::Degraded)
    {
        return OverallHealth::Degraded;
    }
    OverallHealth::Healthy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_unhealthy_not_healthy() {
        // The critical alerting-safety property: no probes => not "healthy".
        assert_eq!(aggregate(&[]), OverallHealth::Unhealthy);
    }

    #[test]
    fn all_healthy_is_healthy() {
        let probes = vec![
            DependencyProbe::healthy("database"),
            DependencyProbe::healthy("scheduler"),
        ];
        assert_eq!(aggregate(&probes), OverallHealth::Healthy);
    }

    #[test]
    fn any_degraded_is_degraded() {
        let probes = vec![
            DependencyProbe::healthy("database"),
            DependencyProbe::degraded("scheduler", "1 schedule overdue"),
        ];
        assert_eq!(aggregate(&probes), OverallHealth::Degraded);
        assert!(aggregate(&probes).is_serving());
    }

    #[test]
    fn any_down_is_unhealthy_and_beats_degraded() {
        let probes = vec![
            DependencyProbe::degraded("scheduler", "lagging"),
            DependencyProbe::down("database", "connectivity probe failed"),
        ];
        assert_eq!(aggregate(&probes), OverallHealth::Unhealthy);
        assert!(!aggregate(&probes).is_serving());
    }

    #[test]
    fn constructors_set_expected_health() {
        assert_eq!(
            DependencyProbe::healthy("x").health,
            DependencyHealth::Healthy
        );
        assert_eq!(
            DependencyProbe::degraded("x", "d").health,
            DependencyHealth::Degraded
        );
        assert_eq!(
            DependencyProbe::down("x", "d").health,
            DependencyHealth::Down
        );
    }
}
