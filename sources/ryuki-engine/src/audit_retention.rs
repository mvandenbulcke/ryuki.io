//! Pure audit-log retention reporting (#62).
//!
//! The audit trail is append-only and tamper-evident (hash-chained), so it only
//! grows. This gives operators visibility into that growth and whether any
//! entries have aged past a retention window — the input to a future
//! partitioning/archival step (which is a SEPARATE, careful change because it
//! must preserve the hash chain). Pure: the API runs the counts and passes them
//! in; this clamps and classifies them.

use serde::Serialize;

/// Retention posture of the audit log against a policy window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRetentionStatus {
    /// No entries at all.
    Empty,
    /// Every entry is within the retention window.
    Compliant,
    /// Some entries have aged past the window — archival/partitioning is due.
    ArchivalRecommended,
}

impl AuditRetentionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditRetentionStatus::Empty => "empty",
            AuditRetentionStatus::Compliant => "compliant",
            AuditRetentionStatus::ArchivalRecommended => "archival_recommended",
        }
    }
}

/// A structured audit retention report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRetentionReport {
    pub total_entries: i64,
    pub within_retention: i64,
    pub beyond_retention: i64,
    /// Age of the OLDEST entry in whole days (`None` when the log is empty).
    pub oldest_age_days: Option<i64>,
    pub retention_days: i64,
    pub status: AuditRetentionStatus,
}

/// Build the report from raw counts. Defensive against inconsistent inputs:
/// `beyond_retention` is clamped into `[0, total]`, `within` is the remainder,
/// and the oldest age is normalised.
///
/// Invariant GUARANTEED for ANY input (so the report is never self-contradictory):
/// `oldest_age_days.is_some()` exactly when `total_entries > 0`. An empty log
/// never carries an age; a non-empty log always does (a missing `oldest_age_secs`
/// degrades to 0 rather than a contradictory `None`). The caller's SQL ties these
/// together — `count(*) = 0` iff `min(occurred_at) IS NULL` — but this function
/// does not rely on that. `status` is `archival_recommended` iff some entry is
/// beyond the window, `empty` iff there are no entries, else `compliant`.
pub fn build_audit_retention(
    total_entries: i64,
    beyond_retention: i64,
    oldest_age_secs: Option<i64>,
    retention_days: i64,
) -> AuditRetentionReport {
    let total = total_entries.max(0);
    let beyond = beyond_retention.clamp(0, total);
    let within = total - beyond;
    let status = if total == 0 {
        AuditRetentionStatus::Empty
    } else if beyond > 0 {
        AuditRetentionStatus::ArchivalRecommended
    } else {
        AuditRetentionStatus::Compliant
    };
    // An empty log reports no age; a non-empty log ALWAYS reports one (a missing
    // age degrades to 0, never a contradictory None for total > 0).
    let oldest_age_days = if total == 0 {
        None
    } else {
        Some(oldest_age_secs.unwrap_or(0).max(0) / 86_400)
    };
    AuditRetentionReport {
        total_entries: total,
        within_retention: within,
        beyond_retention: beyond,
        oldest_age_days,
        retention_days,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_log_is_empty_status() {
        let r = build_audit_retention(0, 0, None, 365);
        assert_eq!(r.status, AuditRetentionStatus::Empty);
        assert_eq!(r.total_entries, 0);
        assert_eq!(r.within_retention, 0);
        assert_eq!(r.oldest_age_days, None);
    }

    #[test]
    fn all_within_window_is_compliant() {
        let r = build_audit_retention(100, 0, Some(10 * 86_400), 365);
        assert_eq!(r.status, AuditRetentionStatus::Compliant);
        assert_eq!(r.within_retention, 100);
        assert_eq!(r.beyond_retention, 0);
        assert_eq!(r.oldest_age_days, Some(10));
    }

    #[test]
    fn some_beyond_window_recommends_archival() {
        let r = build_audit_retention(100, 30, Some(400 * 86_400), 365);
        assert_eq!(r.status, AuditRetentionStatus::ArchivalRecommended);
        assert_eq!(r.within_retention, 70);
        assert_eq!(r.beyond_retention, 30);
        assert_eq!(r.oldest_age_days, Some(400));
    }

    #[test]
    fn beyond_is_clamped_to_total() {
        // A nonsense beyond > total must never make `within` negative.
        let r = build_audit_retention(10, 999, Some(0), 30);
        assert_eq!(r.beyond_retention, 10);
        assert_eq!(r.within_retention, 0);
    }

    #[test]
    fn nonempty_log_always_has_an_age_never_contradictory() {
        // The guaranteed invariant: total > 0 ⇒ oldest_age_days is Some, even if
        // the age input is missing (degrades to 0, never a contradictory None).
        let r = build_audit_retention(5, 0, None, 365);
        assert_eq!(r.status, AuditRetentionStatus::Compliant);
        assert_eq!(r.oldest_age_days, Some(0));
        // And the empty log is the only case with a None age.
        let empty = build_audit_retention(0, 0, Some(999 * 86_400), 365);
        assert_eq!(
            empty.oldest_age_days, None,
            "empty log never carries an age"
        );
    }

    #[test]
    fn negative_inputs_are_normalised() {
        let r = build_audit_retention(-5, -3, Some(-100), 30);
        assert_eq!(r.total_entries, 0);
        assert_eq!(r.beyond_retention, 0);
        assert_eq!(r.status, AuditRetentionStatus::Empty);
        assert_eq!(r.oldest_age_days, None);
    }
}
