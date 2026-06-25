//! Pure restore-test recency classification (#47).
//!
//! A backup is only PROVEN recoverable by a successful restore test. For each
//! system that HAS restore-request history this classifies how recently its last
//! successful restore (a request that reached `Verified`/`Completed`) ran:
//! `current`, `overdue` (older than the policy window), or `never_tested`
//! (restore was requested but never reached a success state). Pure: the API
//! passes in the last-success timestamp.
//!
//! Scope note: this classifies systems that APPEAR in `restore_requests`. A
//! system that has never had a restore request at all is invisible here — that
//! is a backup-COVERAGE gap (see the coverage reports), a different question
//! from "how stale is the last proven restore". So `never_tested` means
//! "requested but never proven", NOT "no backup at all".

use serde::Serialize;

/// Recency verdict for one system's last successful restore test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreTestRecency {
    /// Last successful restore test is within the policy window.
    Current,
    /// Last successful restore test is older than the policy window.
    Overdue,
    /// Restore was requested but never reached a success state — unproven.
    /// (Does NOT mean "never attempted at all"; see the module scope note.)
    NeverTested,
}

impl RestoreTestRecency {
    pub fn as_str(&self) -> &'static str {
        match self {
            RestoreTestRecency::Current => "current",
            RestoreTestRecency::Overdue => "overdue",
            RestoreTestRecency::NeverTested => "never_tested",
        }
    }

    /// Anything other than `current` is a recovery-assurance risk worth surfacing.
    pub fn is_at_risk(&self) -> bool {
        !matches!(self, RestoreTestRecency::Current)
    }
}

/// Classify recency from the last successful restore-test instant (unix seconds;
/// `None` ⇒ never tested). `overdue_after_secs` is the policy window. A last-test
/// timestamp in the FUTURE (clock skew) is clamped to age 0 ⇒ `current`, never a
/// spurious overdue/negative age.
pub fn classify_restore_recency(
    last_test_unix: Option<i64>,
    now_unix: i64,
    overdue_after_secs: i64,
) -> RestoreTestRecency {
    match last_test_unix {
        None => RestoreTestRecency::NeverTested,
        Some(t) => {
            let age = now_unix.saturating_sub(t).max(0);
            if age > overdue_after_secs {
                RestoreTestRecency::Overdue
            } else {
                RestoreTestRecency::Current
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: i64 = 90 * 86_400; // 90 days

    #[test]
    fn none_is_never_tested() {
        assert_eq!(
            classify_restore_recency(None, 1_000_000, WINDOW),
            RestoreTestRecency::NeverTested
        );
        assert!(RestoreTestRecency::NeverTested.is_at_risk());
    }

    #[test]
    fn recent_is_current() {
        let now = 1_000_000_000;
        let last = now - 10 * 86_400; // 10 days ago
        assert_eq!(
            classify_restore_recency(Some(last), now, WINDOW),
            RestoreTestRecency::Current
        );
        assert!(!RestoreTestRecency::Current.is_at_risk());
    }

    #[test]
    fn old_is_overdue() {
        let now = 1_000_000_000;
        let last = now - 100 * 86_400; // 100 days ago > 90d window
        assert_eq!(
            classify_restore_recency(Some(last), now, WINDOW),
            RestoreTestRecency::Overdue
        );
        assert!(RestoreTestRecency::Overdue.is_at_risk());
    }

    #[test]
    fn boundary_exactly_at_window_is_current() {
        let now = 1_000_000_000;
        let last = now - WINDOW; // age == window, not > window
        assert_eq!(
            classify_restore_recency(Some(last), now, WINDOW),
            RestoreTestRecency::Current
        );
    }

    #[test]
    fn future_timestamp_clamps_to_current() {
        let now = 1_000_000_000;
        let last = now + 5_000; // clock skew: "tested in the future"
        assert_eq!(
            classify_restore_recency(Some(last), now, WINDOW),
            RestoreTestRecency::Current
        );
    }
}
