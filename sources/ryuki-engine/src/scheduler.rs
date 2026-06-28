//! Pure scheduling math for the durable background-job engine.
//!
//! The IO-bearing tick loop, leader election, and persistence live in the API
//! crate (`ryuki-api::scheduler`); this module holds only the pure, totally
//! testable decisions it relies on: interval validation, the due predicate, the
//! next-run computation, and the read-only job-kind classifier that is the
//! safety seam keeping the slice-1 engine from ever executing an unsafe kind.
//!
//! No IO, no clock access — every function takes its inputs (including "now")
//! explicitly so it is deterministic and unit-testable without a database.

use chrono::{DateTime, Duration, Utc};

/// Smallest allowed schedule interval. A floor well above any tick cost keeps a
/// misconfigured schedule from turning the tick loop into a busy-spin.
pub const MIN_INTERVAL_SECS: u64 = 10;

/// Largest allowed schedule interval (one year). Bounds the value so adding it
/// to a timestamp can never overflow the chrono range and a typo cannot park a
/// schedule effectively forever.
pub const MAX_INTERVAL_SECS: u64 = 31_536_000;

/// Validate a proposed schedule interval (seconds). Rejects 0, anything below
/// [`MIN_INTERVAL_SECS`], and anything above [`MAX_INTERVAL_SECS`]. Returns the
/// interval unchanged on success so callers can use it inline.
pub fn validate_interval(interval_secs: u64) -> Result<u64, String> {
    if interval_secs < MIN_INTERVAL_SECS {
        return Err(format!(
            "interval_secs must be at least {MIN_INTERVAL_SECS} (got {interval_secs})"
        ));
    }
    if interval_secs > MAX_INTERVAL_SECS {
        return Err(format!(
            "interval_secs must be at most {MAX_INTERVAL_SECS} (got {interval_secs})"
        ));
    }
    Ok(interval_secs)
}

/// True when a schedule whose next run is `next_run_at` is due at `now`. A
/// schedule is due once `now` has reached or passed its next-run instant.
/// Unparseable timestamps are treated as NOT due — the live tick decides
/// dueness in SQL against the DB clock; this mirrors that for the pure path and
/// fails safe (a corrupt row is skipped, never run early).
pub fn is_due(next_run_at_rfc3339: &str, now_rfc3339: &str) -> bool {
    match (
        DateTime::parse_from_rfc3339(next_run_at_rfc3339),
        DateTime::parse_from_rfc3339(now_rfc3339),
    ) {
        (Ok(next), Ok(now)) => now >= next,
        _ => false,
    }
}

/// The next-run instant after `base`, i.e. `base + interval_secs`, as an RFC3339
/// UTC string. Returns `None` when `base` is unparseable or the interval is out
/// of bounds — the caller then leaves the schedule untouched rather than parking
/// it at a bogus time. The live tick advances `next_run_at` in SQL off the DB
/// clock; this is the pure equivalent for tests and any non-DB path.
pub fn next_run_after(base_rfc3339: &str, interval_secs: u64) -> Option<String> {
    let interval = validate_interval(interval_secs).ok()?;
    let base = DateTime::parse_from_rfc3339(base_rfc3339).ok()?;
    let next = base
        .with_timezone(&Utc)
        .checked_add_signed(Duration::seconds(interval as i64))?;
    Some(next.to_rfc3339())
}

/// Whether a job kind is read-only and therefore safe for the slice-1 engine to
/// execute. The durable scheduler will run ONLY read-only kinds; an unknown or
/// side-effecting kind is refused (recorded as `skipped`, never executed). This
/// is the explicit safety boundary that later slices widen — a live/destructive
/// kind must pass a policy gate (#11) before it is ever added here.
pub fn job_is_read_only(job_kind: &str) -> bool {
    matches!(job_kind, "health_probe")
}

/// Whether a job kind may be run by the durable scheduler. This is the widened
/// safety boundary: it admits the read-only kinds PLUS explicitly enumerated
/// SAFE-INTERNAL-WRITE kinds — ones that persist only to our own tables via pure
/// dry-run engine logic and make NO provider / live / network / destructive call.
///
/// `synthetic_health_run` qualifies: it records simulated probe results
/// (`check_results`) computed by the pure `synthetic_health::run_all_checks`. It is
/// an EXPLICIT allowlist entry, never a category or prefix match — a live or
/// destructive kind must still be added here deliberately, and only behind a real
/// policy gate (#11). Anything not listed is refused (recorded `skipped`).
///
/// `maintain_review_scan` (#39) also qualifies: it flags Operational requests due
/// for a recurring review by recording `request.maintain-review-due` domain events
/// and advancing each request's review-due timestamp — writes only to our own
/// tables, NO provider/live/destructive call.
///
/// `connection_health_sweep` (#19) also qualifies: it lists every integration
/// connection, runs the pure `test_connection_stub` (a DRY-RUN, no provider/live
/// call), and appends a `connection_health_checks` row plus refreshes each
/// connection's `last_test_*` — writes only to our own tables.
pub fn job_is_schedulable(job_kind: &str) -> bool {
    job_is_read_only(job_kind)
        || matches!(
            job_kind,
            "synthetic_health_run" | "maintain_review_scan" | "connection_health_sweep"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_interval_enforces_bounds() {
        assert!(validate_interval(0).is_err(), "zero is rejected");
        assert!(
            validate_interval(MIN_INTERVAL_SECS - 1).is_err(),
            "below floor"
        );
        assert_eq!(validate_interval(MIN_INTERVAL_SECS), Ok(MIN_INTERVAL_SECS));
        assert_eq!(validate_interval(3600), Ok(3600));
        assert_eq!(validate_interval(MAX_INTERVAL_SECS), Ok(MAX_INTERVAL_SECS));
        assert!(
            validate_interval(MAX_INTERVAL_SECS + 1).is_err(),
            "above ceiling"
        );
    }

    #[test]
    fn is_due_when_now_reaches_or_passes_next_run() {
        assert!(
            is_due("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
            "exactly at next-run is due"
        );
        assert!(
            is_due("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00"),
            "past next-run is due"
        );
        assert!(
            !is_due("2026-01-01T00:00:01+00:00", "2026-01-01T00:00:00+00:00"),
            "before next-run is not due"
        );
    }

    #[test]
    fn is_due_fails_safe_on_unparseable_input() {
        assert!(!is_due("not-a-time", "2026-01-01T00:00:00+00:00"));
        assert!(!is_due("2026-01-01T00:00:00+00:00", "not-a-time"));
    }

    #[test]
    fn next_run_after_adds_interval() {
        assert_eq!(
            next_run_after("2026-01-01T00:00:00+00:00", 3600).as_deref(),
            Some("2026-01-01T01:00:00+00:00")
        );
    }

    #[test]
    fn next_run_after_rejects_bad_input() {
        assert_eq!(next_run_after("not-a-time", 3600), None);
        assert_eq!(next_run_after("2026-01-01T00:00:00+00:00", 0), None);
        assert_eq!(
            next_run_after("2026-01-01T00:00:00+00:00", MAX_INTERVAL_SECS + 1),
            None
        );
    }

    #[test]
    fn only_known_read_only_kinds_are_runnable() {
        assert!(job_is_read_only("health_probe"));
        assert!(!job_is_read_only("destroy_everything"));
        assert!(!job_is_read_only("live_apply"));
        assert!(!job_is_read_only(""));
    }

    #[test]
    fn schedulable_admits_read_only_plus_synthetic_health_only() {
        // Read-only kinds remain schedulable.
        assert!(job_is_schedulable("health_probe"));
        // The safe-internal-write kinds are schedulable but are NOT read-only.
        assert!(job_is_schedulable("synthetic_health_run"));
        assert!(!job_is_read_only("synthetic_health_run"));
        assert!(job_is_schedulable("maintain_review_scan"));
        assert!(!job_is_read_only("maintain_review_scan"));
        assert!(job_is_schedulable("connection_health_sweep"));
        assert!(!job_is_read_only("connection_health_sweep"));
        // Nothing else is admitted — no live/destructive kind, no prefix match.
        assert!(!job_is_schedulable("live_apply"));
        assert!(!job_is_schedulable("destroy_everything"));
        assert!(!job_is_schedulable("synthetic_health_run_live"));
        assert!(!job_is_schedulable("maintain_review_scan_live"));
        assert!(!job_is_schedulable("connection_health_sweep_live"));
        assert!(!job_is_schedulable(""));
    }
}
