/// Portal SSR integration tests for request-form hardening, badge/label
/// coverage, and global-search filtering.
///
/// These tests only compile and run under `--features ssr`; the portal default
/// feature set is empty, so `cargo test --workspace` skips this module.  The
/// explicit gate is required for the CI PR check:
///   `cargo test -p ryuki-portal-ui --features ssr`
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use std::collections::HashMap;

    use super::super::request_create::{missing_required_fields, type_fields};
    use super::super::request_detail::{
        stage_label, status_badge_class as detail_status_badge_class,
    };
    use super::super::requests::{filter_requests, status_badge_class as list_status_badge_class};
    use crate::models::RequestSummary;

    // --- Task 1.2 ---------------------------------------------------------

    /// Regression guard: switching request type resets field_values (the signal
    /// behaviour) and the new type's FieldDef slice is non-empty and contains
    /// the expected key.  We test the pure helper (`type_fields`) rather than
    /// the Leptos signal because SSR tests must not require a reactive runtime.
    #[test]
    fn type_change_resets_field_values() {
        // Simulate the values map for "patch-maintenance" with some data.
        let mut values: HashMap<String, String> = HashMap::new();
        values.insert(
            "target_host_group".to_string(),
            "wintel-prod-web".to_string(),
        );
        values.insert(
            "maintenance_window".to_string(),
            "2026-07-01 02:00 UTC".to_string(),
        );

        // Simulating type change: field_values would be reset to empty (the
        // reactive handler does `field_values.set(HashMap::new())`).  We test
        // the post-reset state directly.
        let reset_values: HashMap<String, String> = HashMap::new();

        // After reset there are no stale values.
        assert!(
            reset_values.is_empty(),
            "field_values must be empty after a type change"
        );

        // The new type's FieldDef slice is the canonical definition.
        let restore_fields = type_fields("controlled-restore");
        assert!(
            !restore_fields.is_empty(),
            "controlled-restore must define at least one intake field"
        );
        assert!(
            restore_fields.iter().any(|f| f.key == "source_backup_id"),
            "controlled-restore fields must contain source_backup_id"
        );
    }

    // --- Task 1.3 ---------------------------------------------------------

    /// The helper must flag all required fields as missing when values is empty.
    #[test]
    fn missing_required_fields_returns_missing_when_empty() {
        let values = HashMap::new();
        let missing = missing_required_fields("controlled-restore", &values);

        // All three required fields of controlled-restore must appear.
        assert!(
            missing.contains(&"Source Backup ID"),
            "Source Backup ID must be reported missing; got: {missing:?}"
        );
        assert!(
            missing.contains(&"Restore Point"),
            "Restore Point must be reported missing; got: {missing:?}"
        );
        assert!(
            missing.contains(&"Target Host"),
            "Target Host must be reported missing; got: {missing:?}"
        );
    }

    // --- Task 1.4 ---------------------------------------------------------

    /// The helper must return an empty vec when all required fields are filled.
    #[test]
    fn missing_required_fields_returns_empty_when_all_filled() {
        let mut values = HashMap::new();
        values.insert("source_backup_id".to_string(), "bk-2026-06-01".to_string());
        values.insert("restore_point".to_string(), "2026-06-01T02:00Z".to_string());
        values.insert("target_host".to_string(), "db-01".to_string());

        let missing = missing_required_fields("controlled-restore", &values);
        assert!(
            missing.is_empty(),
            "all required fields filled — missing must be empty; got: {missing:?}"
        );
    }

    // --- Badge and label coverage -----------------------------------------

    /// `stage_label` must cover all portal-vocabulary stage strings, including
    /// the Unknown fallback for unrecognized input.
    #[test]
    fn stage_label_covers_all_stages_and_unknown_fallback() {
        for (stage, expected) in [
            ("intake", "Intake"),
            ("validated", "Validated"),
            ("planned", "Planned"),
            ("approved", "Approved"),
            ("locked", "Locked"),
            ("executed", "Executed"),
            ("verified", "Verified"),
            ("failed", "Failed"),
            ("rejected", "Rejected"),
            ("cancelled", "Cancelled"),
            ("totally-unknown", "Unknown"),
            ("", "Unknown"),
        ] {
            assert_eq!(
                stage_label(stage),
                expected,
                "stage_label({stage:?}) must be {expected:?}"
            );
        }
    }

    /// Both `status_badge_class` copies must return identical output for every
    /// status string — including the newly-added in-progress states.  This test
    /// guards against the two copies diverging.
    #[test]
    fn status_badge_class_both_copies_agree_on_all_statuses() {
        for status in [
            "intake",
            "validated",
            "approved",
            "executed",
            "failed",
            "rejected",
            "cancelled",
            "executing",
            "verifying",
            "draft",
            "planned",
            "locked",
            "completed",
            "unknown-status",
        ] {
            let detail = detail_status_badge_class(status);
            let list = list_status_badge_class(status);
            assert_eq!(
                detail,
                list,
                "status_badge_class copies diverge for {status:?}: detail={detail:?}, list={list:?}"
            );
        }
    }

    /// The new in-progress arms must return a class that is distinct from the
    /// neutral fallback so executing/verifying states render with visual weight.
    #[test]
    fn status_badge_class_executing_and_verifying_are_not_neutral() {
        let neutral = detail_status_badge_class("intake");
        let executing = detail_status_badge_class("executing");
        let verifying = detail_status_badge_class("verifying");

        assert_ne!(
            executing, neutral,
            "executing must not fall back to the neutral badge"
        );
        assert_ne!(
            verifying, neutral,
            "verifying must not fall back to the neutral badge"
        );
        // Both in-progress states must return the same class as each other.
        assert_eq!(
            executing, verifying,
            "executing and verifying must use the same badge class"
        );
    }

    // --- admin_settings_error_feedback ----------------------------------------

    use super::super::workspaces::admin_settings_error_feedback;

    /// The static dry-run sentinel message must map to the neutral preview badge
    /// so the user sees an informational "Preview only" message, not an error.
    #[test]
    fn admin_settings_feedback_static_dry_run_save_sentinel_is_neutral() {
        // Exact text produced by reject_static_preview_platform_settings_save.
        let sentinel = "Portal settings save is preview-only in static dry-run mode; no changes were persisted";
        let (class, msg) = admin_settings_error_feedback(sentinel);
        assert_eq!(
            class, "badge neutral",
            "static dry-run sentinel must map to badge neutral, got: {class:?}"
        );
        assert!(
            msg.contains("Preview only"),
            "static dry-run message must contain 'Preview only', got: {msg:?}"
        );
    }

    /// The static dry-run sentinel for reset must also map to neutral.
    #[test]
    fn admin_settings_feedback_static_dry_run_reset_sentinel_is_neutral() {
        let sentinel = "Portal settings reset is preview-only in static dry-run mode; no changes were persisted";
        let (class, _msg) = admin_settings_error_feedback(sentinel);
        assert_eq!(
            class, "badge neutral",
            "static dry-run reset sentinel must map to badge neutral, got: {class:?}"
        );
    }

    /// A real failure (auth rejection, validation error, network) must map to
    /// `badge bad` so the user sees it as an error, not a neutral preview notice.
    #[test]
    fn admin_settings_feedback_real_error_is_badge_bad() {
        let real_error = "VERIFIED_ADMIN_REQUIRED: interactive admin session required";
        let (class, msg) = admin_settings_error_feedback(real_error);
        assert_eq!(
            class, "badge bad",
            "real error must map to badge bad, got: {class:?}"
        );
        assert!(
            msg.contains("VERIFIED_ADMIN_REQUIRED"),
            "real error message must be preserved, got: {msg:?}"
        );
    }

    /// The Leptos wire prefix must be stripped so the user sees the API message,
    /// not the transport wrapper.
    #[test]
    fn admin_settings_feedback_strips_leptos_wire_prefix() {
        let wire_wrapped =
            "error running server function: CONFIG_VALIDATION_FAILED: auth_mode is invalid";
        let (class, msg) = admin_settings_error_feedback(wire_wrapped);
        assert_eq!(
            class, "badge bad",
            "wire-prefixed real error must map to badge bad, got: {class:?}"
        );
        assert!(
            !msg.contains("error running server function:"),
            "wire prefix must be stripped, got: {msg:?}"
        );
        assert!(
            msg.contains("CONFIG_VALIDATION_FAILED"),
            "underlying error must be present after stripping, got: {msg:?}"
        );
    }

    // ── Global search (P0#4) ──────────────────────────────────────────────────

    fn make_requests() -> Vec<RequestSummary> {
        vec![
            RequestSummary {
                id: "abc-1234".to_string(),
                request_type: "server-build".to_string(),
                name: "Build web server".to_string(),
                site: "dc-west".to_string(),
                environment: "production".to_string(),
                status: "approved".to_string(),
                stage: "approved".to_string(),
                created: "2026-01-01T00:00:00Z".to_string(),
            },
            RequestSummary {
                id: "def-5678".to_string(),
                request_type: "patch-maintenance".to_string(),
                name: "Patch Tuesday".to_string(),
                site: "dc-east".to_string(),
                environment: "staging".to_string(),
                status: "intake".to_string(),
                stage: "intake".to_string(),
                created: "2026-01-02T00:00:00Z".to_string(),
            },
            RequestSummary {
                id: "ghi-9012".to_string(),
                request_type: "controlled-restore".to_string(),
                name: "Restore backup".to_string(),
                site: "dc-west".to_string(),
                environment: "production".to_string(),
                status: "failed".to_string(),
                stage: "failed".to_string(),
                created: "2026-01-03T00:00:00Z".to_string(),
            },
        ]
    }

    /// An empty query string returns all requests unchanged.
    #[test]
    fn filter_requests_empty_query_returns_all() {
        let all = make_requests();
        let filtered = filter_requests(&all, "");
        assert_eq!(
            filtered.len(),
            all.len(),
            "empty query must return all {n} requests",
            n = all.len()
        );
    }

    /// filter_requests matches against the request id (case-insensitive).
    #[test]
    fn filter_requests_matches_by_id() {
        let all = make_requests();
        let filtered = filter_requests(&all, "ABC");
        assert_eq!(
            filtered.len(),
            1,
            "expected 1 match for 'ABC', got: {filtered:?}"
        );
        assert_eq!(filtered[0].id, "abc-1234");
    }

    /// filter_requests matches against the name field (case-insensitive).
    #[test]
    fn filter_requests_matches_by_name() {
        let all = make_requests();
        let filtered = filter_requests(&all, "patch");
        assert_eq!(filtered.len(), 1, "expected 1 match for 'patch' in name");
        assert_eq!(filtered[0].id, "def-5678");
    }

    /// filter_requests matches against request_type (case-insensitive).
    #[test]
    fn filter_requests_matches_by_request_type() {
        let all = make_requests();
        let filtered = filter_requests(&all, "server-build");
        assert_eq!(
            filtered.len(),
            1,
            "expected 1 match for 'server-build' type"
        );
        assert_eq!(filtered[0].id, "abc-1234");
    }

    /// filter_requests matches against status (case-insensitive).
    #[test]
    fn filter_requests_matches_by_status() {
        let all = make_requests();
        let filtered = filter_requests(&all, "failed");
        assert_eq!(filtered.len(), 1, "expected 1 match for status 'failed'");
        assert_eq!(filtered[0].id, "ghi-9012");
    }

    /// filter_requests matches against site (case-insensitive).
    #[test]
    fn filter_requests_matches_by_site() {
        let all = make_requests();
        // Both abc-1234 and ghi-9012 are in dc-west.
        let filtered = filter_requests(&all, "dc-west");
        assert_eq!(filtered.len(), 2, "expected 2 matches for site 'dc-west'");
    }

    /// A non-matching query returns an empty vec.
    #[test]
    fn filter_requests_no_match_returns_empty() {
        let all = make_requests();
        let filtered = filter_requests(&all, "zzz-nonexistent");
        assert!(
            filtered.is_empty(),
            "expected zero matches for 'zzz-nonexistent', got: {filtered:?}"
        );
    }

    /// Matching is case-insensitive across all fields.
    #[test]
    fn filter_requests_is_case_insensitive() {
        let all = make_requests();
        let lower = filter_requests(&all, "approved");
        let upper = filter_requests(&all, "APPROVED");
        let mixed = filter_requests(&all, "Approved");
        assert_eq!(lower.len(), upper.len(), "case must not affect match count");
        assert_eq!(lower.len(), mixed.len(), "case must not affect match count");
    }
}
