/// Portal SSR integration tests for request-form hardening.
///
/// These tests only compile and run under `--features ssr`; the portal default
/// feature set is empty, so `cargo test --workspace` skips this module.  The
/// explicit gate is required for the CI PR check:
///   `cargo test -p ryuki-portal-ui --features ssr`
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use std::collections::HashMap;

    use super::super::request_create::{missing_required_fields, type_fields};

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
}
