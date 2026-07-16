use crate::site_registry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GMSAStatus {
    Active,
    Expiring,
    Expired,
    Revoked,
}

impl std::fmt::Display for GMSAStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GMSAStatus::Active => write!(f, "Active"),
            GMSAStatus::Expiring => write!(f, "Expiring"),
            GMSAStatus::Expired => write!(f, "Expired"),
            GMSAStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GMSAAccount {
    pub id: String,
    pub name: String,
    pub sam_account_name: String,
    pub dns_host_name: String,
    pub service_principal_names: Vec<String>,
    pub authorized_hosts: Vec<String>,
    pub site: String,
    pub status: GMSAStatus,
    pub managed_password_interval_days: u32,
    pub created_at: String,
    pub last_rotation_at: String,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn active_site_code(site: &str) -> Result<String, String> {
    let code = site_registry::normalize_site_code_for_lookup(site)
        .map_err(|_| format!("Unknown or empty site: {site}"))?;
    if site_registry::is_valid_site(&code) {
        Ok(code)
    } else {
        Err(format!("Unknown or empty site: {site}"))
    }
}

fn canonical_purpose(value: &str) -> bool {
    !value.is_empty()
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// Resolve the owner of a global gMSA name from the complete governed site
/// namespace. Longest-suffix selection prevents a short code from claiming a
/// name owned by a hyphenated longer code; inactive codes remain reserved.
fn gmsa_name_owner_site(name: &str) -> Result<String, String> {
    if !name.is_ascii() || name != name.to_ascii_lowercase() || name.trim() != name {
        return Err("gMSA name must be canonical lowercase ASCII".into());
    }
    if !name.starts_with("svc-") {
        return Err("gMSA name must start with 'svc-'".into());
    }

    let mut candidates: Vec<(usize, String)> = site_registry::get_known_site_codes()
        .map_err(|_| "Site namespace registry is unavailable".to_string())?
        .into_iter()
        .filter_map(|site| {
            let token = site.to_ascii_lowercase();
            let suffix = format!("-{token}");
            let purpose = name.strip_suffix(&suffix)?.strip_prefix("svc-")?;
            canonical_purpose(purpose).then_some((token.len(), site))
        })
        .collect();
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let owner = candidates
        .first()
        .map(|(_, site)| site.clone())
        .ok_or_else(|| "gMSA name does not end in a governed site namespace".to_string())?;
    if !site_registry::is_valid_site(&owner) {
        return Err(format!("gMSA name owner site '{owner}' is not active"));
    }
    Ok(owner)
}

fn require_site_bound_name(name: &str, canonical_site: &str) -> Result<(), String> {
    let owner_site = gmsa_name_owner_site(name)?;
    if owner_site != canonical_site {
        return Err(format!(
            "gMSA name namespace belongs to site '{owner_site}', not declared site '{canonical_site}'"
        ));
    }
    Ok(())
}

/// Create a new gMSA account in memory (pure — no store). The caller is
/// responsible for persisting the returned record. A fresh UUID is minted
/// on each call.
pub fn create_gmsa(
    name: &str,
    hosts: Vec<String>,
    spns: Vec<String>,
    site: &str,
) -> Result<GMSAAccount, String> {
    if name.is_empty() {
        return Err("gMSA name cannot be empty".into());
    }
    if hosts.is_empty() {
        return Err("At least one authorized host is required".into());
    }
    if site.trim().is_empty() {
        return Err("Site cannot be empty".into());
    }
    let canonical_site = active_site_code(site)?;
    require_site_bound_name(name, &canonical_site)?;
    if spns.is_empty() {
        return Err("At least one SPN is required".into());
    }

    Ok(GMSAAccount {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        sam_account_name: format!("{name}$"),
        dns_host_name: format!("{name}.corp.local"),
        service_principal_names: spns,
        authorized_hosts: hosts,
        site: canonical_site,
        status: GMSAStatus::Active,
        managed_password_interval_days: 30,
        created_at: now_iso(),
        last_rotation_at: now_iso(),
    })
}

/// Validate a gMSA name for naming-convention compliance (pure — no store
/// lookup). The naming check is always applied; in-DB cross-reference
/// validation (SPN present, host assigned) is the responsibility of the
/// caller after loading the record from the repo.
pub fn validate_gmsa(name: &str) -> Result<crate::models::ValidationResult, String> {
    if name.is_empty() {
        return Err("gMSA name cannot be empty".into());
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if let Err(error) = gmsa_name_owner_site(name) {
        errors.push(error);
        failed_rules.push("gmsa-canonical-site-namespace".into());
        remediation.push(
            "Use canonical lowercase format svc-PURPOSE-SITE with a governed active site suffix"
                .into(),
        );
    }

    warnings.push("DRY-RUN: No live AD gMSA validation performed".into());
    warnings.push("DRY-RUN: KDS root key readiness not verified".into());

    Ok(crate::models::ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

/// Add `host` to the account's authorized_hosts list. Returns a clone with
/// the host appended; a no-op (returns the same clone) if the host is already
/// present — idempotent to match the `ON CONFLICT DO NOTHING` repo behaviour.
///
/// Guards: revoked accounts cannot have hosts assigned.
pub fn assign_to_host(account: &GMSAAccount, host: &str) -> Result<GMSAAccount, String> {
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    if account.status == GMSAStatus::Revoked {
        return Err(format!(
            "Cannot assign hosts to revoked gMSA {}",
            account.name
        ));
    }

    let mut updated = account.clone();
    if !updated.authorized_hosts.contains(&host.to_string()) {
        updated.authorized_hosts.push(host.to_string());
    }

    Ok(updated)
}

/// Remove `host` from the account's authorized_hosts list. Returns a clone
/// with the host removed.
///
/// Guards: host must be present in the list; at least one host must remain
/// after removal.
pub fn remove_from_host(account: &GMSAAccount, host: &str) -> Result<GMSAAccount, String> {
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    if !account.authorized_hosts.contains(&host.to_string()) {
        return Err(format!(
            "Host {host} is not in the authorized list for {}",
            account.name
        ));
    }

    let remaining: Vec<String> = account
        .authorized_hosts
        .iter()
        .filter(|h| *h != host)
        .cloned()
        .collect();

    if remaining.is_empty() {
        return Err(format!(
            "Cannot remove last host from {}. At least one authorized host required.",
            account.name
        ));
    }

    let mut updated = account.clone();
    updated.authorized_hosts = remaining;
    Ok(updated)
}

/// Rotate the managed password: sets `last_rotation_at` to now and status to
/// Active. Returns a clone with the updated fields.
///
/// Guard: revoked accounts cannot have their password rotated.
pub fn rotate_password(account: &GMSAAccount) -> Result<GMSAAccount, String> {
    if account.status == GMSAStatus::Revoked {
        return Err(format!(
            "Cannot rotate password for revoked gMSA {}",
            account.name
        ));
    }

    let mut updated = account.clone();
    updated.last_rotation_at = now_iso();
    updated.status = GMSAStatus::Active;
    Ok(updated)
}

/// Verify that `host` is authorized to retrieve the managed password. Returns
/// a clone of the account (read-only — no mutations).
///
/// Guards: revoked accounts and unauthorized hosts are both rejected.
pub fn test_retrieval(account: &GMSAAccount, host: &str) -> Result<GMSAAccount, String> {
    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    if account.status == GMSAStatus::Revoked {
        return Err(format!(
            "Cannot test retrieval for revoked gMSA {}",
            account.name
        ));
    }

    if !account.authorized_hosts.contains(&host.to_string()) {
        return Err(format!(
            "Host {host} is not authorized to retrieve password for {}",
            account.name
        ));
    }

    Ok(account.clone())
}

/// Filter a slice of accounts to those that are expiring or expired, or whose
/// next rotation falls within 7 days. Pure over the provided slice — no I/O.
pub fn get_expiring(accounts: &[GMSAAccount]) -> Vec<GMSAAccount> {
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(7);
    accounts
        .iter()
        .filter(|a| {
            if a.status == GMSAStatus::Expiring || a.status == GMSAStatus::Expired {
                return true;
            }
            if let Ok(last_rotation) = chrono::DateTime::parse_from_rfc3339(&a.last_rotation_at) {
                let rotation = last_rotation.with_timezone(&chrono::Utc);
                let next_rotation =
                    rotation + chrono::Duration::days(a.managed_password_interval_days as i64);
                next_rotation <= threshold
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

/// Where a gMSA's managed-password rotation deadline (`last_rotation_at +
/// managed_password_interval_days`) sits relative to "now". The pure, clock-free
/// mirror of [`CertificateExpiry`](crate::certificate_lifecycle::CertificateExpiry)
/// used by the durable `gmsa_expiry_scan` so the decision is deterministic and the
/// CP clock is the single "now" passed in explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmsaExpiry {
    /// The rotation deadline is in the past — the managed password is overdue to
    /// rotate (stale CP telemetry, or AD-side auto-rotation is not happening).
    Overdue,
    /// Within the soon-window of the rotation deadline — verify before it lapses.
    DueSoon,
    /// Not yet within the window — not actionable.
    Current,
}

impl GmsaExpiry {
    /// Only `Overdue` / `DueSoon` become queue work. Used as the post-SQL
    /// clock-skew guard (the scan re-checks with the CP clock).
    pub fn is_actionable(&self) -> bool {
        matches!(self, GmsaExpiry::Overdue | GmsaExpiry::DueSoon)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            GmsaExpiry::Overdue => "overdue",
            GmsaExpiry::DueSoon => "due-soon",
            GmsaExpiry::Current => "current",
        }
    }
}

/// Classify a gMSA rotation deadline against an explicit `now` and soon-window
/// (all unix-ms). `Overdue` once `now` reaches/passes the deadline; `DueSoon` once
/// the deadline is within `soon_window_ms`; else `Current`. Pure — no clock access.
pub fn classify_gmsa_expiry(
    next_rotation_unix_ms: i64,
    now_unix_ms: i64,
    soon_window_ms: i64,
) -> GmsaExpiry {
    if next_rotation_unix_ms <= now_unix_ms {
        GmsaExpiry::Overdue
    } else if next_rotation_unix_ms <= now_unix_ms.saturating_add(soon_window_ms) {
        GmsaExpiry::DueSoon
    } else {
        GmsaExpiry::Current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(status: GMSAStatus, hosts: Vec<String>) -> GMSAAccount {
        GMSAAccount {
            id: Uuid::new_v4().to_string(),
            name: "svc-testapp-gblon".into(),
            sam_account_name: "svc-testapp-gblon$".into(),
            dns_host_name: "svc-testapp-gblon.corp.local".into(),
            service_principal_names: vec!["HTTP/test.corp.local".into()],
            authorized_hosts: hosts,
            site: "GBLON".into(),
            status,
            managed_password_interval_days: 30,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_rotation_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ─── create_gmsa ────────────────────────────────────────────────────────────

    #[test]
    fn test_create_gmsa_succeeds() {
        let account = create_gmsa(
            "svc-testapp-gblon",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "GBLON",
        );
        assert!(account.is_ok());
        let record = account.unwrap();
        assert_eq!(record.name, "svc-testapp-gblon");
        assert_eq!(record.sam_account_name, "svc-testapp-gblon$");
        assert_eq!(record.dns_host_name, "svc-testapp-gblon.corp.local");
        assert_eq!(record.status, GMSAStatus::Active);
        assert_eq!(record.site, "GBLON");
        assert_eq!(record.authorized_hosts.len(), 1);
    }

    #[test]
    fn test_create_gmsa_invalid_name() {
        let result = create_gmsa(
            "bad-name",
            vec!["host.corp.local".into()],
            vec!["HTTP/host.corp.local".into()],
            "GBLON",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_gmsa_empty_hosts() {
        let result = create_gmsa(
            "svc-testapp-gblon",
            vec![],
            vec!["HTTP/host.corp.local".into()],
            "GBLON",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_gmsa_rejects_foreign_site_suffix() {
        let error = create_gmsa(
            "svc-testapp-defra",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "GBLON",
        )
        .expect_err("a declared site must not claim another site's global gMSA name");

        assert!(error.contains("belongs to site 'DEFRA'"));
    }

    #[test]
    fn test_create_gmsa_canonicalizes_declared_site_and_requires_canonical_suffix() {
        let account = create_gmsa(
            "svc-testapp-gblon",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "gb lon",
        )
        .expect("a supported display-form alias should resolve to the registered active site");
        assert_eq!(account.site, "GBLON");

        let error = create_gmsa(
            "svc-testapp-GBLON",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "GBLON",
        )
        .expect_err("the globally unique name must use the canonical lowercase suffix");
        assert!(error.contains("canonical lowercase ASCII"));
    }

    #[test]
    fn test_create_gmsa_uses_longest_governed_namespace_suffix() {
        for site in ["ZZ", "LAB-ZZ"] {
            site_registry::upsert_site(
                site_registry::SiteEntry {
                    unlocode: site.into(),
                    name: format!("{site} synthetic namespace site"),
                    country: "Test country".into(),
                    country_code: "ZZ".into(),
                    timezone: "UTC".into(),
                    active: true,
                },
                site_registry::SiteCodeSystem::Custom,
            )
            .unwrap();
        }

        let error = create_gmsa(
            "svc-purpose-lab-zz",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "ZZ",
        )
        .expect_err("the shorter suffix must not claim a longer site's namespace");
        assert!(error.contains("belongs to site 'LAB-ZZ'"));

        let account = create_gmsa(
            "svc-purpose-lab-zz",
            vec!["test01.corp.local".into()],
            vec!["HTTP/test01.corp.local".into()],
            "LAB-ZZ",
        )
        .expect("the longest authoritative site suffix owns the name");
        assert_eq!(account.site, "LAB-ZZ");
    }

    #[test]
    fn test_create_gmsa_rejects_ambiguous_or_noncanonical_name_forms() {
        for name in [
            "svc--gblon",
            "svc-purpose--gblon",
            "svc-purpose_gblon",
            "svc-purpose-gblon ",
            "svc-purpøse-gblon",
            "svc-purpose-GBLON",
            "svc-purpose-demuc",
        ] {
            assert!(
                create_gmsa(
                    name,
                    vec!["test01.corp.local".into()],
                    vec!["HTTP/test01.corp.local".into()],
                    "GBLON",
                )
                .is_err(),
                "noncanonical name must fail closed: {name}"
            );
        }
    }

    // ─── validate_gmsa ──────────────────────────────────────────────────────────

    #[test]
    fn test_validate_gmsa_valid_name() {
        let result = validate_gmsa("svc-webappool-gblon").unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_gmsa_invalid_prefix() {
        let result = validate_gmsa("bad-webappool-gblon").unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("svc-")));
    }

    // ─── assign_to_host ─────────────────────────────────────────────────────────

    #[test]
    fn test_assign_to_host_succeeds() {
        let account = make_account(GMSAStatus::Active, vec!["host1.corp.local".into()]);
        let result = assign_to_host(&account, "host2.corp.local");
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert!(
            updated
                .authorized_hosts
                .contains(&"host2.corp.local".to_string())
        );
        assert_eq!(updated.authorized_hosts.len(), 2);
    }

    #[test]
    fn test_assign_already_present_is_idempotent() {
        let account = make_account(GMSAStatus::Active, vec!["host1.corp.local".into()]);
        let result = assign_to_host(&account, "host1.corp.local");
        assert!(result.is_ok());
        // No duplicate added.
        assert_eq!(result.unwrap().authorized_hosts.len(), 1);
    }

    #[test]
    fn test_assign_revoked_fails() {
        let account = make_account(GMSAStatus::Revoked, vec!["host1.corp.local".into()]);
        let result = assign_to_host(&account, "host2.corp.local");
        assert!(result.is_err());
    }

    // ─── remove_from_host ───────────────────────────────────────────────────────

    #[test]
    fn test_remove_from_host_succeeds() {
        let account = make_account(
            GMSAStatus::Active,
            vec!["host1.corp.local".into(), "host2.corp.local".into()],
        );
        let result = remove_from_host(&account, "host1.corp.local");
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert!(
            !updated
                .authorized_hosts
                .contains(&"host1.corp.local".to_string())
        );
        assert_eq!(updated.authorized_hosts.len(), 1);
    }

    #[test]
    fn test_remove_last_host_fails() {
        let account = make_account(GMSAStatus::Active, vec!["host1.corp.local".into()]);
        let result = remove_from_host(&account, "host1.corp.local");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("last host"),
            "expected last-host error, got: {msg}"
        );
    }

    #[test]
    fn test_remove_not_present_fails() {
        let account = make_account(GMSAStatus::Active, vec!["host1.corp.local".into()]);
        let result = remove_from_host(&account, "absent.corp.local");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not in the authorized list"),
            "expected not-in-list error, got: {msg}"
        );
    }

    // ─── rotate_password ────────────────────────────────────────────────────────

    #[test]
    fn test_rotate_password_succeeds() {
        let account = make_account(GMSAStatus::Expiring, vec!["host1.corp.local".into()]);
        let result = rotate_password(&account);
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.status, GMSAStatus::Active);
    }

    #[test]
    fn test_rotate_revoked_fails() {
        let account = make_account(GMSAStatus::Revoked, vec!["host1.corp.local".into()]);
        let result = rotate_password(&account);
        assert!(result.is_err());
    }

    // ─── test_retrieval ─────────────────────────────────────────────────────────

    #[test]
    fn test_test_retrieval_succeeds() {
        let account = make_account(GMSAStatus::Active, vec!["host1.corp.local".into()]);
        let result = test_retrieval(&account, "host1.corp.local");
        assert!(result.is_ok());
    }

    #[test]
    fn test_test_retrieval_unauthorized_host() {
        let account = make_account(GMSAStatus::Active, vec!["host1.corp.local".into()]);
        let result = test_retrieval(&account, "evil-host.corp.local");
        assert!(result.is_err());
    }

    #[test]
    fn test_test_retrieval_revoked_fails() {
        let account = make_account(GMSAStatus::Revoked, vec!["host1.corp.local".into()]);
        let result = test_retrieval(&account, "host1.corp.local");
        assert!(result.is_err());
    }

    // ─── get_expiring ───────────────────────────────────────────────────────────

    #[test]
    fn test_get_expiring_finds_expiring_status() {
        let accounts = vec![
            make_account(GMSAStatus::Active, vec!["h.local".into()]),
            make_account(GMSAStatus::Expiring, vec!["h.local".into()]),
            make_account(GMSAStatus::Expired, vec!["h.local".into()]),
        ];
        let expiring = get_expiring(&accounts);
        assert!(expiring.len() >= 2);
        let has_expiring = expiring
            .iter()
            .any(|a| a.status == GMSAStatus::Expiring || a.status == GMSAStatus::Expired);
        assert!(has_expiring);
    }

    // ─── GMSAStatus Display ─────────────────────────────────────────────────────

    #[test]
    fn test_gmsa_status_display() {
        assert_eq!(GMSAStatus::Active.to_string(), "Active");
        assert_eq!(GMSAStatus::Expiring.to_string(), "Expiring");
        assert_eq!(GMSAStatus::Expired.to_string(), "Expired");
        assert_eq!(GMSAStatus::Revoked.to_string(), "Revoked");
    }

    // ─── classify_gmsa_expiry ───────────────────────────────────────────────────

    #[test]
    fn classify_gmsa_expiry_boundaries() {
        let now = 1_000_000_000_000;
        let window = 7 * 86_400_000; // 7 days in ms

        // Deadline in the past → Overdue.
        assert_eq!(
            classify_gmsa_expiry(now - 1, now, window),
            GmsaExpiry::Overdue
        );
        // Deadline exactly at now → Overdue (<=).
        assert_eq!(classify_gmsa_expiry(now, now, window), GmsaExpiry::Overdue);
        // Within the window → DueSoon.
        assert_eq!(
            classify_gmsa_expiry(now + window - 1, now, window),
            GmsaExpiry::DueSoon
        );
        // Exactly at now + window → DueSoon (<=).
        assert_eq!(
            classify_gmsa_expiry(now + window, now, window),
            GmsaExpiry::DueSoon
        );
        // Beyond the window → Current.
        assert_eq!(
            classify_gmsa_expiry(now + window + 1, now, window),
            GmsaExpiry::Current
        );
    }

    #[test]
    fn gmsa_expiry_actionability_and_labels() {
        assert!(GmsaExpiry::Overdue.is_actionable());
        assert!(GmsaExpiry::DueSoon.is_actionable());
        assert!(!GmsaExpiry::Current.is_actionable());
        assert_eq!(GmsaExpiry::Overdue.as_str(), "overdue");
        assert_eq!(GmsaExpiry::DueSoon.as_str(), "due-soon");
        assert_eq!(GmsaExpiry::Current.as_str(), "current");
    }
}
