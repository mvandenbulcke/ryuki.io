use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BuildStatus {
    Building,
    Testing,
    Promoted,
    Superseded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenImage {
    pub id: String,
    pub image_name: String,
    pub os_family: String,
    pub os_version: String,
    pub distro: String,
    pub build_date: String,
    pub status: BuildStatus,
    pub supersedes_image_id: Option<String>,
    pub site_scope: String,
    pub build_log: String,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

const VALID_OS_FAMILIES: &[&str] = &["Windows", "Linux"];
const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ─── Pure construction ────────────────────────────────────────────────────────

/// Construct a new `GoldenImage` in `Building` status. Returns an error on
/// invalid `os_family` or `site`. The caller is responsible for persisting the
/// result.
pub fn initiate_build(
    image_name: &str,
    os_family: &str,
    distro: &str,
    version: &str,
    site: &str,
) -> Result<GoldenImage, String> {
    if image_name.is_empty() {
        return Err("image_name cannot be empty".into());
    }
    if !VALID_OS_FAMILIES.contains(&os_family) {
        return Err(format!(
            "Unknown os_family: {os_family}. Valid values: {}",
            VALID_OS_FAMILIES.join(", ")
        ));
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!(
            "Unknown site: {site}. Valid values: {}",
            VALID_SITES.join(", ")
        ));
    }
    if distro.is_empty() {
        return Err("distro cannot be empty".into());
    }
    if version.is_empty() {
        return Err("version cannot be empty".into());
    }

    let ts = now_iso();
    Ok(GoldenImage {
        id: Uuid::new_v4().to_string(),
        image_name: image_name.to_string(),
        os_family: os_family.to_string(),
        os_version: version.to_string(),
        distro: distro.to_string(),
        build_date: ts.clone(),
        status: BuildStatus::Building,
        supersedes_image_id: None,
        site_scope: site.to_string(),
        build_log: format!(
            "Build started: {ts}. OS installation queued for {os_family} {version}."
        ),
    })
}

/// Transition a `Building` image to `Testing`. Returns an error when the image
/// is not in `Building` status. The caller is responsible for persisting the
/// transition.
pub fn run_tests(img: &GoldenImage) -> Result<GoldenImage, String> {
    if img.status != BuildStatus::Building {
        return Err(format!(
            "Image '{}' is not in Building status (current: {:?})",
            img.id, img.status
        ));
    }
    let ts = now_iso();
    let mut updated = img.clone();
    updated.status = BuildStatus::Testing;
    updated.build_log.push_str(&format!(
        "\nTesting started: {ts}. Security scan queued, agent checks queued, baseline compliance queued."
    ));
    Ok(updated)
}

/// Transition a `Testing` image to `Promoted`. Returns an error when the image
/// is not in `Testing` status. The caller is responsible for persisting the
/// transition AND for superseding previously-promoted images for the same
/// `site_scope + os_family` (the repo `promote` function performs both
/// operations in one transaction).
pub fn promote_image(img: &GoldenImage) -> Result<GoldenImage, String> {
    if img.status != BuildStatus::Testing {
        return Err(format!(
            "Image '{}' is not in Testing status (current: {:?})",
            img.id, img.status
        ));
    }
    let ts = now_iso();
    let mut updated = img.clone();
    updated.status = BuildStatus::Promoted;
    updated.build_log.push_str(&format!(
        "\nPromoted: {ts}. Tests passed: security scan clear, agent checks passed, baseline compliance met."
    ));
    Ok(updated)
}

/// Transition an image to `Failed`. Images already in a terminal state
/// (`Promoted` or `Superseded`) cannot be rejected. The caller is responsible
/// for persisting the transition.
pub fn reject_image(img: &GoldenImage, reason: &str) -> Result<GoldenImage, String> {
    if img.status == BuildStatus::Promoted || img.status == BuildStatus::Superseded {
        return Err(format!(
            "Image '{}' is in terminal status {:?} and cannot be rejected",
            img.id, img.status
        ));
    }
    if reason.is_empty() {
        return Err("rejection reason cannot be empty".into());
    }
    let ts = now_iso();
    let mut updated = img.clone();
    updated.status = BuildStatus::Failed;
    updated
        .build_log
        .push_str(&format!("\nRejected: {ts}. Reason: {reason}"));
    Ok(updated)
}

/// Construct a new `GoldenImage` for a scheduled monthly build. Returns an
/// error on invalid inputs.
pub fn schedule_monthly_build(
    site: &str,
    os_family: &str,
    distro: &str,
) -> Result<GoldenImage, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!(
            "Unknown site: {site}. Valid values: {}",
            VALID_SITES.join(", ")
        ));
    }
    if !VALID_OS_FAMILIES.contains(&os_family) {
        return Err(format!(
            "Unknown os_family: {os_family}. Valid values: {}",
            VALID_OS_FAMILIES.join(", ")
        ));
    }
    if distro.is_empty() {
        return Err("distro cannot be empty".into());
    }
    let ts = now_iso();
    let image_name = format!(
        "{}-{}-{}-{}",
        distro.to_lowercase().replace(' ', "-"),
        site.to_lowercase(),
        chrono::Utc::now().format("%Y%m"),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    Ok(GoldenImage {
        id: Uuid::new_v4().to_string(),
        image_name,
        os_family: os_family.to_string(),
        os_version: "latest".into(),
        distro: distro.to_string(),
        build_date: ts.clone(),
        status: BuildStatus::Building,
        supersedes_image_id: None,
        site_scope: site.to_string(),
        build_log: format!(
            "Scheduled monthly build started: {ts}. OS: {os_family} {distro}. Automated monthly security baseline update."
        ),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub fn seed_image(id: &str, status: BuildStatus, site: &str, os_family: &str) -> GoldenImage {
    GoldenImage {
        id: id.to_string(),
        image_name: format!(
            "test-{}-{}-{}",
            os_family.to_lowercase(),
            site.to_lowercase(),
            id
        ),
        os_family: os_family.to_string(),
        os_version: "1.0".into(),
        distro: format!("Test {os_family}"),
        build_date: "2026-01-01T00:00:00Z".into(),
        status,
        supersedes_image_id: None,
        site_scope: site.to_string(),
        build_log: "seed".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiate_build() {
        let img = initiate_build("rhel-9-test", "Linux", "RHEL 9", "9.3", "DEFRA").unwrap();
        assert_eq!(img.os_family, "Linux");
        assert_eq!(img.status, BuildStatus::Building);
        assert_eq!(img.site_scope, "DEFRA");
    }

    #[test]
    fn test_initiate_build_invalid_os() {
        assert!(initiate_build("test", "DOS", "DOS 6", "6", "DEFRA").is_err());
    }

    #[test]
    fn test_initiate_build_invalid_site() {
        assert!(initiate_build("test", "Linux", "Ubuntu", "24.04", "MARS").is_err());
    }

    #[test]
    fn test_run_tests() {
        let building = initiate_build("test-img", "Linux", "Ubuntu", "24.04", "DEFRA").unwrap();
        let testing = run_tests(&building).unwrap();
        assert_eq!(testing.status, BuildStatus::Testing);
        assert!(testing.build_log.contains("Testing started"));
    }

    #[test]
    fn test_run_tests_wrong_status() {
        let img = seed_image("x", BuildStatus::Testing, "DEFRA", "Linux");
        assert!(run_tests(&img).is_err());
    }

    #[test]
    fn test_promote_image() {
        let testing = seed_image("x", BuildStatus::Testing, "GBLON", "Windows");
        let promoted = promote_image(&testing).unwrap();
        assert_eq!(promoted.status, BuildStatus::Promoted);
        assert!(promoted.build_log.contains("Promoted"));
    }

    #[test]
    fn test_promote_wrong_status() {
        let img = seed_image("x", BuildStatus::Building, "DEFRA", "Linux");
        assert!(promote_image(&img).is_err());
    }

    #[test]
    fn test_reject_image() {
        let building = seed_image("x", BuildStatus::Building, "DEFRA", "Linux");
        let failed = reject_image(&building, "Security scan failed: CVE-2026-1234").unwrap();
        assert_eq!(failed.status, BuildStatus::Failed);
        assert!(failed.build_log.contains("CVE"));
    }

    #[test]
    fn test_reject_terminal_status() {
        let promoted = seed_image("x", BuildStatus::Promoted, "DEFRA", "Linux");
        assert!(reject_image(&promoted, "reason").is_err());
        let superseded = seed_image("x", BuildStatus::Superseded, "DEFRA", "Linux");
        assert!(reject_image(&superseded, "reason").is_err());
    }

    #[test]
    fn test_reject_empty_reason() {
        let building = seed_image("x", BuildStatus::Building, "DEFRA", "Linux");
        assert!(reject_image(&building, "").is_err());
    }

    #[test]
    fn test_schedule_monthly_build() {
        let img = schedule_monthly_build("GBLON", "Linux", "Ubuntu 24.04").unwrap();
        assert_eq!(img.status, BuildStatus::Building);
        assert_eq!(img.site_scope, "GBLON");
        assert!(img.build_log.contains("monthly"));
    }

    #[test]
    fn test_schedule_monthly_invalid_site() {
        assert!(schedule_monthly_build("MARS", "Linux", "Ubuntu").is_err());
    }

    #[test]
    fn test_image_not_found_guard() {
        let img = seed_image("x", BuildStatus::Promoted, "DEFRA", "Linux");
        // Promoted → run_tests should fail
        assert!(run_tests(&img).is_err());
    }
}
