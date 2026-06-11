use serde::Serialize;
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum BuildStatus {
    Building,
    Testing,
    Promoted,
    Superseded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
struct GoldenImage {
    id: String,
    image_name: String,
    os_family: String,
    os_version: String,
    distro: String,
    build_date: String,
    status: BuildStatus,
    supersedes_image_id: Option<String>,
    site_scope: String,
    build_log: String,
}

type ImageStore = Vec<GoldenImage>;

static IMAGE_STORE: OnceLock<Mutex<ImageStore>> = OnceLock::new();

fn image_store() -> &'static Mutex<ImageStore> {
    IMAGE_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> ImageStore {
    vec![
        GoldenImage {
            id: "img-001".into(),
            image_name: "win-svr-2022-defra-v1".into(),
            os_family: "Windows".into(),
            os_version: "2022".into(),
            distro: "Windows Server 2022 Datacenter".into(),
            build_date: "2026-05-01T06:00:00Z".into(),
            status: BuildStatus::Promoted,
            supersedes_image_id: None,
            site_scope: "DEFRA".into(),
            build_log: "Build completed: 2026-05-01T06:00:00Z. Tests: security scan passed, agent checks passed, baseline compliance passed.".into(),
        },
        GoldenImage {
            id: "img-002".into(),
            image_name: "ubuntu-2404-defra-v1".into(),
            os_family: "Linux".into(),
            os_version: "24.04".into(),
            distro: "Ubuntu 24.04 LTS".into(),
            build_date: "2026-05-02T06:00:00Z".into(),
            status: BuildStatus::Promoted,
            supersedes_image_id: None,
            site_scope: "DEFRA".into(),
            build_log: "Build completed: 2026-05-02T06:00:00Z. Tests: security scan passed, agent checks passed, baseline compliance passed.".into(),
        },
        GoldenImage {
            id: "img-003".into(),
            image_name: "win-svr-2025-gblon-v0".into(),
            os_family: "Windows".into(),
            os_version: "2025".into(),
            distro: "Windows Server 2025 Datacenter".into(),
            build_date: "2026-06-10T08:00:00Z".into(),
            status: BuildStatus::Building,
            supersedes_image_id: None,
            site_scope: "GBLON".into(),
            build_log: "Build started: 2026-06-10T08:00:00Z. Status: OS installation completed, agent installation in progress.".into(),
        },
        GoldenImage {
            id: "img-004".into(),
            image_name: "win-svr-2019-defra-v0".into(),
            os_family: "Windows".into(),
            os_version: "2019".into(),
            distro: "Windows Server 2019 Datacenter".into(),
            build_date: "2026-04-01T06:00:00Z".into(),
            status: BuildStatus::Superseded,
            supersedes_image_id: None,
            site_scope: "DEFRA".into(),
            build_log: "Superseded by img-001 (Windows Server 2022) on 2026-05-01. No further builds scheduled.".into(),
        },
    ]
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn next_id(store: &ImageStore) -> String {
    let max_n = store
        .iter()
        .filter_map(|img| {
            img.id
                .strip_prefix("img-")
                .and_then(|n| n.parse::<u32>().ok())
        })
        .max()
        .unwrap_or(0);
    format!("img-{:03}", max_n + 1)
}

fn image_to_json(img: &GoldenImage) -> Value {
    json!({
        "id": img.id,
        "image_name": img.image_name,
        "os_family": img.os_family,
        "os_version": img.os_version,
        "distro": img.distro,
        "build_date": img.build_date,
        "status": img.status,
        "supersedes_image_id": img.supersedes_image_id,
        "site_scope": img.site_scope,
        "build_log": img.build_log
    })
}

pub fn initiate_build(
    image_name: &str,
    os_family: &str,
    distro: &str,
    version: &str,
    site: &str,
) -> Result<Value, String> {
    let mut store = image_store().lock().map_err(|e| e.to_string())?;
    let id = next_id(&store);
    let img = GoldenImage {
        id,
        image_name: image_name.to_string(),
        os_family: os_family.to_string(),
        os_version: version.to_string(),
        distro: distro.to_string(),
        build_date: now_iso(),
        status: BuildStatus::Building,
        supersedes_image_id: None,
        site_scope: site.to_string(),
        build_log: format!(
            "Build started: {}. OS installation queued for {} {}.",
            now_iso(),
            os_family,
            version
        ),
    };
    let json = image_to_json(&img);
    store.push(img);
    Ok(json!({
        "source": "dry-run",
        "image": json
    }))
}

pub fn run_tests(image_id: &str) -> Result<Value, String> {
    let mut store = image_store().lock().map_err(|e| e.to_string())?;
    let img = store
        .iter_mut()
        .find(|i| i.id == image_id)
        .ok_or_else(|| format!("Image '{}' not found", image_id))?;

    if img.status != BuildStatus::Building {
        return Err(format!(
            "Image '{}' is not in Building status (current: {:?})",
            image_id, img.status
        ));
    }

    img.status = BuildStatus::Testing;
    img.build_log.push_str(&format!(
        "\nTesting started: {}. Security scan queued, agent checks queued, baseline compliance queued.",
        now_iso()
    ));

    Ok(json!({
        "source": "dry-run",
        "image": image_to_json(img),
        "test_phases": ["security-scan", "agent-checks", "baseline-compliance"]
    }))
}

pub fn promote_image(image_id: &str) -> Result<Value, String> {
    let mut store = image_store().lock().map_err(|e| e.to_string())?;

    let current_status = store
        .iter()
        .find(|i| i.id == image_id)
        .map(|i| i.status.clone());
    let current_status = current_status.ok_or_else(|| format!("Image '{}' not found", image_id))?;
    if current_status != BuildStatus::Testing {
        return Err(format!(
            "Image '{}' is not in Testing status (current: {:?})",
            image_id, current_status
        ));
    }

    let (site, os_family) = {
        let img = store.iter().find(|i| i.id == image_id).unwrap();
        (img.site_scope.clone(), img.os_family.clone())
    };

    // Supersede previously promoted images for the same site + os_family
    let mut superseded_ids: Vec<String> = Vec::new();
    for img in store.iter_mut() {
        if img.site_scope == site
            && img.os_family == os_family
            && img.status == BuildStatus::Promoted
        {
            img.status = BuildStatus::Superseded;
            superseded_ids.push(img.id.clone());
        }
    }

    let img = store.iter_mut().find(|i| i.id == image_id).unwrap();
    img.status = BuildStatus::Promoted;
    img.build_log.push_str(&format!(
        "\nPromoted: {}. Tests passed: security scan clear, agent checks passed, baseline compliance met.",
        now_iso()
    ));

    Ok(json!({
        "source": "dry-run",
        "image": image_to_json(img),
        "superseded": superseded_ids
    }))
}

pub fn reject_image(image_id: &str, reason: &str) -> Result<Value, String> {
    let mut store = image_store().lock().map_err(|e| e.to_string())?;
    let img = store
        .iter_mut()
        .find(|i| i.id == image_id)
        .ok_or_else(|| format!("Image '{}' not found", image_id))?;

    if img.status == BuildStatus::Promoted || img.status == BuildStatus::Superseded {
        return Err(format!(
            "Image '{}' is in terminal status {:?} and cannot be rejected",
            image_id, img.status
        ));
    }

    img.status = BuildStatus::Failed;
    img.build_log
        .push_str(&format!("\nRejected: {}. Reason: {}", now_iso(), reason));

    Ok(json!({
        "source": "dry-run",
        "image": image_to_json(img),
        "rejection_reason": reason
    }))
}

pub fn get_active_images(site: &str) -> Result<Value, String> {
    let store = image_store().lock().map_err(|e| e.to_string())?;
    let images: Vec<&GoldenImage> = store
        .iter()
        .filter(|i| i.site_scope == site && i.status == BuildStatus::Promoted)
        .collect();

    if images.is_empty() {
        return Err(format!("No active images found for site '{}'", site));
    }

    let mut by_os: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
    for img in &images {
        by_os
            .entry(img.os_family.clone())
            .or_default()
            .push(image_to_json(img));
    }

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "active_count": images.len(),
        "active_by_os": by_os
    }))
}

pub fn get_build_history(site: &str) -> Result<Value, String> {
    let store = image_store().lock().map_err(|e| e.to_string())?;
    let images: Vec<&GoldenImage> = store.iter().filter(|i| i.site_scope == site).collect();

    if images.is_empty() {
        return Err(format!("No build history found for site '{}'", site));
    }

    let list: Vec<Value> = images.iter().map(|i| image_to_json(i)).collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "build_count": list.len(),
        "builds": list
    }))
}

pub fn get_superseded() -> Result<Value, String> {
    let store = image_store().lock().map_err(|e| e.to_string())?;
    let superseded: Vec<Value> = store
        .iter()
        .filter(|i| i.status == BuildStatus::Superseded)
        .map(image_to_json)
        .collect();

    Ok(json!({
        "source": "dry-run",
        "superseded_count": superseded.len(),
        "images": superseded
    }))
}

pub fn schedule_monthly_build(site: &str, os_family: &str, distro: &str) -> Result<Value, String> {
    let mut store = image_store().lock().map_err(|e| e.to_string())?;
    let id = next_id(&store);
    let image_name = format!(
        "{}-{}-{}-{}",
        distro.to_lowercase().replace(' ', "-"),
        site.to_lowercase(),
        chrono::Utc::now().format("%Y%m"),
        id
    );

    let img = GoldenImage {
        id,
        image_name,
        os_family: os_family.to_string(),
        os_version: "latest".into(),
        distro: distro.to_string(),
        build_date: now_iso(),
        status: BuildStatus::Building,
        supersedes_image_id: None,
        site_scope: site.to_string(),
        build_log: format!(
            "Scheduled monthly build started: {}. OS: {} {}. Automated monthly security baseline update.",
            now_iso(),
            os_family,
            distro
        ),
    };

    let json = image_to_json(&img);
    store.push(img);
    Ok(json!({
        "source": "dry-run",
        "scheduled": true,
        "cadence": "monthly",
        "image": json
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiate_build() {
        let result = initiate_build("rhel-9-test", "Linux", "RHEL 9", "9.3", "DEFRA").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["image"]["os_family"], "Linux");
        assert_eq!(result["image"]["status"], "building");
        assert_eq!(result["image"]["site_scope"], "DEFRA");
    }

    #[test]
    fn test_run_tests() {
        let build = initiate_build("test-img", "Linux", "Ubuntu", "24.04", "DEFRA").unwrap();
        let image_id = build["image"]["id"].as_str().unwrap();
        let result = run_tests(image_id).unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["image"]["status"], "testing");
    }

    #[test]
    fn test_promote_image() {
        let build =
            initiate_build("test-promote", "Windows", "WinSvr2025", "2025", "GBLON").unwrap();
        let image_id = build["image"]["id"].as_str().unwrap();
        run_tests(image_id).unwrap();
        let result = promote_image(image_id).unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["image"]["status"], "promoted");

        // Verify the previously promoted win-svr-2022-defra-v1 is NOT superseded (different site/os)
        let defra_active = get_active_images("DEFRA").unwrap();
        let win_images = defra_active["active_by_os"]["Windows"].as_array().unwrap();
        assert!(win_images.iter().any(|i| i["id"] == "img-001"));
    }

    #[test]
    fn test_promote_supersedes_previous() {
        // img-002 is Ubuntu promoted at DEFRA. Build a new Ubuntu, test, and promote it.
        let build =
            initiate_build("ubuntu-2404-v2", "Linux", "Ubuntu 24.04", "24.04", "DEFRA").unwrap();
        let image_id = build["image"]["id"].as_str().unwrap();
        run_tests(image_id).unwrap();
        let result = promote_image(image_id).unwrap();
        let superseded = result["superseded"].as_array().unwrap();
        assert!(
            !superseded.is_empty(),
            "should supersede the existing Ubuntu image at DEFRA"
        );
        assert!(superseded.iter().any(|s| s.as_str() == Some("img-002")));
    }

    #[test]
    fn test_reject_image() {
        let build = initiate_build("test-reject", "Linux", "Ubuntu", "24.04", "DEFRA").unwrap();
        let image_id = build["image"]["id"].as_str().unwrap();
        let result = reject_image(image_id, "Security scan failed: CVE-2026-1234").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["image"]["status"], "failed");
        assert!(result["rejection_reason"].as_str().unwrap().contains("CVE"));
    }

    #[test]
    fn test_get_active_images() {
        let result = get_active_images("DEFRA").unwrap();
        assert_eq!(result["site"], "DEFRA");
        assert!(result["active_count"].as_u64().unwrap() >= 1);
        let win_images = result["active_by_os"]["Windows"].as_array().unwrap();
        assert!(win_images.iter().any(|i| i["id"] == "img-001"));
    }

    #[test]
    fn test_get_build_history() {
        let result = get_build_history("DEFRA").unwrap();
        assert_eq!(result["site"], "DEFRA");
        assert!(result["build_count"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn test_get_superseded() {
        let result = get_superseded().unwrap();
        assert!(result["superseded_count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_schedule_monthly_build() {
        let result = schedule_monthly_build("GBLON", "Linux", "Ubuntu 24.04").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["scheduled"], true);
        assert_eq!(result["cadence"], "monthly");
        assert_eq!(result["image"]["status"], "building");
    }

    #[test]
    fn test_image_not_found() {
        assert!(run_tests("img-999").is_err());
        assert!(promote_image("img-999").is_err());
        assert!(reject_image("img-999", "test").is_err());
    }

    #[test]
    fn test_site_not_found() {
        assert!(get_active_images("NONEXISTENT").is_err());
        assert!(get_build_history("NONEXISTENT").is_err());
    }
}
