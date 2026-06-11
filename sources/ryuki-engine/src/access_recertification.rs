use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReviewType {
    ADGroup,
    ServiceAccount,
    LocalAdmin,
    Sudo,
    SharePermission,
}

impl std::fmt::Display for ReviewType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewType::ADGroup => write!(f, "ADGroup"),
            ReviewType::ServiceAccount => write!(f, "ServiceAccount"),
            ReviewType::LocalAdmin => write!(f, "LocalAdmin"),
            ReviewType::Sudo => write!(f, "Sudo"),
            ReviewType::SharePermission => write!(f, "SharePermission"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReviewStatus {
    Pending,
    InProgress,
    Approved,
    Revoked,
    Exempted,
}

impl std::fmt::Display for ReviewStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewStatus::Pending => write!(f, "Pending"),
            ReviewStatus::InProgress => write!(f, "InProgress"),
            ReviewStatus::Approved => write!(f, "Approved"),
            ReviewStatus::Revoked => write!(f, "Revoked"),
            ReviewStatus::Exempted => write!(f, "Exempted"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CampaignStatus {
    Active,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessReview {
    pub id: String,
    pub review_type: ReviewType,
    pub target_name: String,
    pub owner: String,
    pub last_reviewed: String,
    pub next_review_due: String,
    pub status: ReviewStatus,
    pub reviewer: Option<String>,
    pub site: String,
    pub access_details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecertificationCampaign {
    pub id: String,
    pub name: String,
    pub start_date: String,
    pub end_date: String,
    pub review_type: ReviewType,
    pub reviewer_group: String,
    pub reviews_count: usize,
    pub completed_count: usize,
    pub status: CampaignStatus,
}

type AccessStore = (Vec<AccessReview>, Vec<RecertificationCampaign>);

static ACCESS_STORE: OnceLock<Mutex<AccessStore>> = OnceLock::new();

fn store() -> &'static Mutex<AccessStore> {
    ACCESS_STORE.get_or_init(|| Mutex::new((seed_reviews(), seed_campaigns())))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn parse_review_type(value: &str) -> Result<ReviewType, String> {
    match value {
        "ADGroup" => Ok(ReviewType::ADGroup),
        "ServiceAccount" => Ok(ReviewType::ServiceAccount),
        "LocalAdmin" => Ok(ReviewType::LocalAdmin),
        "Sudo" => Ok(ReviewType::Sudo),
        "SharePermission" => Ok(ReviewType::SharePermission),
        other => Err(format!(
            "Invalid review_type: {other}. Must be ADGroup, ServiceAccount, LocalAdmin, Sudo, or SharePermission"
        )),
    }
}

fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn seed_reviews() -> Vec<AccessReview> {
    let now = Utc::now();
    vec![
        AccessReview {
            id: "ar-defra-ad-001".into(),
            review_type: ReviewType::ADGroup,
            target_name: "DEFRA-Infra-Admins".into(),
            owner: "defra.platform.owner".into(),
            last_reviewed: (now - Duration::days(120)).to_rfc3339(),
            next_review_due: (now - Duration::days(30)).to_rfc3339(),
            status: ReviewStatus::Pending,
            reviewer: None,
            site: "DEFRA".into(),
            access_details: vec![
                "Privileged AD group".into(),
                "Domain admin delegation".into(),
            ],
        },
        AccessReview {
            id: "ar-defra-svc-001".into(),
            review_type: ReviewType::ServiceAccount,
            target_name: "svc-defra-backup".into(),
            owner: "backup.platform.owner".into(),
            last_reviewed: (now - Duration::days(88)).to_rfc3339(),
            next_review_due: (now + Duration::days(2)).to_rfc3339(),
            status: ReviewStatus::InProgress,
            reviewer: Some("alice.reviewer".into()),
            site: "DEFRA".into(),
            access_details: vec![
                "Backup API token".into(),
                "Vault policy: backup-read".into(),
            ],
        },
        AccessReview {
            id: "ar-defra-share-001".into(),
            review_type: ReviewType::SharePermission,
            target_name: "\\\\defra-fs-01\\engineering".into(),
            owner: "engineering.owner".into(),
            last_reviewed: (now - Duration::days(10)).to_rfc3339(),
            next_review_due: (now + Duration::days(80)).to_rfc3339(),
            status: ReviewStatus::Approved,
            reviewer: Some("carla.reviewer".into()),
            site: "DEFRA".into(),
            access_details: vec![
                "Read/write share permission".into(),
                "NTFS modify for engineers".into(),
            ],
        },
        AccessReview {
            id: "ar-gblon-admin-001".into(),
            review_type: ReviewType::LocalAdmin,
            target_name: "gblon-hv-01 local Administrators".into(),
            owner: "gblon.compute.owner".into(),
            last_reviewed: (now - Duration::days(180)).to_rfc3339(),
            next_review_due: (now - Duration::days(90)).to_rfc3339(),
            status: ReviewStatus::Pending,
            reviewer: None,
            site: "GBLON".into(),
            access_details: vec![
                "Local admin group".into(),
                "Break-glass workstation access".into(),
            ],
        },
        AccessReview {
            id: "ar-gblon-sudo-001".into(),
            review_type: ReviewType::Sudo,
            target_name: "gblon-linux-sre sudoers".into(),
            owner: "linux.platform.owner".into(),
            last_reviewed: (now - Duration::days(70)).to_rfc3339(),
            next_review_due: (now + Duration::days(20)).to_rfc3339(),
            status: ReviewStatus::Pending,
            reviewer: None,
            site: "GBLON".into(),
            access_details: vec![
                "NOPASSWD deploy commands".into(),
                "Journal read access".into(),
            ],
        },
        AccessReview {
            id: "ar-gblon-svc-001".into(),
            review_type: ReviewType::ServiceAccount,
            target_name: "svc-gblon-monitoring".into(),
            owner: "observability.owner".into(),
            last_reviewed: (now - Duration::days(30)).to_rfc3339(),
            next_review_due: (now + Duration::days(60)).to_rfc3339(),
            status: ReviewStatus::Exempted,
            reviewer: Some("security.exception".into()),
            site: "GBLON".into(),
            access_details: vec![
                "Monitoring read-only credential".into(),
                "Temporary exemption until agent migration".into(),
            ],
        },
        AccessReview {
            id: "ar-deber-ad-001".into(),
            review_type: ReviewType::ADGroup,
            target_name: "DEBER-Storage-Operators".into(),
            owner: "deber.storage.owner".into(),
            last_reviewed: (now - Duration::days(95)).to_rfc3339(),
            next_review_due: (now - Duration::days(5)).to_rfc3339(),
            status: ReviewStatus::InProgress,
            reviewer: Some("diego.reviewer".into()),
            site: "DEBER".into(),
            access_details: vec![
                "Storage console operator".into(),
                "Array snapshot rights".into(),
            ],
        },
        AccessReview {
            id: "ar-deber-sudo-001".into(),
            review_type: ReviewType::Sudo,
            target_name: "deber-db sudoers".into(),
            owner: "database.platform.owner".into(),
            last_reviewed: (now - Duration::days(20)).to_rfc3339(),
            next_review_due: (now + Duration::days(40)).to_rfc3339(),
            status: ReviewStatus::Approved,
            reviewer: Some("db.security".into()),
            site: "DEBER".into(),
            access_details: vec![
                "PostgreSQL service restart".into(),
                "Log collection commands".into(),
            ],
        },
        AccessReview {
            id: "ar-deber-share-001".into(),
            review_type: ReviewType::SharePermission,
            target_name: "\\\\deber-fs-02\\finance".into(),
            owner: "finance.owner".into(),
            last_reviewed: (now - Duration::days(140)).to_rfc3339(),
            next_review_due: (now - Duration::days(50)).to_rfc3339(),
            status: ReviewStatus::Revoked,
            reviewer: Some("finance.security".into()),
            site: "DEBER".into(),
            access_details: vec![
                "Legacy contractor group removed".into(),
                "Access revoked in dry-run evidence".into(),
            ],
        },
    ]
}

fn seed_campaigns() -> Vec<RecertificationCampaign> {
    let now = Utc::now();
    vec![
        RecertificationCampaign {
            id: "arcamp-ad-q2".into(),
            name: "Q2 AD privileged access review".into(),
            start_date: (now - Duration::days(5)).to_rfc3339(),
            end_date: (now + Duration::days(25)).to_rfc3339(),
            review_type: ReviewType::ADGroup,
            reviewer_group: "identity-governance".into(),
            reviews_count: 2,
            completed_count: 0,
            status: CampaignStatus::Active,
        },
        RecertificationCampaign {
            id: "arcamp-sudo-q2".into(),
            name: "Q2 Linux sudo recertification".into(),
            start_date: (now - Duration::days(3)).to_rfc3339(),
            end_date: (now + Duration::days(27)).to_rfc3339(),
            review_type: ReviewType::Sudo,
            reviewer_group: "linux-platform-reviewers".into(),
            reviews_count: 2,
            completed_count: 1,
            status: CampaignStatus::Active,
        },
    ]
}

fn review_response(review: &AccessReview) -> Value {
    json!({
        "source": "dry-run",
        "review": review
    })
}

fn completed_reviews_count(reviews: &[AccessReview], review_type: &ReviewType) -> usize {
    reviews
        .iter()
        .filter(|review| review.review_type == *review_type)
        .filter(|review| {
            matches!(
                review.status,
                ReviewStatus::Approved | ReviewStatus::Revoked | ReviewStatus::Exempted
            )
        })
        .count()
}

pub fn list_reviews(site: &str, review_type: &str) -> Result<Value, String> {
    let parsed_type = if review_type.is_empty() {
        None
    } else {
        Some(parse_review_type(review_type)?)
    };
    let store = store().lock().unwrap();
    let reviews: Vec<AccessReview> = store
        .0
        .iter()
        .filter(|review| site.is_empty() || review.site == site)
        .filter(|review| match &parsed_type {
            Some(review_type) => review.review_type == *review_type,
            None => true,
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": reviews.len(),
        "reviews": reviews
    }))
}

pub fn get_review(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let review = store
        .0
        .iter()
        .find(|review| review.id == id)
        .ok_or_else(|| format!("Access review '{id}' not found"))?;

    Ok(review_response(review))
}

pub fn list_due_reviews() -> Result<Value, String> {
    let now = Utc::now();
    let store = store().lock().unwrap();
    let reviews: Vec<AccessReview> = store
        .0
        .iter()
        .filter(|review| {
            parse_date(&review.next_review_due).is_some_and(|due| due < now)
                && review.status != ReviewStatus::Revoked
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": reviews.len(),
        "reviews": reviews
    }))
}

pub fn list_expiring(days: i64) -> Result<Value, String> {
    if days < 0 {
        return Err("days must be zero or greater".into());
    }
    let now = Utc::now();
    let threshold = now + Duration::days(days);
    let store = store().lock().unwrap();
    let reviews: Vec<AccessReview> = store
        .0
        .iter()
        .filter(|review| {
            parse_date(&review.next_review_due).is_some_and(|due| due >= now && due <= threshold)
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "days": days,
        "count": reviews.len(),
        "reviews": reviews
    }))
}

pub fn start_review(id: &str, reviewer: &str) -> Result<Value, String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    let mut store = store().lock().unwrap();
    let review = store
        .0
        .iter_mut()
        .find(|review| review.id == id)
        .ok_or_else(|| format!("Access review '{id}' not found"))?;

    review.status = ReviewStatus::InProgress;
    review.reviewer = Some(reviewer.to_string());

    Ok(json!({
        "source": "dry-run",
        "action": "start-review",
        "review": review
    }))
}

pub fn approve_review(id: &str, reviewer: &str, justification: &str) -> Result<Value, String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if justification.trim().is_empty() {
        return Err("justification cannot be empty".into());
    }
    let mut store = store().lock().unwrap();
    let review = store
        .0
        .iter_mut()
        .find(|review| review.id == id)
        .ok_or_else(|| format!("Access review '{id}' not found"))?;

    review.status = ReviewStatus::Approved;
    review.reviewer = Some(reviewer.to_string());
    review.last_reviewed = now_iso();
    review.next_review_due = (Utc::now() + Duration::days(90)).to_rfc3339();
    review
        .access_details
        .push(format!("Approved justification: {justification}"));

    Ok(json!({
        "source": "dry-run",
        "action": "approve-review",
        "review": review
    }))
}

pub fn revoke_review(id: &str, reviewer: &str, reason: &str) -> Result<Value, String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    let mut store = store().lock().unwrap();
    let review = store
        .0
        .iter_mut()
        .find(|review| review.id == id)
        .ok_or_else(|| format!("Access review '{id}' not found"))?;

    review.status = ReviewStatus::Revoked;
    review.reviewer = Some(reviewer.to_string());
    review.last_reviewed = now_iso();
    review
        .access_details
        .push(format!("Revocation reason: {reason}"));

    Ok(json!({
        "source": "dry-run",
        "action": "revoke-review",
        "review": review
    }))
}

pub fn exempt_review(
    id: &str,
    reviewer: &str,
    justification: &str,
    exemption_expiry: &str,
) -> Result<Value, String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if justification.trim().is_empty() {
        return Err("justification cannot be empty".into());
    }
    if parse_date(exemption_expiry).is_none() {
        return Err(format!("Invalid exemption_expiry: {exemption_expiry}"));
    }
    let mut store = store().lock().unwrap();
    let review = store
        .0
        .iter_mut()
        .find(|review| review.id == id)
        .ok_or_else(|| format!("Access review '{id}' not found"))?;

    review.status = ReviewStatus::Exempted;
    review.reviewer = Some(reviewer.to_string());
    review.last_reviewed = now_iso();
    review.next_review_due = exemption_expiry.to_string();
    review.access_details.push(format!(
        "Exemption justification: {justification}; expires: {exemption_expiry}"
    ));

    Ok(json!({
        "source": "dry-run",
        "action": "exempt-review",
        "review": review
    }))
}

pub fn get_summary() -> Result<Value, String> {
    let store = store().lock().unwrap();
    let reviews = &store.0;
    let pending = reviews
        .iter()
        .filter(|review| review.status == ReviewStatus::Pending)
        .count();
    let in_progress = reviews
        .iter()
        .filter(|review| review.status == ReviewStatus::InProgress)
        .count();
    let approved = reviews
        .iter()
        .filter(|review| review.status == ReviewStatus::Approved)
        .count();
    let revoked = reviews
        .iter()
        .filter(|review| review.status == ReviewStatus::Revoked)
        .count();
    let exempted = reviews
        .iter()
        .filter(|review| review.status == ReviewStatus::Exempted)
        .count();

    Ok(json!({
        "source": "dry-run",
        "total": reviews.len(),
        "pending": pending,
        "in_progress": in_progress,
        "approved": approved,
        "revoked": revoked,
        "exempted": exempted
    }))
}

pub fn create_campaign(
    name: &str,
    review_type: &str,
    reviewer_group: &str,
    days: i64,
) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if reviewer_group.trim().is_empty() {
        return Err("reviewer_group cannot be empty".into());
    }
    if days <= 0 {
        return Err("days must be greater than zero".into());
    }

    let review_type = parse_review_type(review_type)?;
    let mut store = store().lock().unwrap();
    let reviews_count = store
        .0
        .iter()
        .filter(|review| review.review_type == review_type)
        .count();
    let completed_count = completed_reviews_count(&store.0, &review_type);
    let campaign = RecertificationCampaign {
        id: format!(
            "arcamp-{}",
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        name: name.to_string(),
        start_date: now_iso(),
        end_date: (Utc::now() + Duration::days(days)).to_rfc3339(),
        review_type,
        reviewer_group: reviewer_group.to_string(),
        reviews_count,
        completed_count,
        status: CampaignStatus::Active,
    };

    store.1.push(campaign.clone());

    Ok(json!({
        "source": "dry-run",
        "action": "create-campaign",
        "campaign": campaign
    }))
}

pub fn get_campaign(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let campaign = store
        .1
        .iter()
        .find(|campaign| campaign.id == id)
        .ok_or_else(|| format!("Recertification campaign '{id}' not found"))?;
    let progress_percent = if campaign.reviews_count == 0 {
        0.0
    } else {
        (campaign.completed_count as f64 / campaign.reviews_count as f64) * 100.0
    };

    Ok(json!({
        "source": "dry-run",
        "campaign": campaign,
        "progress_percent": progress_percent
    }))
}

pub fn list_campaigns() -> Result<Value, String> {
    let store = store().lock().unwrap();
    Ok(json!({
        "source": "dry-run",
        "count": store.1.len(),
        "campaigns": store.1.clone()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_reviews_returns_seed_entries() {
        let result = list_reviews("", "").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert!(result["reviews"].as_array().unwrap().len() >= 9);

        let defra = list_reviews("DEFRA", "").unwrap();
        assert!(defra["reviews"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn test_list_due_reviews_finds_overdue_reviews() {
        let result = list_due_reviews().unwrap();
        let reviews = result["reviews"].as_array().unwrap();
        assert!(
            reviews
                .iter()
                .any(|review| review["id"] == "ar-defra-ad-001")
        );
    }

    #[test]
    fn test_start_review_sets_in_progress() {
        let result = start_review("ar-gblon-sudo-001", "test.reviewer").unwrap();
        assert_eq!(result["review"]["status"], "InProgress");
        assert_eq!(result["review"]["reviewer"], "test.reviewer");
    }

    #[test]
    fn test_approve_review_sets_approved() {
        let result =
            approve_review("ar-defra-svc-001", "test.approver", "Access still required").unwrap();
        assert_eq!(result["review"]["status"], "Approved");
        assert_eq!(result["review"]["reviewer"], "test.approver");
    }

    #[test]
    fn test_revoke_review_sets_revoked() {
        let result = revoke_review(
            "ar-gblon-admin-001",
            "test.reviewer",
            "Access no longer needed",
        )
        .unwrap();
        assert_eq!(result["review"]["status"], "Revoked");
        assert_eq!(result["review"]["reviewer"], "test.reviewer");
    }

    #[test]
    fn test_create_campaign_creates_with_correct_counts() {
        let result = create_campaign(
            "Service account recertification",
            "ServiceAccount",
            "iam-reviewers",
            14,
        )
        .unwrap();
        assert_eq!(
            result["campaign"]["name"],
            "Service account recertification"
        );
        assert_eq!(result["campaign"]["review_type"], "ServiceAccount");
        assert_eq!(result["campaign"]["reviews_count"], 2);
    }

    #[test]
    fn test_get_summary_returns_correct_aggregate_counts() {
        let result = get_summary().unwrap();
        let total = result["total"].as_u64().unwrap();
        let counted = result["pending"].as_u64().unwrap()
            + result["in_progress"].as_u64().unwrap()
            + result["approved"].as_u64().unwrap()
            + result["revoked"].as_u64().unwrap()
            + result["exempted"].as_u64().unwrap();

        assert_eq!(total, counted);
        assert!(total >= 9);
    }
}
