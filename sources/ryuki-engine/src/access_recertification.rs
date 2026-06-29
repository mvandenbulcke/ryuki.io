use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CampaignStatus::Active => write!(f, "Active"),
            CampaignStatus::Completed => write!(f, "Completed"),
        }
    }
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

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn parse_review_type(value: &str) -> Result<ReviewType, String> {
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

pub fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn review_response(review: &AccessReview) -> Value {
    json!({
        "source": "db",
        "review": review
    })
}

pub fn completed_reviews_count(reviews: &[AccessReview], review_type: &ReviewType) -> usize {
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

/// Pure read over a slice. Returns JSON with count and reviews filtered by site/type.
pub fn list_reviews_pure(
    reviews: &[AccessReview],
    site: &str,
    review_type: Option<&ReviewType>,
) -> Value {
    let filtered: Vec<&AccessReview> = reviews
        .iter()
        .filter(|r| site.is_empty() || r.site == site)
        .filter(|r| review_type.is_none_or(|rt| r.review_type == *rt))
        .collect();
    json!({
        "source": "db",
        "count": filtered.len(),
        "reviews": filtered
    })
}

/// Pure read over a slice. Returns due reviews (next_review_due < now, not Revoked).
pub fn list_due_reviews_pure(reviews: &[AccessReview]) -> Value {
    let now = Utc::now();
    let due: Vec<&AccessReview> = reviews
        .iter()
        .filter(|r| {
            parse_date(&r.next_review_due).is_some_and(|d| d < now)
                && r.status != ReviewStatus::Revoked
        })
        .collect();
    json!({
        "source": "db",
        "count": due.len(),
        "reviews": due
    })
}

/// Pure read over a slice. Returns reviews expiring within `days` days from now.
pub fn list_expiring_pure(reviews: &[AccessReview], days: i64) -> Value {
    let now = Utc::now();
    let threshold = now + Duration::days(days);
    let expiring: Vec<&AccessReview> = reviews
        .iter()
        .filter(|r| parse_date(&r.next_review_due).is_some_and(|d| d >= now && d <= threshold))
        .collect();
    json!({
        "source": "db",
        "days": days,
        "count": expiring.len(),
        "reviews": expiring
    })
}

/// Pure summary over a slice.
pub fn get_summary_pure(reviews: &[AccessReview]) -> Value {
    let pending = reviews
        .iter()
        .filter(|r| r.status == ReviewStatus::Pending)
        .count();
    let in_progress = reviews
        .iter()
        .filter(|r| r.status == ReviewStatus::InProgress)
        .count();
    let approved = reviews
        .iter()
        .filter(|r| r.status == ReviewStatus::Approved)
        .count();
    let revoked = reviews
        .iter()
        .filter(|r| r.status == ReviewStatus::Revoked)
        .count();
    let exempted = reviews
        .iter()
        .filter(|r| r.status == ReviewStatus::Exempted)
        .count();
    json!({
        "source": "db",
        "total": reviews.len(),
        "pending": pending,
        "in_progress": in_progress,
        "approved": approved,
        "revoked": revoked,
        "exempted": exempted
    })
}

/// Pure guard for start_review: validates that the loaded review is Pending and
/// reviewer is non-empty. Returns the new field values or an error string.
/// Does NOT mutate — the repo applies the CAS UPDATE.
pub fn start_review_guard(review: &AccessReview, reviewer: &str) -> Result<(), String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if review.status != ReviewStatus::Pending {
        return Err(format!(
            "access review '{}' is not in Pending status (current: {})",
            review.id, review.status
        ));
    }
    Ok(())
}

/// Pure guard for approve_review.
pub fn approve_review_guard(
    review: &AccessReview,
    reviewer: &str,
    justification: &str,
) -> Result<(), String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if justification.trim().is_empty() {
        return Err("justification cannot be empty".into());
    }
    if !matches!(
        review.status,
        ReviewStatus::InProgress | ReviewStatus::Pending
    ) {
        return Err(format!(
            "access review '{}' cannot be approved from status '{}'",
            review.id, review.status
        ));
    }
    Ok(())
}

/// Pure guard for revoke_review.
pub fn revoke_review_guard(
    review: &AccessReview,
    reviewer: &str,
    reason: &str,
) -> Result<(), String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    if !matches!(
        review.status,
        ReviewStatus::InProgress | ReviewStatus::Pending
    ) {
        return Err(format!(
            "access review '{}' cannot be revoked from status '{}'",
            review.id, review.status
        ));
    }
    Ok(())
}

/// Pure guard for exempt_review.
pub fn exempt_review_guard(
    review: &AccessReview,
    reviewer: &str,
    justification: &str,
    exemption_expiry: &str,
) -> Result<(), String> {
    if reviewer.trim().is_empty() {
        return Err("reviewer cannot be empty".into());
    }
    if justification.trim().is_empty() {
        return Err("justification cannot be empty".into());
    }
    if parse_date(exemption_expiry).is_none() {
        return Err(format!("Invalid exemption_expiry: {exemption_expiry}"));
    }
    // An exemption grants an exception while a review is still open; a review
    // already Approved/Revoked/Exempted is terminal and must not be rewritten.
    if !matches!(
        review.status,
        ReviewStatus::InProgress | ReviewStatus::Pending
    ) {
        return Err(format!(
            "access review '{}' cannot be exempted from status '{}'",
            review.id, review.status
        ));
    }
    Ok(())
}

/// Pure guard for create_campaign.
pub fn create_campaign_guard(name: &str, reviewer_group: &str, days: i64) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if reviewer_group.trim().is_empty() {
        return Err("reviewer_group cannot be empty".into());
    }
    if days <= 0 {
        return Err("days must be greater than zero".into());
    }
    Ok(())
}

/// Build a new RecertificationCampaign value (for the repo to INSERT).
pub fn build_campaign(
    name: &str,
    review_type: ReviewType,
    reviewer_group: &str,
    days: i64,
    reviews_count: usize,
    completed_count: usize,
) -> RecertificationCampaign {
    RecertificationCampaign {
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
    }
}

pub fn campaign_response(campaign: &RecertificationCampaign) -> Value {
    let progress_percent = if campaign.reviews_count == 0 {
        0.0
    } else {
        (campaign.completed_count as f64 / campaign.reviews_count as f64) * 100.0
    };
    json!({
        "source": "db",
        "campaign": campaign,
        "progress_percent": progress_percent
    })
}

pub fn get_review_response(review: &AccessReview) -> Value {
    review_response(review)
}

// ---------------------------------------------------------------------------
// Recertification overdue classification (durable-scheduler scan)
// ---------------------------------------------------------------------------

/// Whether an `Active` recertification campaign has blown its `end_date`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecertificationDueState {
    /// Past (or exactly at) the deadline while still Active — actionable work.
    Overdue,
    /// The deadline is still in the future — not yet actionable.
    NotYetDue,
}

impl RecertificationDueState {
    /// Only `Overdue` becomes queue work. Used as the post-SQL clock-skew guard
    /// (the scan re-checks with the CP clock so a near-edge row the DB clock
    /// selected but the CP clock says is not-yet-due is skipped).
    pub fn is_actionable(&self) -> bool {
        matches!(self, RecertificationDueState::Overdue)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RecertificationDueState::Overdue => "overdue",
            RecertificationDueState::NotYetDue => "not-yet-due",
        }
    }
}

/// Pure: is a campaign overdue at `now`? A campaign is overdue once the current
/// time reaches its `end_date` (`>=`, so exactly-at-deadline counts). Mirrors the
/// shape of `legal_hold::classify_legal_hold_expiry` but binary (no "soon"
/// window in slice 1).
pub fn classify_recertification_overdue(
    end_date_unix_ms: i64,
    now_unix_ms: i64,
) -> RecertificationDueState {
    if now_unix_ms >= end_date_unix_ms {
        RecertificationDueState::Overdue
    } else {
        RecertificationDueState::NotYetDue
    }
}

#[cfg(test)]
pub fn seed_reviews() -> Vec<AccessReview> {
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

#[cfg(test)]
pub fn seed_campaigns() -> Vec<RecertificationCampaign> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recertification_overdue_boundaries() {
        let end = 1_000_000_000_000_i64;
        // Past the deadline → overdue (actionable).
        let v = classify_recertification_overdue(end, end + 1);
        assert_eq!(v, RecertificationDueState::Overdue);
        assert!(v.is_actionable());
        assert_eq!(v.as_str(), "overdue");
        // Exactly at the deadline (now == end) → overdue (>=).
        assert_eq!(
            classify_recertification_overdue(end, end),
            RecertificationDueState::Overdue
        );
        // Before the deadline → not yet due (non-actionable; the scan skips it).
        let nyd = classify_recertification_overdue(end, end - 1);
        assert_eq!(nyd, RecertificationDueState::NotYetDue);
        assert!(!nyd.is_actionable());
        assert_eq!(nyd.as_str(), "not-yet-due");
    }

    #[test]
    fn test_list_reviews_returns_seed_entries() {
        let reviews = seed_reviews();
        let result = list_reviews_pure(&reviews, "", None);
        assert_eq!(result["source"], "db");
        assert!(result["reviews"].as_array().unwrap().len() >= 9);

        let defra = list_reviews_pure(&reviews, "DEFRA", None);
        assert!(defra["reviews"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn test_list_due_reviews_finds_overdue_reviews() {
        let reviews = seed_reviews();
        let result = list_due_reviews_pure(&reviews);
        let arr = result["reviews"].as_array().unwrap();
        assert!(arr.iter().any(|r| r["id"] == "ar-defra-ad-001"));
    }

    #[test]
    fn test_start_review_guard_ok_on_pending() {
        let reviews = seed_reviews();
        let review = reviews
            .iter()
            .find(|r| r.id == "ar-gblon-sudo-001")
            .unwrap();
        assert!(start_review_guard(review, "test.reviewer").is_ok());
    }

    #[test]
    fn test_approve_review_guard_ok_on_in_progress() {
        let reviews = seed_reviews();
        let review = reviews.iter().find(|r| r.id == "ar-defra-svc-001").unwrap();
        assert!(approve_review_guard(review, "test.approver", "Access still required").is_ok());
    }

    #[test]
    fn test_revoke_review_guard_ok_on_in_progress() {
        let reviews = seed_reviews();
        let review = reviews
            .iter()
            .find(|r| r.id == "ar-gblon-admin-001")
            .unwrap();
        assert!(revoke_review_guard(review, "test.reviewer", "Access no longer needed").is_ok());
    }

    #[test]
    fn test_exempt_review_guard_rejects_terminal_states() {
        let reviews = seed_reviews();
        let open = reviews
            .iter()
            .find(|r| matches!(r.status, ReviewStatus::Pending | ReviewStatus::InProgress))
            .expect("a seed review should be Pending/InProgress");
        let expiry = "2027-01-01T00:00:00Z";
        // OK while the review is still open.
        assert!(exempt_review_guard(open, "test.reviewer", "temporary exception", expiry).is_ok());
        // Rejected once the review is terminal — exempt must not rewrite it.
        let mut terminal = open.clone();
        for st in [
            ReviewStatus::Approved,
            ReviewStatus::Revoked,
            ReviewStatus::Exempted,
        ] {
            terminal.status = st;
            assert!(
                exempt_review_guard(&terminal, "test.reviewer", "temporary exception", expiry)
                    .is_err(),
                "exempt must reject a terminal-status review"
            );
        }
    }

    #[test]
    fn test_build_campaign_creates_with_correct_counts() {
        let reviews = seed_reviews();
        let rt = ReviewType::ServiceAccount;
        let reviews_count = reviews.iter().filter(|r| r.review_type == rt).count();
        let completed_count = completed_reviews_count(&reviews, &rt);
        let campaign = build_campaign(
            "Service account recertification",
            rt,
            "iam-reviewers",
            14,
            reviews_count,
            completed_count,
        );
        assert_eq!(campaign.name, "Service account recertification");
        assert_eq!(campaign.reviews_count, 2);
    }

    #[test]
    fn test_get_summary_returns_correct_aggregate_counts() {
        let reviews = seed_reviews();
        let result = get_summary_pure(&reviews);
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
