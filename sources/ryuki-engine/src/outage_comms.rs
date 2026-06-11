use chrono::{Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ImpactLevel {
    None,
    Low,
    Med,
    High,
    Critical,
}

impl std::fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImpactLevel::None => write!(f, "None"),
            ImpactLevel::Low => write!(f, "Low"),
            ImpactLevel::Med => write!(f, "Med"),
            ImpactLevel::High => write!(f, "High"),
            ImpactLevel::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeStatus {
    Draft,
    Sent,
    Acknowledged,
    Completed,
    Cancelled,
}

impl std::fmt::Display for NoticeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoticeStatus::Draft => write!(f, "Draft"),
            NoticeStatus::Sent => write!(f, "Sent"),
            NoticeStatus::Acknowledged => write!(f, "Acknowledged"),
            NoticeStatus::Completed => write!(f, "Completed"),
            NoticeStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutageNotice {
    pub id: String,
    pub site: String,
    pub affected_systems: Vec<String>,
    pub start_time: String,
    pub end_time: String,
    pub impact_level: ImpactLevel,
    pub message_template: String,
    pub status: NoticeStatus,
    pub sent_at: Option<String>,
    pub acknowledged_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: Vec<NoticeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeMetadata {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeAckEvent {
    pub notice_id: String,
    pub user: String,
    pub acknowledged_at: String,
}

type NoticeStore = Vec<OutageNotice>;

static NOTICE_STORE: OnceLock<Mutex<NoticeStore>> = OnceLock::new();

fn notice_store() -> &'static Mutex<NoticeStore> {
    NOTICE_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn parse_iso_time(time: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn seed_data() -> NoticeStore {
    let now = Utc::now();
    vec![
        OutageNotice {
            id: "oc-defra-001".into(),
            site: "DEFRA".into(),
            affected_systems: vec!["defra-db-cluster".into(), "defra-app-servers".into()],
            start_time: (now + Days::new(2)).to_rfc3339(),
            end_time: (now + Days::new(2) + chrono::Duration::hours(4)).to_rfc3339(),
            impact_level: ImpactLevel::High,
            message_template: "Scheduled database maintenance on {{site}}. Systems affected: {{systems}}. Expected impact: {{impact}}. Window: {{start}} to {{end}} UTC.".into(),
            status: NoticeStatus::Draft,
            sent_at: None,
            acknowledged_by: None,
            created_at: (now - chrono::Duration::hours(12)).to_rfc3339(),
            updated_at: (now - chrono::Duration::hours(12)).to_rfc3339(),
            metadata: vec![
                NoticeMetadata { key: "source".into(), value: "static-seed".into() },
                NoticeMetadata { key: "dry_run".into(), value: "true".into() },
            ],
        },
        OutageNotice {
            id: "oc-gblon-001".into(),
            site: "GBLON".into(),
            affected_systems: vec!["gblon-vsan-cluster".into(), "gblon-esx-hosts".into()],
            start_time: (now - chrono::Duration::hours(6)).to_rfc3339(),
            end_time: (now - chrono::Duration::hours(1)).to_rfc3339(),
            impact_level: ImpactLevel::Critical,
            message_template: "Emergency storage expansion on {{site}}. Systems affected: {{systems}}. Expected impact: {{impact}}. Window: {{start}} to {{end}} UTC.".into(),
            status: NoticeStatus::Sent,
            sent_at: Some((now - chrono::Duration::hours(5) - chrono::Duration::minutes(30)).to_rfc3339()),
            acknowledged_by: Some("bob.engineer".into()),
            created_at: (now - chrono::Duration::hours(7)).to_rfc3339(),
            updated_at: (now - chrono::Duration::hours(5)).to_rfc3339(),
            metadata: vec![
                NoticeMetadata { key: "source".into(), value: "static-seed".into() },
                NoticeMetadata { key: "dry_run".into(), value: "true".into() },
            ],
        },
        OutageNotice {
            id: "oc-frpar-001".into(),
            site: "FRPAR".into(),
            affected_systems: vec!["frpar-core-switch".into(), "frpar-edge-firewall".into()],
            start_time: (now + Days::new(5)).to_rfc3339(),
            end_time: (now + Days::new(5) + chrono::Duration::hours(3)).to_rfc3339(),
            impact_level: ImpactLevel::Med,
            message_template: "Network firmware upgrade on {{site}}. Systems affected: {{systems}}. Expected impact: {{impact}}. Window: {{start}} to {{end}} UTC.".into(),
            status: NoticeStatus::Draft,
            sent_at: None,
            acknowledged_by: None,
            created_at: (now - chrono::Duration::hours(1)).to_rfc3339(),
            updated_at: (now - chrono::Duration::hours(1)).to_rfc3339(),
            metadata: vec![
                NoticeMetadata { key: "source".into(), value: "static-seed".into() },
                NoticeMetadata { key: "dry_run".into(), value: "true".into() },
            ],
        },
    ]
}

fn expand_template(notice: &OutageNotice) -> String {
    notice
        .message_template
        .replace("{{site}}", &notice.site)
        .replace("{{systems}}", &notice.affected_systems.join(", "))
        .replace("{{impact}}", &notice.impact_level.to_string())
        .replace("{{start}}", &notice.start_time)
        .replace("{{end}}", &notice.end_time)
}

pub fn create_notice(
    site: &str,
    affected_systems: Vec<String>,
    start_time: &str,
    end_time: &str,
    impact_level: &str,
) -> Result<OutageNotice, String> {
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    if affected_systems.is_empty() {
        return Err("affected_systems cannot be empty".into());
    }
    if parse_iso_time(start_time).is_none() {
        return Err(format!("Invalid start_time: {}", start_time));
    }
    if parse_iso_time(end_time).is_none() {
        return Err(format!("Invalid end_time: {}", end_time));
    }
    if parse_iso_time(end_time) <= parse_iso_time(start_time) {
        return Err("end_time must be after start_time".into());
    }
    let impact = match impact_level {
        "None" => ImpactLevel::None,
        "Low" => ImpactLevel::Low,
        "Med" => ImpactLevel::Med,
        "High" => ImpactLevel::High,
        "Critical" => ImpactLevel::Critical,
        other => {
            return Err(format!(
                "Invalid impact_level: {}. Must be None, Low, Med, High, or Critical",
                other
            ));
        }
    };

    let id = format!(
        "oc-{}-{}",
        site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let notice = OutageNotice {
        id: id.clone(),
        site: site.to_string(),
        affected_systems,
        start_time: start_time.to_string(),
        end_time: end_time.to_string(),
        impact_level: impact,
        message_template: "Maintenance on {site}. Systems affected: {systems}. Impact: {impact}. Window: {start} to {end} UTC.".to_string(),
        status: NoticeStatus::Draft,
        sent_at: None,
        acknowledged_by: None,
        created_at: now_iso(),
        updated_at: now_iso(),
        metadata: vec![
            NoticeMetadata {
                key: "source".into(),
                value: "static-seed".into(),
            },
            NoticeMetadata {
                key: "dry_run".into(),
                value: "true".into(),
            },
        ],
    };

    notice_store().lock().unwrap().push(notice.clone());
    Ok(notice)
}

pub fn preview_notice(notice_id: &str) -> Result<Value, String> {
    let store = notice_store().lock().unwrap();
    let notice = store
        .iter()
        .find(|n| n.id == notice_id)
        .ok_or_else(|| format!("Notice '{}' not found", notice_id))?;

    let rendered = expand_template(notice);

    Ok(json!({
        "source": "dry-run",
        "notice_id": notice.id,
        "site": notice.site,
        "impact_level": notice.impact_level,
        "status": notice.status,
        "rendered_message": rendered,
        "affected_systems": notice.affected_systems,
        "start_time": notice.start_time,
        "end_time": notice.end_time
    }))
}

pub fn send_notice(notice_id: &str) -> Result<OutageNotice, String> {
    let mut store = notice_store().lock().unwrap();
    let notice = store
        .iter_mut()
        .find(|n| n.id == notice_id)
        .ok_or_else(|| format!("Notice '{}' not found", notice_id))?;

    if notice.status == NoticeStatus::Sent || notice.status == NoticeStatus::Acknowledged {
        return Err(format!("Notice '{}' has already been sent", notice_id));
    }
    if notice.status == NoticeStatus::Completed {
        return Err(format!("Cannot send a completed notice '{}'", notice_id));
    }
    if notice.status == NoticeStatus::Cancelled {
        return Err(format!("Cannot send a cancelled notice '{}'", notice_id));
    }

    notice.status = NoticeStatus::Sent;
    notice.sent_at = Some(now_iso());
    notice.updated_at = now_iso();
    notice.metadata.push(NoticeMetadata {
        key: "sent_to".into(),
        value: "support-groups (mock)".into(),
    });

    Ok(notice.clone())
}

pub fn acknowledge_notice(notice_id: &str, user: &str) -> Result<NoticeAckEvent, String> {
    let mut store = notice_store().lock().unwrap();
    let notice = store
        .iter_mut()
        .find(|n| n.id == notice_id)
        .ok_or_else(|| format!("Notice '{}' not found", notice_id))?;

    if notice.status != NoticeStatus::Sent {
        return Err(format!(
            "Notice '{}' must be in Sent status to acknowledge (current: {})",
            notice_id, notice.status
        ));
    }

    notice.status = NoticeStatus::Acknowledged;
    notice.acknowledged_by = Some(user.to_string());
    notice.updated_at = now_iso();
    notice.metadata.push(NoticeMetadata {
        key: "acknowledged_by".into(),
        value: user.to_string(),
    });

    Ok(NoticeAckEvent {
        notice_id: notice_id.to_string(),
        user: user.to_string(),
        acknowledged_at: now_iso(),
    })
}

pub fn complete_notice(notice_id: &str) -> Result<OutageNotice, String> {
    let mut store = notice_store().lock().unwrap();
    let notice = store
        .iter_mut()
        .find(|n| n.id == notice_id)
        .ok_or_else(|| format!("Notice '{}' not found", notice_id))?;

    if notice.status != NoticeStatus::Acknowledged && notice.status != NoticeStatus::Sent {
        return Err(format!(
            "Notice '{}' must be sent before completion (current: {})",
            notice_id, notice.status
        ));
    }

    notice.status = NoticeStatus::Completed;
    notice.updated_at = now_iso();
    notice.metadata.push(NoticeMetadata {
        key: "completed_at".into(),
        value: now_iso(),
    });

    Ok(notice.clone())
}

pub fn cancel_notice(notice_id: &str) -> Result<OutageNotice, String> {
    let mut store = notice_store().lock().unwrap();
    let notice = store
        .iter_mut()
        .find(|n| n.id == notice_id)
        .ok_or_else(|| format!("Notice '{}' not found", notice_id))?;

    if notice.status == NoticeStatus::Completed {
        return Err(format!("Cannot cancel a completed notice '{}'", notice_id));
    }
    if notice.status == NoticeStatus::Cancelled {
        return Err("Notice is already cancelled".into());
    }

    notice.status = NoticeStatus::Cancelled;
    notice.updated_at = now_iso();
    notice.metadata.push(NoticeMetadata {
        key: "cancelled_at".into(),
        value: now_iso(),
    });

    Ok(notice.clone())
}

pub fn get_active_notices(site: &str) -> Vec<OutageNotice> {
    let now = Utc::now();
    let store = notice_store().lock().unwrap();
    store
        .iter()
        .filter(|n| {
            n.site == site
                && n.status != NoticeStatus::Completed
                && n.status != NoticeStatus::Cancelled
                && match (parse_iso_time(&n.start_time), parse_iso_time(&n.end_time)) {
                    (Some(_start), Some(end)) => now <= end,
                    _ => false,
                }
        })
        .cloned()
        .collect()
}

pub fn get_notice_history(site: &str) -> Vec<OutageNotice> {
    let store = notice_store().lock().unwrap();
    store
        .iter()
        .filter(|n| {
            n.site == site
                && (n.status == NoticeStatus::Completed || n.status == NoticeStatus::Cancelled)
        })
        .cloned()
        .collect()
}

pub fn get_upcoming(site: &str) -> Vec<OutageNotice> {
    let now = Utc::now();
    let cutoff = now + Days::new(7);
    let store = notice_store().lock().unwrap();
    store
        .iter()
        .filter(|n| {
            n.site == site
                && n.status != NoticeStatus::Cancelled
                && n.status != NoticeStatus::Completed
                && match parse_iso_time(&n.start_time) {
                    Some(start) => start >= now && start <= cutoff,
                    None => false,
                }
        })
        .cloned()
        .collect()
}

pub fn get_notice(notice_id: &str) -> Result<OutageNotice, String> {
    let store = notice_store().lock().unwrap();
    store
        .iter()
        .find(|n| n.id == notice_id)
        .cloned()
        .ok_or_else(|| format!("Notice '{}' not found", notice_id))
}

pub fn get_all_notices(site: &str) -> Vec<OutageNotice> {
    let store = notice_store().lock().unwrap();
    if site.is_empty() {
        store.clone()
    } else {
        store.iter().filter(|n| n.site == site).cloned().collect()
    }
}

pub fn get_outage_contract() -> Value {
    json!({
        "source": "static-seed",
        "communicationMode": "draft-only",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveNotificationAllowed": false,
        "rawRecipientDataAllowed": false,
        "supportedWorkflows": [
            "create-notice",
            "preview-notice",
            "send-notice",
            "acknowledge-notice",
            "complete-notice",
            "cancel-notice",
            "active-notices",
            "notice-history",
            "upcoming-notices"
        ],
        "impactLevels": ["None", "Low", "Med", "High", "Critical"],
        "noticeStatuses": ["Draft", "Sent", "Acknowledged", "Completed", "Cancelled"],
        "messageVariables": ["{{site}}", "{{systems}}", "{{impact}}", "{{start}}", "{{end}}"],
        "requiredInputs": [
            "site",
            "affectedSystems",
            "startTime",
            "endTime",
            "impactLevel",
            "messageTemplate",
            "owner",
            "supportGroup"
        ],
        "requiredGuards": [
            "site-known",
            "affected-systems-known",
            "impact-level-known",
            "message-template-approved",
            "recipient-audience-approved",
            "notification-disabled",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-notification-disabled",
            "site-unknown",
            "affected-systems-unknown",
            "impact-level-unknown",
            "raw-recipient-data",
            "evidence-not-redacted"
        ],
        "requiredEvidence": [
            "Communication draft",
            "Affected CI summary",
            "Impact assessment",
            "Audience decision",
            "Support group roster",
            "Handover notes",
            "Evidence references"
        ],
        "rules": [
            {
                "id": "no-live-notification-send",
                "decision": "block",
                "requirement": "Outage communications engine creates drafts and mock-sends only. No live notifications are dispatched.",
                "evidence": "Communication draft"
            },
            {
                "id": "impact-assessment-required",
                "decision": "block",
                "requirement": "Impact level and affected systems must be documented before notice can be sent.",
                "evidence": "Impact assessment"
            },
            {
                "id": "recipient-data-protection",
                "decision": "block",
                "requirement": "Drafts and channel plans must not expose raw recipient data, credentials, or provider payloads.",
                "evidence": "Channel plan"
            },
            {
                "id": "completion-acknowledgment-tracked",
                "decision": "block",
                "requirement": "Notice completion requires acknowledgment tracking and system restoration verification.",
                "evidence": "Handover notes"
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_notice_succeeds() {
        let notice = create_notice(
            "DEFRA",
            vec!["defra-app-01".into()],
            "2026-07-01T10:00:00Z",
            "2026-07-01T14:00:00Z",
            "High",
        )
        .unwrap();

        assert!(notice.id.starts_with("oc-defra-"));
        assert_eq!(notice.site, "DEFRA");
        assert_eq!(notice.impact_level, ImpactLevel::High);
        assert_eq!(notice.status, NoticeStatus::Draft);
        assert_eq!(notice.affected_systems.len(), 1);
    }

    #[test]
    fn test_create_notice_invalid_impact() {
        let result = create_notice(
            "DEFRA",
            vec!["srv".into()],
            "2026-07-01T10:00:00Z",
            "2026-07-01T14:00:00Z",
            "Catastrophic",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_notice_empty_site() {
        let result = create_notice(
            "",
            vec!["srv".into()],
            "2026-07-01T10:00:00Z",
            "2026-07-01T14:00:00Z",
            "Low",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_notice_invalid_time_range() {
        let result = create_notice(
            "DEFRA",
            vec!["srv".into()],
            "2026-07-01T14:00:00Z",
            "2026-07-01T10:00:00Z",
            "Low",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_preview_notice_renders_template() {
        let preview = preview_notice("oc-defra-001").unwrap();
        assert_eq!(preview["notice_id"], "oc-defra-001");
        assert_eq!(preview["status"], "draft");
        let rendered = preview["rendered_message"].as_str().unwrap();
        assert!(rendered.contains("DEFRA"));
        assert!(rendered.contains("defra-db-cluster"));
        assert!(!rendered.contains("{{site}}"));
    }

    #[test]
    fn test_preview_notice_not_found() {
        assert!(preview_notice("oc-nonexistent").is_err());
    }

    #[test]
    fn test_send_notice() {
        let notice = create_notice(
            "GBLON",
            vec!["gblon-app-01".into()],
            "2026-08-01T10:00:00Z",
            "2026-08-01T14:00:00Z",
            "Med",
        )
        .unwrap();

        let sent = send_notice(&notice.id).unwrap();
        assert_eq!(sent.status, NoticeStatus::Sent);
        assert!(sent.sent_at.is_some());
    }

    #[test]
    fn test_send_notice_already_sent() {
        assert!(send_notice("oc-gblon-001").is_err());
    }

    #[test]
    fn test_acknowledge_notice() {
        let notice = create_notice(
            "FRPAR",
            vec!["frpar-srv-01".into()],
            "2026-08-02T10:00:00Z",
            "2026-08-02T12:00:00Z",
            "Low",
        )
        .unwrap();

        let _sent = send_notice(&notice.id).unwrap();
        let ack = acknowledge_notice(&notice.id, "alice.operator").unwrap();
        assert_eq!(ack.notice_id, notice.id);
        assert_eq!(ack.user, "alice.operator");

        let updated = get_notice(&notice.id).unwrap();
        assert_eq!(updated.status, NoticeStatus::Acknowledged);
        assert_eq!(updated.acknowledged_by, Some("alice.operator".into()));
    }

    #[test]
    fn test_acknowledge_notice_not_sent() {
        assert!(acknowledge_notice("oc-defra-001", "user").is_err());
    }

    #[test]
    fn test_complete_notice() {
        let notice = create_notice(
            "NLAMS",
            vec!["nlams-srv-01".into()],
            "2026-08-03T08:00:00Z",
            "2026-08-03T10:00:00Z",
            "High",
        )
        .unwrap();

        let _sent = send_notice(&notice.id).unwrap();
        let _ack = acknowledge_notice(&notice.id, "bob.engineer").unwrap();
        let completed = complete_notice(&notice.id).unwrap();
        assert_eq!(completed.status, NoticeStatus::Completed);

        let updated = get_notice(&notice.id).unwrap();
        assert_eq!(updated.status, NoticeStatus::Completed);
    }

    #[test]
    fn test_complete_notice_not_sent() {
        assert!(complete_notice("oc-frpar-001").is_err());
    }

    #[test]
    fn test_cancel_notice() {
        let notice = create_notice(
            "DEFRA",
            vec!["defra-srv-01".into()],
            "2026-08-04T10:00:00Z",
            "2026-08-04T12:00:00Z",
            "Med",
        )
        .unwrap();

        let cancelled = cancel_notice(&notice.id).unwrap();
        assert_eq!(cancelled.status, NoticeStatus::Cancelled);
    }

    #[test]
    fn test_cancel_notice_already_completed() {
        let notice = create_notice(
            "GBLON",
            vec!["gblon-srv-01".into()],
            "2026-07-01T10:00:00Z",
            "2026-07-01T14:00:00Z",
            "Low",
        )
        .unwrap();
        // Must send + ack + complete before testing cancel on completed
        let _sent = send_notice(&notice.id).unwrap();
        let _ack = acknowledge_notice(&notice.id, "user").unwrap();
        let _completed = complete_notice(&notice.id).unwrap();
        assert!(cancel_notice(&notice.id).is_err());
    }

    #[test]
    fn test_get_active_notices() {
        let active = get_active_notices("DEFRA");
        assert!(!active.is_empty());
        for notice in &active {
            assert!(notice.status != NoticeStatus::Completed);
            assert!(notice.status != NoticeStatus::Cancelled);
        }
    }

    #[test]
    fn test_get_notice_history() {
        let notice = create_notice(
            "DEBER",
            vec!["deber-srv-01".into()],
            "2026-06-10T08:00:00Z",
            "2026-06-10T10:00:00Z",
            "Low",
        )
        .unwrap();
        let _sent = send_notice(&notice.id).unwrap();
        let _ack = acknowledge_notice(&notice.id, "user").unwrap();
        let _completed = complete_notice(&notice.id).unwrap();

        let history = get_notice_history("DEBER");
        assert!(!history.is_empty());
        assert!(history.iter().any(|n| n.id == notice.id));
    }

    #[test]
    fn test_get_upcoming() {
        let upcoming = get_upcoming("DEFRA");
        assert!(!upcoming.is_empty(), "oc-defra-001 is 2 days in the future");
        for notice in &upcoming {
            assert!(notice.status != NoticeStatus::Cancelled);
            assert!(notice.status != NoticeStatus::Completed);
        }
    }

    #[test]
    fn test_get_all_notices() {
        let all = get_all_notices("");
        assert!(all.len() >= 3);

        let defra = get_all_notices("DEFRA");
        assert!(!defra.is_empty());
        for n in &defra {
            assert_eq!(n.site, "DEFRA");
        }
    }

    #[test]
    fn test_get_notice() {
        let notice = get_notice("oc-defra-001").unwrap();
        assert_eq!(notice.id, "oc-defra-001");
        assert_eq!(notice.site, "DEFRA");
    }

    #[test]
    fn test_get_notice_not_found() {
        assert!(get_notice("oc-nonexistent").is_err());
    }

    #[test]
    fn test_create_notice_empty_systems() {
        let result = create_notice(
            "DEFRA",
            vec![],
            "2026-07-01T10:00:00Z",
            "2026-07-01T14:00:00Z",
            "Low",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_impact_level_display() {
        assert_eq!(ImpactLevel::None.to_string(), "None");
        assert_eq!(ImpactLevel::Low.to_string(), "Low");
        assert_eq!(ImpactLevel::Med.to_string(), "Med");
        assert_eq!(ImpactLevel::High.to_string(), "High");
        assert_eq!(ImpactLevel::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_notice_status_display() {
        assert_eq!(NoticeStatus::Draft.to_string(), "Draft");
        assert_eq!(NoticeStatus::Sent.to_string(), "Sent");
        assert_eq!(NoticeStatus::Acknowledged.to_string(), "Acknowledged");
        assert_eq!(NoticeStatus::Completed.to_string(), "Completed");
        assert_eq!(NoticeStatus::Cancelled.to_string(), "Cancelled");
    }

    #[test]
    fn test_get_outage_contract() {
        let contract = get_outage_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["dryRunRequired"], true);
        assert!(
            !contract["supportedWorkflows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!contract["impactLevels"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_send_notice_not_found() {
        assert!(send_notice("oc-nonexistent").is_err());
    }

    #[test]
    fn test_acknowledge_notice_not_found() {
        assert!(acknowledge_notice("oc-nonexistent", "user").is_err());
    }

    #[test]
    fn test_complete_notice_not_found() {
        assert!(complete_notice("oc-nonexistent").is_err());
    }

    #[test]
    fn test_cancel_notice_not_found() {
        assert!(cancel_notice("oc-nonexistent").is_err());
    }

    #[test]
    fn test_get_notice_history_empty_for_new_site() {
        let history = get_notice_history("DEHAM");
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_active_notices_empty_for_completed_site() {
        let notice = create_notice(
            "DEBER",
            vec!["deber-srv-01".into()],
            "2026-06-09T08:00:00Z",
            "2026-06-09T10:00:00Z",
            "Low",
        )
        .unwrap();
        let _sent = send_notice(&notice.id).unwrap();
        let _ack = acknowledge_notice(&notice.id, "user").unwrap();
        let _completed = complete_notice(&notice.id).unwrap();

        let active = get_active_notices("DEBER");
        assert!(active.is_empty());
    }
}
