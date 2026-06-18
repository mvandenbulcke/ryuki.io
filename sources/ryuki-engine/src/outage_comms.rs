use chrono::{Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

// ─── Pure helpers ─────────────────────────────────────────────────────────────

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn parse_iso_time(time: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn expand_template(notice: &OutageNotice) -> String {
    notice
        .message_template
        .replace("{{site}}", &notice.site)
        .replace("{{systems}}", &notice.affected_systems.join(", "))
        .replace("{{impact}}", &notice.impact_level.to_string())
        .replace("{{start}}", &notice.start_time)
        .replace("{{end}}", &notice.end_time)
}

// ─── Pure business logic ──────────────────────────────────────────────────────

/// Validate inputs and return a new `OutageNotice` in Draft status.
/// Does NOT write to any store — caller persists the returned notice.
pub fn build_notice(
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
    let impact = parse_impact_level(impact_level)?;

    let id = format!(
        "oc-{}-{}",
        site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let now = now_iso();
    Ok(OutageNotice {
        id,
        site: site.to_string(),
        affected_systems,
        start_time: start_time.to_string(),
        end_time: end_time.to_string(),
        impact_level: impact,
        message_template: "Maintenance on {{site}}. Systems affected: {{systems}}. Impact: {{impact}}. Window: {{start}} to {{end}} UTC.".to_string(),
        status: NoticeStatus::Draft,
        sent_at: None,
        acknowledged_by: None,
        created_at: now.clone(),
        updated_at: now,
        metadata: vec![
            NoticeMetadata { key: "source".into(), value: "static-seed".into() },
            NoticeMetadata { key: "dry_run".into(), value: "true".into() },
        ],
    })
}

pub fn parse_impact_level(impact_level: &str) -> Result<ImpactLevel, String> {
    match impact_level {
        "None" => Ok(ImpactLevel::None),
        "Low" => Ok(ImpactLevel::Low),
        "Med" => Ok(ImpactLevel::Med),
        "High" => Ok(ImpactLevel::High),
        "Critical" => Ok(ImpactLevel::Critical),
        other => Err(format!(
            "Invalid impact_level: {}. Must be None, Low, Med, High, or Critical",
            other
        )),
    }
}

/// Guard: validate that a notice can transition to Sent. Returns Err with reason if not.
pub fn send_guard(notice: &OutageNotice) -> Result<(), String> {
    if notice.status == NoticeStatus::Sent || notice.status == NoticeStatus::Acknowledged {
        return Err(format!("Notice '{}' has already been sent", notice.id));
    }
    if notice.status == NoticeStatus::Completed {
        return Err(format!("Cannot send a completed notice '{}'", notice.id));
    }
    if notice.status == NoticeStatus::Cancelled {
        return Err(format!("Cannot send a cancelled notice '{}'", notice.id));
    }
    Ok(())
}

/// Guard: validate that a notice can be acknowledged (must be Sent).
pub fn acknowledge_guard(notice: &OutageNotice) -> Result<(), String> {
    if notice.status != NoticeStatus::Sent {
        return Err(format!(
            "Notice '{}' must be in Sent status to acknowledge (current: {})",
            notice.id, notice.status
        ));
    }
    Ok(())
}

/// Guard: validate that a notice can be completed (must be Sent or Acknowledged).
pub fn complete_guard(notice: &OutageNotice) -> Result<(), String> {
    if notice.status != NoticeStatus::Acknowledged && notice.status != NoticeStatus::Sent {
        return Err(format!(
            "Notice '{}' must be sent before completion (current: {})",
            notice.id, notice.status
        ));
    }
    Ok(())
}

/// Guard: validate that a notice can be cancelled (not already Completed or Cancelled).
pub fn cancel_guard(notice: &OutageNotice) -> Result<(), String> {
    if notice.status == NoticeStatus::Completed {
        return Err(format!("Cannot cancel a completed notice '{}'", notice.id));
    }
    if notice.status == NoticeStatus::Cancelled {
        return Err("Notice is already cancelled".into());
    }
    Ok(())
}

/// Pure preview: render a notice's template without any store access.
pub fn preview_notice_pure(notice: &OutageNotice) -> Value {
    let rendered = expand_template(notice);
    json!({
        "source": "dry-run",
        "notice_id": notice.id,
        "site": notice.site,
        "impact_level": notice.impact_level,
        "status": notice.status,
        "rendered_message": rendered,
        "affected_systems": notice.affected_systems,
        "start_time": notice.start_time,
        "end_time": notice.end_time
    })
}

/// Pure filter: active notices from a slice (not Completed/Cancelled and end_time >= now).
pub fn filter_active<'a>(notices: &'a [OutageNotice], site: &str) -> Vec<&'a OutageNotice> {
    let now = Utc::now();
    notices
        .iter()
        .filter(|n| {
            n.site == site
                && n.status != NoticeStatus::Completed
                && n.status != NoticeStatus::Cancelled
                && match parse_iso_time(&n.end_time) {
                    Some(end) => now <= end,
                    None => false,
                }
        })
        .collect()
}

/// Pure filter: history (Completed or Cancelled) from a slice.
pub fn filter_history<'a>(notices: &'a [OutageNotice], site: &str) -> Vec<&'a OutageNotice> {
    notices
        .iter()
        .filter(|n| {
            n.site == site
                && (n.status == NoticeStatus::Completed || n.status == NoticeStatus::Cancelled)
        })
        .collect()
}

/// Pure filter: upcoming notices within 7 days from a slice.
pub fn filter_upcoming<'a>(notices: &'a [OutageNotice], site: &str) -> Vec<&'a OutageNotice> {
    let now = Utc::now();
    let cutoff = now + Days::new(7);
    notices
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
        .collect()
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

    /// Build a notice in an arbitrary status for guard/filter tests. Times are
    /// expressed as offsets (in hours) from now so filter windows are testable.
    fn notice_with(
        id: &str,
        site: &str,
        status: NoticeStatus,
        start_offset_hours: i64,
        end_offset_hours: i64,
    ) -> OutageNotice {
        let now = Utc::now();
        OutageNotice {
            id: id.into(),
            site: site.into(),
            affected_systems: vec![format!("{}-srv-01", site.to_lowercase())],
            start_time: (now + chrono::Duration::hours(start_offset_hours)).to_rfc3339(),
            end_time: (now + chrono::Duration::hours(end_offset_hours)).to_rfc3339(),
            impact_level: ImpactLevel::Med,
            message_template:
                "Maintenance on {{site}}. Systems affected: {{systems}}. Impact: {{impact}}. Window: {{start}} to {{end}} UTC."
                    .into(),
            status,
            sent_at: None,
            acknowledged_by: None,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
            metadata: Vec::new(),
        }
    }

    // ─── build_notice (pure validation) ───────────────────────────────────────

    #[test]
    fn test_build_notice_succeeds() {
        let notice = build_notice(
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
    fn test_build_notice_invalid_impact() {
        assert!(
            build_notice(
                "DEFRA",
                vec!["srv".into()],
                "2026-07-01T10:00:00Z",
                "2026-07-01T14:00:00Z",
                "Catastrophic",
            )
            .is_err()
        );
    }

    #[test]
    fn test_build_notice_empty_site() {
        assert!(
            build_notice(
                "",
                vec!["srv".into()],
                "2026-07-01T10:00:00Z",
                "2026-07-01T14:00:00Z",
                "Low",
            )
            .is_err()
        );
    }

    #[test]
    fn test_build_notice_empty_systems() {
        assert!(
            build_notice(
                "DEFRA",
                vec![],
                "2026-07-01T10:00:00Z",
                "2026-07-01T14:00:00Z",
                "Low",
            )
            .is_err()
        );
    }

    #[test]
    fn test_build_notice_invalid_time_range() {
        assert!(
            build_notice(
                "DEFRA",
                vec!["srv".into()],
                "2026-07-01T14:00:00Z",
                "2026-07-01T10:00:00Z",
                "Low",
            )
            .is_err()
        );
    }

    #[test]
    fn test_build_notice_default_template_expands() {
        // The default template must use {{double}} braces so expand_template
        // (and the DB-stored template) actually substitute the placeholders.
        let notice = build_notice(
            "DEFRA",
            vec!["defra-db".into()],
            "2026-07-01T10:00:00Z",
            "2026-07-01T14:00:00Z",
            "High",
        )
        .unwrap();
        let rendered = expand_template(&notice);
        assert!(rendered.contains("DEFRA"));
        assert!(rendered.contains("defra-db"));
        assert!(!rendered.contains("{{site}}"));
        assert!(!rendered.contains("{{systems}}"));
    }

    #[test]
    fn test_parse_impact_level() {
        assert_eq!(
            parse_impact_level("Critical").unwrap(),
            ImpactLevel::Critical
        );
        assert!(parse_impact_level("Nope").is_err());
    }

    // ─── Lifecycle guards (pure) ──────────────────────────────────────────────

    #[test]
    fn test_send_guard() {
        assert!(send_guard(&notice_with("n", "DEFRA", NoticeStatus::Draft, 24, 28)).is_ok());
        for s in [
            NoticeStatus::Sent,
            NoticeStatus::Acknowledged,
            NoticeStatus::Completed,
            NoticeStatus::Cancelled,
        ] {
            assert!(
                send_guard(&notice_with("n", "DEFRA", s.clone(), 24, 28)).is_err(),
                "send_guard should reject {s}"
            );
        }
    }

    #[test]
    fn test_acknowledge_guard() {
        assert!(acknowledge_guard(&notice_with("n", "DEFRA", NoticeStatus::Sent, 1, 4)).is_ok());
        for s in [
            NoticeStatus::Draft,
            NoticeStatus::Acknowledged,
            NoticeStatus::Completed,
            NoticeStatus::Cancelled,
        ] {
            assert!(
                acknowledge_guard(&notice_with("n", "DEFRA", s.clone(), 1, 4)).is_err(),
                "acknowledge_guard should reject {s}"
            );
        }
    }

    #[test]
    fn test_complete_guard() {
        assert!(complete_guard(&notice_with("n", "DEFRA", NoticeStatus::Sent, 1, 4)).is_ok());
        assert!(
            complete_guard(&notice_with("n", "DEFRA", NoticeStatus::Acknowledged, 1, 4)).is_ok()
        );
        for s in [
            NoticeStatus::Draft,
            NoticeStatus::Completed,
            NoticeStatus::Cancelled,
        ] {
            assert!(
                complete_guard(&notice_with("n", "DEFRA", s.clone(), 1, 4)).is_err(),
                "complete_guard should reject {s}"
            );
        }
    }

    #[test]
    fn test_cancel_guard() {
        for s in [
            NoticeStatus::Draft,
            NoticeStatus::Sent,
            NoticeStatus::Acknowledged,
        ] {
            assert!(
                cancel_guard(&notice_with("n", "DEFRA", s.clone(), 1, 4)).is_ok(),
                "cancel_guard should allow {s}"
            );
        }
        assert!(cancel_guard(&notice_with("n", "DEFRA", NoticeStatus::Completed, 1, 4)).is_err());
        assert!(cancel_guard(&notice_with("n", "DEFRA", NoticeStatus::Cancelled, 1, 4)).is_err());
    }

    // ─── Pure preview + template ──────────────────────────────────────────────

    #[test]
    fn test_preview_notice_pure_renders_template() {
        let notice = notice_with("oc-defra-001", "DEFRA", NoticeStatus::Draft, 48, 52);
        let preview = preview_notice_pure(&notice);
        assert_eq!(preview["notice_id"], "oc-defra-001");
        // status serializes via serde rename_all = kebab-case
        assert_eq!(preview["status"], "draft");
        let rendered = preview["rendered_message"].as_str().unwrap();
        assert!(rendered.contains("DEFRA"));
        assert!(rendered.contains("defra-srv-01"));
        assert!(!rendered.contains("{{site}}"));
    }

    // ─── Pure filters ─────────────────────────────────────────────────────────

    #[test]
    fn test_filter_active() {
        let notices = vec![
            notice_with("a", "DEFRA", NoticeStatus::Sent, -2, 4), // active: ends in future
            notice_with("b", "DEFRA", NoticeStatus::Completed, -10, -2), // terminal
            notice_with("c", "DEFRA", NoticeStatus::Draft, -2, -1), // ended in past
            notice_with("d", "GBLON", NoticeStatus::Sent, -2, 4), // other site
        ];
        let active = filter_active(&notices, "DEFRA");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "a");
    }

    #[test]
    fn test_filter_history() {
        let notices = vec![
            notice_with("a", "DEFRA", NoticeStatus::Completed, -20, -10),
            notice_with("b", "DEFRA", NoticeStatus::Cancelled, -20, -10),
            notice_with("c", "DEFRA", NoticeStatus::Sent, 1, 4),
            notice_with("d", "GBLON", NoticeStatus::Completed, -20, -10),
        ];
        let history = filter_history(&notices, "DEFRA");
        assert_eq!(history.len(), 2);
        assert!(history.iter().all(|n| n.site == "DEFRA"));
    }

    #[test]
    fn test_filter_upcoming() {
        let notices = vec![
            notice_with("a", "DEFRA", NoticeStatus::Draft, 48, 52), // upcoming (2 days)
            notice_with("b", "DEFRA", NoticeStatus::Draft, 24 * 10, 24 * 10 + 4), // beyond 7 days
            notice_with("c", "DEFRA", NoticeStatus::Draft, -5, -1), // already started
            notice_with("d", "DEFRA", NoticeStatus::Cancelled, 48, 52), // terminal
        ];
        let upcoming = filter_upcoming(&notices, "DEFRA");
        assert_eq!(upcoming.len(), 1);
        assert_eq!(upcoming[0].id, "a");
    }

    #[test]
    fn test_filter_empty_for_unknown_site() {
        let notices = vec![notice_with("a", "DEFRA", NoticeStatus::Sent, -2, 4)];
        assert!(filter_active(&notices, "DEHAM").is_empty());
        assert!(filter_history(&notices, "DEHAM").is_empty());
        assert!(filter_upcoming(&notices, "DEHAM").is_empty());
    }

    // ─── Display + contract ───────────────────────────────────────────────────

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
}
