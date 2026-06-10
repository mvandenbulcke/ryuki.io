use crate::models::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "key",
    "private",
    "auth",
];

pub fn collect_evidence(request: &Request) -> Result<EvidencePack, String> {
    let id = format!(
        "ev-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let now = Utc::now().to_rfc3339();

    let mut items: Vec<EvidenceItem> = Vec::new();

    items.push(EvidenceItem {
        key: "request-payload-summary".into(),
        value: format!(
            "Request {} of type {} for site {} environment {} owner {} criticality {}",
            request.id,
            request.request_type,
            request.site,
            request.environment,
            request.owner,
            request.criticality
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    for stage in &request.stages {
        for evidence in &stage.evidence {
            items.push(evidence.clone());
        }
    }

    if let Some(ref manifest_id) = request.evidence_manifest_id {
        items.push(EvidenceItem {
            key: "evidence-manifest-reference".into(),
            value: manifest_id.clone(),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Summary,
        });
    }

    for approver in &request.approval_route {
        items.push(EvidenceItem {
            key: "approval-route-entry".into(),
            value: format!("Approver role: {}", approver),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::ApprovalDecision,
        });
    }

    let mut pack = EvidencePack {
        id,
        request_id: request.id.clone(),
        items,
        redacted: false,
        created_at: now,
        format: "json".into(),
        compliance_checks: Vec::new(),
        metadata: HashMap::new(),
    };

    redact_evidence(&mut pack)?;

    pack.redacted = true;

    Ok(pack)
}

pub fn redact_evidence(pack: &mut EvidencePack) -> Result<(), String> {
    for item in pack.items.iter_mut() {
        if should_redact(&item.key, &item.value) {
            item.redacted = true;
            item.redacted_value = Some("***REDACTED***".into());
        }
    }
    pack.redacted = true;
    Ok(())
}

fn should_redact(key: &str, value: &str) -> bool {
    let key_lower = key.to_lowercase();
    let value_lower = value.to_lowercase();

    for pattern in SENSITIVE_KEY_PATTERNS {
        if key_lower.contains(pattern) {
            return true;
        }
    }

    if value_lower.contains("password:")
        || value_lower.contains("secret:")
        || value_lower.contains("token=")
        || value_lower.contains("api_key")
    {
        return true;
    }

    false
}

pub fn export_evidence(pack: &EvidencePack, format: &str) -> Result<String, String> {
    if !pack.redacted {
        return Err("Cannot export unredacted evidence pack.".into());
    }

    let safe_pack = build_safe_export_pack(pack);

    match format {
        "json" => serde_json::to_string_pretty(&safe_pack).map_err(|e| e.to_string()),
        "yaml" => serde_yaml::to_string(&safe_pack).map_err(|e| e.to_string()),
        _ => Err(format!("Unsupported export format: {}", format)),
    }
}

/// Converts an evidence pack to a safe export representation where
/// redacted items expose only their redacted_value or a safe marker,
/// never the original sensitive value.
fn build_safe_export_pack(pack: &EvidencePack) -> serde_json::Value {
    let items: Vec<serde_json::Value> = pack
        .items
        .iter()
        .map(|item| {
            let safe_value = safe_export_value(item);
            serde_json::json!({
                "key": item.key,
                "value": safe_value,
                "redacted": item.redacted,
                "evidence_type": item.evidence_type,
            })
        })
        .collect();

    serde_json::json!({
        "id": pack.id,
        "request_id": pack.request_id,
        "items": items,
        "redacted": pack.redacted,
        "created_at": pack.created_at,
        "format": pack.format,
        "compliance_checks": pack.compliance_checks,
        "metadata": pack.metadata,
    })
}

/// Returns the safe export value for an evidence item.
/// - If redacted with redacted_value → uses that
/// - If redacted without redacted_value → uses safe marker
/// - If not redacted → uses original value
fn safe_export_value(item: &EvidenceItem) -> String {
    if item.redacted {
        item.redacted_value
            .clone()
            .unwrap_or_else(|| "***REDACTED***".to_string())
    } else {
        item.value.clone()
    }
}

pub fn verify_evidence_compliance(pack: &EvidencePack) -> Result<Vec<String>, String> {
    let mut checks: Vec<String> = Vec::new();

    if !pack.redacted {
        checks.push("FAIL: Evidence pack is not redacted".into());
    } else {
        checks.push("PASS: Evidence pack is redacted".into());
    }

    let total = pack.items.len();
    let redacted_count = pack.items.iter().filter(|i| i.redacted).count();
    let unredacted_count = total - redacted_count;

    checks.push(format!(
        "Evidence items: {} total, {} redacted, {} unredacted",
        total, redacted_count, unredacted_count
    ));

    for item in &pack.items {
        if item.redacted && item.redacted_value.is_none() {
            checks.push(format!(
                "FAIL: Item '{}' is marked redacted but has no redacted_value",
                item.key
            ));
        }
        if !item.redacted && should_redact(&item.key, &item.value) {
            checks.push(format!(
                "FAIL: Item '{}' contains sensitive content but is not redacted",
                item.key
            ));
        }
    }

    let has_summary = pack
        .items
        .iter()
        .any(|i| matches!(i.evidence_type, EvidenceType::Summary));
    if !has_summary {
        checks.push("WARN: No summary evidence item found".into());
    }

    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_lifecycle;

    fn make_request_with_stages() -> Request {
        let mut req = request_lifecycle::create_request(
            "windows-server-deployment",
            RequestType::ServerDeployment,
            "alice",
            "bob",
            "LOVE",
            "production",
            "critical",
        )
        .unwrap();
        req.approval_route.push("Datacenter Approver".into());
        let stages = request_lifecycle::plan_request(&req).unwrap();
        req.stages.extend(stages);
        req
    }

    #[test]
    fn test_collect_evidence_creates_redacted_pack() {
        let req = make_request_with_stages();
        let pack = collect_evidence(&req).unwrap();
        assert!(pack.redacted);
        assert!(!pack.items.is_empty());
    }

    #[test]
    fn test_redact_evidence_redacts_sensitive_keys() {
        let mut pack = EvidencePack {
            id: "ev-001".into(),
            request_id: "req-001".into(),
            items: vec![
                EvidenceItem {
                    key: "admin_password".into(),
                    value: "supersecret123".into(),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::ExecutionLog,
                },
                EvidenceItem {
                    key: "server_name".into(),
                    value: "web-server-01".into(),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::Summary,
                },
            ],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        redact_evidence(&mut pack).unwrap();

        let password_item = pack
            .items
            .iter()
            .find(|i| i.key == "admin_password")
            .unwrap();
        assert!(password_item.redacted);
        assert_eq!(password_item.redacted_value, Some("***REDACTED***".into()));

        let server_item = pack.items.iter().find(|i| i.key == "server_name").unwrap();
        assert!(!server_item.redacted);
    }

    #[test]
    fn test_redact_evidence_redacts_token_in_value() {
        let mut pack = EvidencePack {
            id: "ev-002".into(),
            request_id: "req-002".into(),
            items: vec![EvidenceItem {
                key: "config".into(),
                value: "api_token=abc123xyz".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        redact_evidence(&mut pack).unwrap();
        assert!(pack.items[0].redacted);
    }

    #[test]
    fn test_export_evidence_unredacted_fails() {
        let pack = EvidencePack {
            id: "ev-003".into(),
            request_id: "req-003".into(),
            items: Vec::new(),
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        assert!(export_evidence(&pack, "json").is_err());
    }

    #[test]
    fn test_export_evidence_json_format() {
        let pack = EvidencePack {
            id: "ev-004".into(),
            request_id: "req-004".into(),
            items: vec![EvidenceItem {
                key: "summary".into(),
                value: "All clear".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let exported = export_evidence(&pack, "json").unwrap();
        assert!(exported.contains("summary"));
        assert!(exported.contains("All clear"));
    }

    #[test]
    fn test_export_evidence_yaml_format() {
        let pack = EvidencePack {
            id: "ev-005".into(),
            request_id: "req-005".into(),
            items: vec![EvidenceItem {
                key: "summary".into(),
                value: "Test".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "yaml".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let exported = export_evidence(&pack, "yaml").unwrap();
        assert!(!exported.is_empty());
    }

    #[test]
    fn test_export_evidence_unsupported_format() {
        let pack = EvidencePack {
            id: "ev-006".into(),
            request_id: "req-006".into(),
            items: Vec::new(),
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        assert!(export_evidence(&pack, "csv").is_err());
    }

    #[test]
    fn test_verify_evidence_compliance_unredacted() {
        let pack = EvidencePack {
            id: "ev-007".into(),
            request_id: "req-007".into(),
            items: Vec::new(),
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let checks = verify_evidence_compliance(&pack).unwrap();
        assert!(checks.iter().any(|c| c.contains("not redacted")));
    }

    #[test]
    fn test_verify_evidence_compliance_redacted() {
        let pack = EvidencePack {
            id: "ev-008".into(),
            request_id: "req-008".into(),
            items: vec![EvidenceItem {
                key: "summary".into(),
                value: "Test".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let checks = verify_evidence_compliance(&pack).unwrap();
        assert!(checks.iter().any(|c| c.contains("redacted")));
    }

    #[test]
    fn test_collect_evidence_no_sensitive_data_leaked() {
        let req = make_request_with_stages();
        let pack = collect_evidence(&req).unwrap();
        let json = export_evidence(&pack, "json").unwrap();

        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("token"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("api_key"));
    }

    #[test]
    fn test_export_evidence_original_sensitive_value_excluded() {
        // RED: current export serializes full EvidencePack including raw value.
        // The export MUST NOT contain the original sensitive value.
        let pack = EvidencePack {
            id: "ev-redact-001".into(),
            request_id: "req-001".into(),
            items: vec![EvidenceItem {
                key: "admin_password".into(),
                value: "supersecret123".into(),
                redacted_value: Some("***REDACTED***".into()),
                redacted: true,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(!exported.contains("supersecret123"));
        assert!(exported.contains("***REDACTED***"));
    }

    #[test]
    fn test_export_evidence_missing_redaction_uses_safe_marker() {
        // RED: item redacted but no redacted_value — must not expose original value.
        let pack = EvidencePack {
            id: "ev-redact-002".into(),
            request_id: "req-002".into(),
            items: vec![EvidenceItem {
                key: "token_field".into(),
                value: "leaked-token-abc".into(),
                redacted_value: None,
                redacted: true,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(!exported.contains("leaked-token-abc"));
        assert!(exported.contains("***REDACTED***"));
    }

    #[test]
    fn test_export_evidence_non_sensitive_value_preserved() {
        // Non-sensitive values must remain in the export.
        let pack = EvidencePack {
            id: "ev-redact-003".into(),
            request_id: "req-003".into(),
            items: vec![EvidenceItem {
                key: "server_name".into(),
                value: "web-server-01".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(exported.contains("web-server-01"));
    }
}
