use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Any => write!(f, "ANY"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    Allow,
    Deny,
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Allow => write!(f, "Allow"),
            RuleAction::Deny => write!(f, "Deny"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

impl std::fmt::Display for RuleDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleDirection::Inbound => write!(f, "Inbound"),
            RuleDirection::Outbound => write!(f, "Outbound"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleStatus {
    Active,
    Disabled,
    PendingReview,
}

impl std::fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleStatus::Active => write!(f, "Active"),
            RuleStatus::Disabled => write!(f, "Disabled"),
            RuleStatus::PendingReview => write!(f, "PendingReview"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSetStatus {
    Draft,
    Applied,
    Revoked,
}

impl std::fmt::Display for RuleSetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetStatus::Draft => write!(f, "Draft"),
            RuleSetStatus::Applied => write!(f, "Applied"),
            RuleSetStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub source_ip: String,
    pub source_port: String,
    pub dest_ip: String,
    pub dest_port: String,
    pub protocol: Protocol,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub priority: u32,
    pub site: String,
    pub status: RuleStatus,
    pub created_by: String,
    pub created_at: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleSet {
    pub id: String,
    pub name: String,
    pub rules: Vec<String>,
    pub site: String,
    pub applied_to: String,
    pub status: RuleSetStatus,
}

type FirewallStore = (Vec<FirewallRule>, Vec<FirewallRuleSet>);

static STORE: OnceLock<Mutex<FirewallStore>> = OnceLock::new();

fn store() -> &'static Mutex<FirewallStore> {
    STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn short_id() -> String {
    Uuid::new_v4()
        .to_string()
        .split('-')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn parse_protocol(protocol: &str) -> Result<Protocol, String> {
    match protocol {
        "TCP" | "tcp" | "Tcp" => Ok(Protocol::Tcp),
        "UDP" | "udp" | "Udp" => Ok(Protocol::Udp),
        "ICMP" | "icmp" | "Icmp" => Ok(Protocol::Icmp),
        "ANY" | "any" | "Any" => Ok(Protocol::Any),
        other => Err(format!(
            "Invalid protocol: {}. Must be TCP, UDP, ICMP, or ANY",
            other
        )),
    }
}

fn parse_action(action: &str) -> Result<RuleAction, String> {
    match action {
        "Allow" | "allow" | "ALLOW" => Ok(RuleAction::Allow),
        "Deny" | "deny" | "DENY" => Ok(RuleAction::Deny),
        other => Err(format!("Invalid action: {}. Must be Allow or Deny", other)),
    }
}

fn parse_direction(direction: &str) -> Result<RuleDirection, String> {
    match direction {
        "Inbound" | "inbound" | "INBOUND" => Ok(RuleDirection::Inbound),
        "Outbound" | "outbound" | "OUTBOUND" => Ok(RuleDirection::Outbound),
        other => Err(format!(
            "Invalid direction: {}. Must be Inbound or Outbound",
            other
        )),
    }
}

fn seed_rule(
    id: &str,
    name: &str,
    source_ip: &str,
    source_port: &str,
    dest_ip: &str,
    dest_port: &str,
    protocol: Protocol,
    action: RuleAction,
    direction: RuleDirection,
    priority: u32,
    site: &str,
    status: RuleStatus,
    description: &str,
) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        name: name.into(),
        source_ip: source_ip.into(),
        source_port: source_port.into(),
        dest_ip: dest_ip.into(),
        dest_port: dest_port.into(),
        protocol,
        action,
        direction,
        priority,
        site: site.into(),
        status,
        created_by: "ryuki.engine".into(),
        created_at: now_iso(),
        description: description.into(),
    }
}

fn seed_data() -> FirewallStore {
    let rules = vec![
        seed_rule(
            "fw-defra-001",
            "Allow DEFRA web ingress",
            "10.10.0.0/24",
            "any",
            "10.10.10.20",
            "443",
            Protocol::Tcp,
            RuleAction::Allow,
            RuleDirection::Inbound,
            100,
            "DEFRA",
            RuleStatus::Active,
            "Permit HTTPS traffic to DEFRA web tier.",
        ),
        seed_rule(
            "fw-defra-002",
            "Deny DEFRA duplicate web ingress",
            "10.10.0.0/24",
            "any",
            "10.10.10.20",
            "443",
            Protocol::Tcp,
            RuleAction::Deny,
            RuleDirection::Inbound,
            110,
            "DEFRA",
            RuleStatus::PendingReview,
            "Conflicting mock rule used for review workflows.",
        ),
        seed_rule(
            "fw-defra-003",
            "Allow DEFRA DNS egress",
            "10.10.10.0/24",
            "any",
            "10.10.1.53",
            "53",
            Protocol::Udp,
            RuleAction::Allow,
            RuleDirection::Outbound,
            120,
            "DEFRA",
            RuleStatus::Active,
            "Permit DNS queries to local resolver.",
        ),
        seed_rule(
            "fw-gblon-001",
            "Allow GBLON SSH admin",
            "10.20.1.0/24",
            "any",
            "10.20.20.10",
            "22",
            Protocol::Tcp,
            RuleAction::Allow,
            RuleDirection::Inbound,
            100,
            "GBLON",
            RuleStatus::Active,
            "Permit admin SSH to bastion host.",
        ),
        seed_rule(
            "fw-gblon-002",
            "Deny GBLON database ingress",
            "0.0.0.0/0",
            "any",
            "10.20.30.15",
            "5432",
            Protocol::Tcp,
            RuleAction::Deny,
            RuleDirection::Inbound,
            90,
            "GBLON",
            RuleStatus::Active,
            "Block external PostgreSQL access.",
        ),
        seed_rule(
            "fw-gblon-003",
            "Allow GBLON monitoring",
            "10.20.50.5",
            "any",
            "10.20.0.0/16",
            "10050",
            Protocol::Tcp,
            RuleAction::Allow,
            RuleDirection::Inbound,
            130,
            "GBLON",
            RuleStatus::Disabled,
            "Mock Zabbix probe rule.",
        ),
        seed_rule(
            "fw-nlams-001",
            "Allow NLAMS ICMP diagnostics",
            "10.30.0.0/16",
            "any",
            "10.30.0.0/16",
            "any",
            Protocol::Icmp,
            RuleAction::Allow,
            RuleDirection::Inbound,
            140,
            "NLAMS",
            RuleStatus::Active,
            "Permit internal ICMP diagnostics.",
        ),
        seed_rule(
            "fw-nlams-002",
            "Deny NLAMS internet egress",
            "10.30.40.0/24",
            "any",
            "0.0.0.0/0",
            "any",
            Protocol::Any,
            RuleAction::Deny,
            RuleDirection::Outbound,
            80,
            "NLAMS",
            RuleStatus::Active,
            "Block broad outbound internet traffic.",
        ),
        seed_rule(
            "fw-frpar-001",
            "Allow FRPAR API ingress",
            "10.40.1.0/24",
            "any",
            "10.40.20.30",
            "8443",
            Protocol::Tcp,
            RuleAction::Allow,
            RuleDirection::Inbound,
            100,
            "FRPAR",
            RuleStatus::Active,
            "Permit partner API traffic.",
        ),
        seed_rule(
            "fw-deber-001",
            "Allow DEBER backup egress",
            "10.50.10.0/24",
            "any",
            "10.50.200.20",
            "9100",
            Protocol::Tcp,
            RuleAction::Allow,
            RuleDirection::Outbound,
            100,
            "DEBER",
            RuleStatus::PendingReview,
            "Draft backup appliance egress rule.",
        ),
    ];

    let rule_sets = vec![
        FirewallRuleSet {
            id: "fws-defra-001".into(),
            name: "DEFRA web edge policy".into(),
            rules: vec!["fw-defra-001".into(), "fw-defra-002".into()],
            site: "DEFRA".into(),
            applied_to: "defra-edge-fw-01".into(),
            status: RuleSetStatus::Draft,
        },
        FirewallRuleSet {
            id: "fws-gblon-001".into(),
            name: "GBLON core protection".into(),
            rules: vec!["fw-gblon-001".into(), "fw-gblon-002".into()],
            site: "GBLON".into(),
            applied_to: "10.20.0.0/16".into(),
            status: RuleSetStatus::Applied,
        },
        FirewallRuleSet {
            id: "fws-nlams-001".into(),
            name: "NLAMS diagnostics policy".into(),
            rules: vec!["fw-nlams-001".into(), "fw-nlams-002".into()],
            site: "NLAMS".into(),
            applied_to: "nlams-core-fw-01".into(),
            status: RuleSetStatus::Revoked,
        },
    ];

    (rules, rule_sets)
}

pub fn list_rules(site: &str, direction: &str) -> Result<Value, String> {
    let direction_filter = if direction.trim().is_empty() {
        None
    } else {
        Some(parse_direction(direction)?)
    };

    let store = store().lock().unwrap();
    let rules: Vec<FirewallRule> = store
        .0
        .iter()
        .filter(|rule| site.is_empty() || rule.site == site)
        .filter(|rule| {
            direction_filter
                .as_ref()
                .is_none_or(|direction| rule.direction == *direction)
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "rules": rules,
        "count": rules.len()
    }))
}

pub fn get_rule(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let rule = store
        .0
        .iter()
        .find(|rule| rule.id == id)
        .cloned()
        .ok_or_else(|| format!("Firewall rule '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "rule": rule
    }))
}

pub fn create_rule(
    name: &str,
    source_ip: &str,
    dest_ip: &str,
    protocol: &str,
    action: &str,
    direction: &str,
    site: &str,
    description: &str,
) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if source_ip.trim().is_empty() {
        return Err("source_ip cannot be empty".into());
    }
    if dest_ip.trim().is_empty() {
        return Err("dest_ip cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let protocol = parse_protocol(protocol)?;
    let action = parse_action(action)?;
    let direction = parse_direction(direction)?;

    let mut store = store().lock().unwrap();
    let priority = store
        .0
        .iter()
        .filter(|rule| rule.site == site)
        .map(|rule| rule.priority)
        .max()
        .unwrap_or(0)
        + 10;
    let id = format!("fw-{}-{}", site.to_lowercase(), short_id());
    let rule = FirewallRule {
        id: id.clone(),
        name: name.into(),
        source_ip: source_ip.into(),
        source_port: "any".into(),
        dest_ip: dest_ip.into(),
        dest_port: "any".into(),
        protocol,
        action,
        direction,
        priority,
        site: site.into(),
        status: RuleStatus::PendingReview,
        created_by: "ryuki.engine".into(),
        created_at: now_iso(),
        description: description.into(),
    };

    store.0.push(rule.clone());

    Ok(json!({
        "source": "dry-run",
        "rule": rule
    }))
}

pub fn update_rule(id: &str, action: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let rule = store
        .0
        .iter_mut()
        .find(|rule| rule.id == id)
        .ok_or_else(|| format!("Firewall rule '{}' not found", id))?;

    match action {
        "Allow" | "allow" | "ALLOW" | "Deny" | "deny" | "DENY" => {
            rule.action = parse_action(action)?;
        }
        "Enable" | "enable" | "ENABLE" | "Active" | "active" | "ACTIVE" => {
            rule.status = RuleStatus::Active;
        }
        "Disable" | "disable" | "DISABLE" | "Disabled" | "disabled" | "DISABLED" => {
            rule.status = RuleStatus::Disabled;
        }
        other => {
            return Err(format!(
                "Invalid update action: {}. Must be Allow, Deny, Enable, or Disable",
                other
            ));
        }
    }

    Ok(json!({
        "source": "dry-run",
        "rule": rule.clone()
    }))
}

pub fn delete_rule(id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let position = store
        .0
        .iter()
        .position(|rule| rule.id == id)
        .ok_or_else(|| format!("Firewall rule '{}' not found", id))?;
    let deleted = store.0.remove(position);

    for rule_set in &mut store.1 {
        rule_set.rules.retain(|rule_id| rule_id != id);
    }

    Ok(json!({
        "source": "dry-run",
        "deleted_rule_id": deleted.id,
        "status": "deleted"
    }))
}

pub fn validate_rule(
    name: &str,
    source_ip: &str,
    dest_ip: &str,
    protocol: &str,
) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if source_ip.trim().is_empty() {
        return Err("source_ip cannot be empty".into());
    }
    if dest_ip.trim().is_empty() {
        return Err("dest_ip cannot be empty".into());
    }

    let protocol = parse_protocol(protocol)?;
    let store = store().lock().unwrap();
    let conflicts: Vec<FirewallRule> = store
        .0
        .iter()
        .filter(|rule| {
            rule.name == name
                || (rule.source_ip == source_ip
                    && rule.dest_ip == dest_ip
                    && (rule.protocol == protocol
                        || rule.protocol == Protocol::Any
                        || protocol == Protocol::Any))
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "valid": conflicts.is_empty(),
        "conflicts": conflicts
    }))
}

pub fn create_rule_set(
    name: &str,
    rule_ids: Vec<String>,
    site: &str,
    target: &str,
) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if rule_ids.is_empty() {
        return Err("rule_ids cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    if target.trim().is_empty() {
        return Err("target cannot be empty".into());
    }

    let mut store = store().lock().unwrap();
    for rule_id in &rule_ids {
        let exists = store
            .0
            .iter()
            .any(|rule| rule.id == *rule_id && rule.site == site);
        if !exists {
            return Err(format!(
                "Firewall rule '{}' not found for site '{}'",
                rule_id, site
            ));
        }
    }

    let rule_set = FirewallRuleSet {
        id: format!("fws-{}-{}", site.to_lowercase(), short_id()),
        name: name.into(),
        rules: rule_ids,
        site: site.into(),
        applied_to: target.into(),
        status: RuleSetStatus::Draft,
    };

    store.1.push(rule_set.clone());

    Ok(json!({
        "source": "dry-run",
        "rule_set": rule_set
    }))
}

pub fn apply_rule_set(id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let rule_set = store
        .1
        .iter_mut()
        .find(|rule_set| rule_set.id == id)
        .ok_or_else(|| format!("Firewall rule set '{}' not found", id))?;

    if rule_set.status == RuleSetStatus::Revoked {
        return Err(format!("Cannot apply revoked rule set '{}'", id));
    }

    rule_set.status = RuleSetStatus::Applied;

    Ok(json!({
        "source": "dry-run",
        "rule_set": rule_set.clone()
    }))
}

pub fn revoke_rule_set(id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let rule_set = store
        .1
        .iter_mut()
        .find(|rule_set| rule_set.id == id)
        .ok_or_else(|| format!("Firewall rule set '{}' not found", id))?;

    rule_set.status = RuleSetStatus::Revoked;

    Ok(json!({
        "source": "dry-run",
        "rule_set": rule_set.clone()
    }))
}

pub fn get_conflicts(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let site_rules: Vec<&FirewallRule> = store
        .0
        .iter()
        .filter(|rule| site.is_empty() || rule.site == site)
        .collect();
    let mut conflicts = Vec::new();

    for (index, left) in site_rules.iter().enumerate() {
        for right in site_rules.iter().skip(index + 1) {
            if left.direction == right.direction
                && left.source_ip == right.source_ip
                && left.dest_ip == right.dest_ip
                && (left.protocol == right.protocol
                    || left.protocol == Protocol::Any
                    || right.protocol == Protocol::Any)
                && left.action != right.action
            {
                conflicts.push(json!({
                    "site": left.site,
                    "rule_ids": [left.id, right.id],
                    "reason": "overlapping rules have conflicting actions"
                }));
            }
        }
    }

    Ok(json!({
        "source": "dry-run",
        "conflicts": conflicts,
        "count": conflicts.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_list_rules() {
        let name = format!("Test list rule {}", short_id());
        let created = create_rule(
            &name,
            "192.0.2.10",
            "198.51.100.10",
            "TCP",
            "Allow",
            "Inbound",
            "FRPAR",
            "Test rule for list workflow.",
        )
        .unwrap();

        assert_eq!(created["source"], "dry-run");
        assert_eq!(created["rule"]["name"], name);

        let listed = list_rules("FRPAR", "Inbound").unwrap();
        assert_eq!(listed["source"], "dry-run");
        assert!(listed["rules"].as_array().unwrap().iter().any(|rule| {
            rule["id"] == created["rule"]["id"] && rule["name"] == created["rule"]["name"]
        }));
    }

    #[test]
    fn test_update_rule_action() {
        let created = create_rule(
            &format!("Test update rule {}", short_id()),
            "192.0.2.20",
            "198.51.100.20",
            "UDP",
            "Allow",
            "Outbound",
            "DEBER",
            "Test rule for update workflow.",
        )
        .unwrap();
        let id = created["rule"]["id"].as_str().unwrap();

        let updated = update_rule(id, "Deny").unwrap();
        assert_eq!(updated["rule"]["action"], "deny");
    }

    #[test]
    fn test_validate_rule_duplicate_detection() {
        let validation = validate_rule(
            "Allow DEFRA web ingress",
            "10.10.0.0/24",
            "10.10.10.20",
            "TCP",
        )
        .unwrap();

        assert_eq!(validation["source"], "dry-run");
        assert_eq!(validation["valid"], false);
        assert!(!validation["conflicts"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_create_and_apply_rule_set() {
        let rule = create_rule(
            &format!("Test set rule {}", short_id()),
            "192.0.2.30",
            "198.51.100.30",
            "TCP",
            "Allow",
            "Inbound",
            "GBLON",
            "Test rule for rule set workflow.",
        )
        .unwrap();
        let rule_id = rule["rule"]["id"].as_str().unwrap().to_string();

        let rule_set = create_rule_set(
            &format!("Test rule set {}", short_id()),
            vec![rule_id],
            "GBLON",
            "gblon-test-fw-01",
        )
        .unwrap();
        let rule_set_id = rule_set["rule_set"]["id"].as_str().unwrap();

        let applied = apply_rule_set(rule_set_id).unwrap();
        assert_eq!(applied["source"], "dry-run");
        assert_eq!(applied["rule_set"]["status"], "applied");
    }

    #[test]
    fn test_revoke_rule_set() {
        let rule_set = create_rule_set(
            &format!("Test revoke set {}", short_id()),
            vec!["fw-nlams-001".into()],
            "NLAMS",
            "nlams-test-fw-01",
        )
        .unwrap();
        let rule_set_id = rule_set["rule_set"]["id"].as_str().unwrap();

        let revoked = revoke_rule_set(rule_set_id).unwrap();
        assert_eq!(revoked["source"], "dry-run");
        assert_eq!(revoked["rule_set"]["status"], "revoked");
    }

    #[test]
    fn test_get_conflicts() {
        let conflicts = get_conflicts("DEFRA").unwrap();
        assert_eq!(conflicts["source"], "dry-run");
        assert!(conflicts["count"].as_u64().unwrap() >= 1);
        assert!(!conflicts["conflicts"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_delete_rule() {
        let rule = create_rule(
            &format!("Test delete rule {}", short_id()),
            "192.0.2.40",
            "198.51.100.40",
            "ICMP",
            "Allow",
            "Inbound",
            "DEFRA",
            "Test rule for delete workflow.",
        )
        .unwrap();
        let rule_id = rule["rule"]["id"].as_str().unwrap();

        let deleted = delete_rule(rule_id).unwrap();
        assert_eq!(deleted["source"], "dry-run");
        assert_eq!(deleted["deleted_rule_id"], rule_id);
        assert!(get_rule(rule_id).is_err());
    }

    #[test]
    fn test_update_rule_enable_disable() {
        let rule = create_rule(
            &format!("Test status rule {}", short_id()),
            "192.0.2.50",
            "198.51.100.50",
            "TCP",
            "Allow",
            "Inbound",
            "DEFRA",
            "Test rule for status workflow.",
        )
        .unwrap();
        let rule_id = rule["rule"]["id"].as_str().unwrap();

        let disabled = update_rule(rule_id, "Disable").unwrap();
        assert_eq!(disabled["rule"]["status"], "disabled");

        let enabled = update_rule(rule_id, "Enable").unwrap();
        assert_eq!(enabled["rule"]["status"], "active");
    }
}
