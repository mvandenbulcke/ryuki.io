use ryuki_core::PrincipalId;
use serde::{Deserialize, Serialize};

pub const APP_ROLE_PLATFORM_ADMIN: &str = "PlatformAdmin";
pub const APP_ROLE_DATACENTER_APPROVER: &str = "DatacenterApprover";
pub const APP_ROLE_VMWARE_OPERATOR: &str = "VMwareOperator";
pub const APP_ROLE_HYPERV_OPERATOR: &str = "HyperVOperator";
pub const APP_ROLE_PROXMOX_OPERATOR: &str = "ProxmoxOperator";
pub const APP_ROLE_WINTEL_LINUX_OPERATOR: &str = "WintelLinuxOperator";
pub const APP_ROLE_BACKUP_OPERATOR: &str = "BackupOperator";
pub const APP_ROLE_MONITORING_OPERATOR: &str = "MonitoringOperator";
pub const APP_ROLE_SERVICE_DESK: &str = "ServiceDesk";
pub const APP_ROLE_AUDITOR: &str = "Auditor";
pub const APP_ROLE_REQUESTER: &str = "Requester";
pub const APP_ROLE_BREAK_GLASS_ADMIN: &str = "BreakGlassAdmin";

pub const ALL_APP_ROLES: &[&str] = &[
    APP_ROLE_PLATFORM_ADMIN,
    APP_ROLE_DATACENTER_APPROVER,
    APP_ROLE_VMWARE_OPERATOR,
    APP_ROLE_HYPERV_OPERATOR,
    APP_ROLE_PROXMOX_OPERATOR,
    APP_ROLE_WINTEL_LINUX_OPERATOR,
    APP_ROLE_BACKUP_OPERATOR,
    APP_ROLE_MONITORING_OPERATOR,
    APP_ROLE_SERVICE_DESK,
    APP_ROLE_AUDITOR,
    APP_ROLE_REQUESTER,
    APP_ROLE_BREAK_GLASS_ADMIN,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub instance: String,
    pub enabled: bool,
}

impl Default for EntraConfig {
    fn default() -> Self {
        Self {
            tenant_id: "placeholder-tenant-id".to_string(),
            client_id: "placeholder-client-id".to_string(),
            instance: "https://login.microsoftonline.com".to_string(),
            enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacRole {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    /// Provider-neutral functional domains published to access-control clients.
    /// These are descriptive policy axes; protected mutations are enforced by
    /// the typed `capabilities` registry below rather than by string matching.
    #[serde(default)]
    pub execution_domains: Vec<String>,
    /// Closed, server-owned operation grants. Identity providers contribute only
    /// verified role names; callers can never supply these capabilities directly.
    #[serde(default)]
    pub capabilities: Vec<OperationCapability>,
}

/// Functional grants that must not be implied by coarse permissions such as
/// `request`, `audit`, or `execute`. Keeping these as a closed enum prevents a
/// typo or a newly added route from silently becoming an authorization grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationCapability {
    #[serde(rename = "identity.ad-computer.delete")]
    IdentityAdComputerDelete,
    #[serde(rename = "network.firewall.manage")]
    NetworkFirewallManage,
    #[serde(rename = "monitoring.alert-routing.manage")]
    MonitoringAlertRoutingManage,
    #[serde(rename = "monitoring.alert.read")]
    MonitoringAlertRead,
    #[serde(rename = "monitoring.alert.acknowledge")]
    MonitoringAlertAcknowledge,
    #[serde(rename = "storage.array.decommission")]
    StorageArrayDecommission,
    #[serde(rename = "software.deployment.execute")]
    SoftwareDeploymentExecute,
}

impl OperationCapability {
    pub const ALL: [Self; 7] = [
        Self::IdentityAdComputerDelete,
        Self::NetworkFirewallManage,
        Self::MonitoringAlertRoutingManage,
        Self::MonitoringAlertRead,
        Self::MonitoringAlertAcknowledge,
        Self::StorageArrayDecommission,
        Self::SoftwareDeploymentExecute,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityAdComputerDelete => "identity.ad-computer.delete",
            Self::NetworkFirewallManage => "network.firewall.manage",
            Self::MonitoringAlertRoutingManage => "monitoring.alert-routing.manage",
            Self::MonitoringAlertRead => "monitoring.alert.read",
            Self::MonitoringAlertAcknowledge => "monitoring.alert.acknowledge",
            Self::StorageArrayDecommission => "storage.array.decommission",
            Self::SoftwareDeploymentExecute => "software.deployment.execute",
        }
    }
}

/// Server-attested class of the credential actor behind an admitted request.
///
/// This is deliberately provider-neutral: an interactive identity is a human
/// only after its credential kind and exact governed assignment have both been
/// validated. Role names, provider labels, display names, and token validity do
/// not establish human provenance. Unknown is the fail-closed default so older
/// constructors and deserialized payloads cannot acquire sign-off authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorClass {
    VerifiedHuman,
    Workload,
    Simulated,
    #[default]
    Unknown,
}

impl ActorClass {
    /// Stable persistence spelling for evidence records. Keep this aligned
    /// with the serde representation and database CHECK constraints.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedHuman => "verified-human",
            Self::Workload => "workload",
            Self::Simulated => "simulated",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthSession {
    /// Compatibility projection exposed under the historical `user_id` wire
    /// key. Admitted sessions project their opaque principal UUID here;
    /// unverified and simulated sessions use fixed non-authoritative labels.
    /// Security decisions must never read this string.
    #[serde(rename = "user_id")]
    pub display_user_id: String,
    /// Stable, provider-independent authority for an admitted session.
    ///
    /// It is deliberately excluded from serialized session projections so a
    /// caller cannot turn a UUID-shaped provider subject or display value into
    /// authority by deserializing an `AuthSession`. Admission code alone sets
    /// this field after validating an exact principal/key/link binding. `None`
    /// is the fail-closed state for unverified projections.
    #[serde(skip)]
    pub principal_id: Option<PrincipalId>,
    pub display_name: String,
    pub roles: Vec<String>,
    pub token_valid: bool,
    pub provider_mode: String,
    /// Internal admission evidence. It is never accepted from or emitted to a
    /// serialized session seam; every request must re-establish it through the
    /// credential-specific authority boundary.
    #[serde(skip)]
    pub actor_class: ActorClass,
    /// Effective authorized SITE scopes for this principal (#2). EMPTY means
    /// Global only after the credential-specific admission boundary has proved
    /// an explicit Global grant (API-token policy, interactive assignment, or
    /// isolated static development identity). Interactive Unknown/Revoked
    /// authority never produces a verified `AuthSession`; scoped browser
    /// sessions persist and reload this effective list.
    ///
    /// `skip_serializing_if` empty keeps the canonical `/me` seam shape unchanged
    /// for the common UNSCOPED case (the keys appear only when a scope is set),
    /// while `default` lets older payloads without the keys deserialize cleanly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub site_scope: Vec<String>,
    /// Effective ENVIRONMENT scopes. EMPTY has the same admitted-Global
    /// meaning as `site_scope`; it is never an Unknown fallback.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_scope: Vec<String>,
}

impl AuthSession {
    pub fn static_dry_run() -> Self {
        Self {
            display_user_id: "static-user".to_string(),
            display_name: "Platform Operator (Static)".to_string(),
            roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: false,
            provider_mode: "static-dry-run".to_string(),
            actor_class: ActorClass::Simulated,
            ..Self::default()
        }
    }

    pub fn unverified_entra() -> Self {
        Self {
            display_user_id: "unverified-entra-user".to_string(),
            display_name: "Unverified Entra ID User".to_string(),
            roles: vec![],
            token_valid: false,
            provider_mode: "entra-id-unverified".to_string(),
            ..Self::default()
        }
    }

    /// Whether this request carries fresh server-side proof of an admitted
    /// human actor. Token validity remains an independent mandatory condition.
    pub const fn is_verified_human(&self) -> bool {
        self.principal_id.is_some()
            && self.token_valid
            && matches!(self.actor_class, ActorClass::VerifiedHuman)
    }
}

pub fn get_rbac_roles() -> Vec<RbacRole> {
    vec![
        RbacRole {
            name: APP_ROLE_PLATFORM_ADMIN.to_string(),
            description:
                "Platform Admins — full platform administration, approval, and audit access"
                    .to_string(),
            permissions: vec![
                "admin".to_string(),
                "approve".to_string(),
                "audit".to_string(),
            ],
            execution_domains: vec![
                "platform".to_string(),
                "governance".to_string(),
                "emergency".to_string(),
            ],
            capabilities: OperationCapability::ALL.to_vec(),
        },
        RbacRole {
            name: APP_ROLE_DATACENTER_APPROVER.to_string(),
            description: "Approvers — datacenter-level approval and audit".to_string(),
            permissions: vec!["approve".to_string(), "audit".to_string()],
            execution_domains: vec![
                "datacenter".to_string(),
                "capacity".to_string(),
                "live-execution-final".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_VMWARE_OPERATOR.to_string(),
            description: "VMware Operators — virtualization execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
            execution_domains: vec![
                "vmware".to_string(),
                "placement".to_string(),
                "lifecycle".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_HYPERV_OPERATOR.to_string(),
            description: "Hyper-V Operators — virtualization execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
            execution_domains: vec![
                "hyper-v".to_string(),
                "placement".to_string(),
                "lifecycle".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_PROXMOX_OPERATOR.to_string(),
            description: "Proxmox Operators — virtualization execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
            execution_domains: vec![
                "proxmox".to_string(),
                "placement".to_string(),
                "lifecycle".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_WINTEL_LINUX_OPERATOR.to_string(),
            description: "Wintel/Linux Operators — OS execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
            execution_domains: vec![
                "windows".to_string(),
                "linux".to_string(),
                "patching".to_string(),
                "baseline".to_string(),
                "software-deployment".to_string(),
            ],
            capabilities: vec![OperationCapability::SoftwareDeploymentExecute],
        },
        RbacRole {
            name: APP_ROLE_BACKUP_OPERATOR.to_string(),
            description: "Backup Operators — backup execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
            execution_domains: vec![
                "backup".to_string(),
                "restore".to_string(),
                "dr".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_MONITORING_OPERATOR.to_string(),
            description: "Monitoring Operators — monitoring execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
            execution_domains: vec![
                "monitoring".to_string(),
                "alert-routing".to_string(),
                "maintenance-window".to_string(),
            ],
            capabilities: vec![
                OperationCapability::MonitoringAlertRoutingManage,
                OperationCapability::MonitoringAlertRead,
                OperationCapability::MonitoringAlertAcknowledge,
            ],
        },
        RbacRole {
            name: APP_ROLE_SERVICE_DESK.to_string(),
            description: "Service Desk — triage, request, and audit access".to_string(),
            permissions: vec!["request".to_string(), "audit".to_string()],
            execution_domains: vec![
                "approved-runbook".to_string(),
                "incident-context".to_string(),
                "handover".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_AUDITOR.to_string(),
            description: "Auditor — read-only audit access".to_string(),
            permissions: vec!["audit".to_string()],
            execution_domains: vec![
                "evidence-review".to_string(),
                "export-review".to_string(),
                "compliance".to_string(),
            ],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_REQUESTER.to_string(),
            description: "Requester — request-only access".to_string(),
            permissions: vec!["request".to_string()],
            execution_domains: vec!["request-intake".to_string(), "evidence-view".to_string()],
            capabilities: vec![],
        },
        RbacRole {
            name: APP_ROLE_BREAK_GLASS_ADMIN.to_string(),
            description: "Break-Glass — emergency administration and audit".to_string(),
            permissions: vec!["admin".to_string(), "audit".to_string()],
            execution_domains: vec!["emergency".to_string()],
            capabilities: OperationCapability::ALL.to_vec(),
        },
    ]
}

#[cfg(test)]
fn get_untrusted_roles_from_token(token: &str) -> Vec<String> {
    if token.is_empty() {
        return vec![];
    }
    let body = if let Some(payload) = token.split('.').nth(1) {
        payload
    } else {
        return vec![];
    };
    let decoded = base64_decode_url_safe(body);
    if decoded.is_empty() {
        return vec![];
    }
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&decoded)
        && let Some(roles) = json.get("roles").and_then(|r| r.as_array())
    {
        return roles
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    vec![]
}

#[cfg(test)]
fn base64_decode_url_safe(input: &str) -> String {
    let mut s = input.to_string();
    s = s.replace('-', "+").replace('_', "/");
    let padding = (4 - (s.len() % 4)) % 4;
    s.push_str(&"=".repeat(padding));
    String::from_utf8(base64_decode_internal(&s).unwrap_or_default()).unwrap_or_default()
}

#[cfg(test)]
fn base64_decode_internal(input: &str) -> Option<Vec<u8>> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for c in input.chars() {
        if c == '=' {
            break;
        }
        let idx = alphabet.find(c)? as u32;
        buffer = (buffer << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Returns true when the session is authorized for `permission`.
///
/// A permission `p` is satisfied if the session holds `p` exactly OR the
/// session holds the `admin` permission. `admin` is therefore a superuser
/// permission: PlatformAdmin and BreakGlassAdmin both carry it and thus pass
/// every coarse permission (request/execute/approve/admin) in this wave. The
/// check is keyed on the held PERMISSION, not the role name, so it stays
/// role-name-agnostic — any future role that carries `admin` inherits the same
/// superuser semantics, and a role that merely holds `audit` never leaks into
/// the mutating permissions.
pub fn check_permission(session: &AuthSession, permission: &str) -> bool {
    let admitted_actor = session.principal_id.is_some()
        && session.token_valid
        && matches!(
            session.actor_class,
            ActorClass::VerifiedHuman | ActorClass::Workload
        );
    // Credential-free modes retain their historical coarse RBAC only for an
    // explicitly labelled dry-run projection. This branch cannot create human
    // approval evidence and never grants authority to a token-bearing or
    // provider-backed unverified session.
    let simulated_dry_run = session.principal_id.is_none()
        && matches!(session.actor_class, ActorClass::Simulated)
        && !session.token_valid
        && matches!(
            session.provider_mode.as_str(),
            "static-dry-run" | "mock-dry-run"
        );
    if !admitted_actor && !simulated_dry_run {
        return false;
    }
    // `approve` represents durable human judgment. An admin-capable workload
    // may still perform explicitly authorized machine operations, but it can
    // never satisfy an approval role resolution or create human evidence.
    if permission == "approve" && !session.is_verified_human() {
        return false;
    }
    let roles = get_rbac_roles();
    let mut held = std::collections::HashSet::new();
    for role_name in &session.roles {
        if let Some(role) = roles.iter().find(|r| &r.name == role_name) {
            held.extend(role.permissions.iter().map(String::as_str));
        }
    }
    held.contains("admin") || held.contains(permission)
}

/// Defense-in-depth for sign-off sinks that use a permission other than the
/// ordinary `approve` tier (for example an admin-only live-apply grant).
pub fn check_human_signoff_permission(session: &AuthSession, permission: &str) -> bool {
    session.is_verified_human() && check_permission(session, permission)
}

/// Returns whether a verified session's server-resolved roles grant a typed
/// functional operation. Generic `execute` never satisfies this check. The
/// existing `admin` permission remains the explicit superuser override for
/// PlatformAdmin, BreakGlassAdmin, and any future governed admin role.
pub fn check_operation_capability(session: &AuthSession, capability: OperationCapability) -> bool {
    if check_permission(session, "admin") {
        return true;
    }
    let roles = get_rbac_roles();
    session.roles.iter().any(|role_name| {
        roles
            .iter()
            .find(|role| &role.name == role_name)
            .is_some_and(|role| role.capabilities.contains(&capability))
    })
}

/// Whether a principal whose authorized scopes are `scopes` may act on the
/// `requested` scope value (a site or an environment). The verified building
/// block for site/env-scoped RBAC (#2): the API persists per-token
/// site_scope/environment_scope but does not yet enforce them, letting a
/// scoped operator read another scope's data via `?site=`.
///
/// Rules (deny-by-default once a scope is set):
/// - EMPTY `scopes` ⇒ UNRESTRICTED — permits any request (the common
///   admin/operator case with no scoping configured).
/// - `requested == None` ⇒ permitted — a request that does not name a scope is
///   not constrained by this check (the handler may still apply its own
///   default-scope logic).
/// - otherwise the (trimmed) requested value must be one of the (trimmed)
///   authorized scopes; the match is case-SENSITIVE (site/env identifiers are
///   canonical, e.g. `GBLON`, `production`).
///
/// Pure; the API resolves the principal's scopes and the requested value and
/// passes them in.
pub fn scope_permits(scopes: &[String], requested: Option<&str>) -> bool {
    if scopes.is_empty() {
        return true;
    }
    match requested {
        None => true,
        Some(req) => {
            let req = req.trim();
            scopes.iter().any(|s| s.trim() == req)
        }
    }
}

/// The effective filter to query with after enforcing a principal's scopes (#2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeFilter {
    /// Proceed using this effective filter value. `None` (no filter / all
    /// scopes) is only ever returned for an UNRESTRICTED principal — a scoped
    /// principal is always narrowed to a concrete in-scope value.
    Allow(Option<String>),
    /// The principal requested a scope it does not hold, or omitted the scope
    /// while holding several distinct ones — deny the read (403).
    Deny,
}

/// Resolve the EFFECTIVE scope filter for a principal whose authorized scopes
/// are `scopes`, given the `requested` filter value (`?site` / `?environment`).
///
/// This is the enforcement counterpart to [`scope_permits`]. Where
/// `scope_permits` only answers yes/no for an explicit value, this also closes
/// the omitted-filter leak: a scoped principal that omits the filter must NOT
/// fall through to an unfiltered (all-scopes) read. Instead it is narrowed to
/// its own scope when that is unambiguous.
///
/// Rules (deny-by-default once a scope is set):
/// - UNRESTRICTED (`scopes` has no non-blank entry) ⇒ `Allow(requested)` — the
///   requested value passes through verbatim (trimmed; blank ⇒ `None`).
/// - explicit `requested` in scope ⇒ `Allow(Some(requested))`.
/// - explicit `requested` out of scope ⇒ `Deny`.
/// - omitted `requested` with exactly ONE distinct authorized scope ⇒
///   `Allow(Some(that scope))` — narrow the read to the principal's own scope.
/// - omitted `requested` with MULTIPLE distinct authorized scopes ⇒ `Deny` — the
///   single-value filter cannot express a set, so the principal must name one
///   in-scope value explicitly. Scopes are trimmed and DEDUPLICATED first, so a
///   token whose only scope is repeated (e.g. `["GBLON", " GBLON "]`) still
///   narrows rather than denying.
///
/// Pure; the API resolves the principal's scopes and requested value and passes
/// them in.
pub fn resolve_scope_filter(scopes: &[String], requested: Option<&str>) -> ScopeFilter {
    // Trim + drop blanks so a `?site=` with whitespace behaves like omission.
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    // Distinct, trimmed, non-blank authorized scopes. An all-blank scope set has
    // no usable scope and collapses to the unrestricted case (this cannot arise
    // from a real token — `parse_token_scope` strips blanks to an empty Vec).
    let mut distinct: Vec<&str> = scopes
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    distinct.sort_unstable();
    distinct.dedup();
    let Some(&first) = distinct.first() else {
        // No usable scope ⇒ unrestricted: pass the requested value through.
        return ScopeFilter::Allow(requested.map(str::to_string));
    };
    match requested {
        Some(req) => {
            if distinct.contains(&req) {
                ScopeFilter::Allow(Some(req.to_string()))
            } else {
                ScopeFilter::Deny
            }
        }
        None if distinct.len() > 1 => ScopeFilter::Deny,
        None => ScopeFilter::Allow(Some(first.to_string())),
    }
}

pub fn get_entra_config_from_env(tenant_id: &str, client_id: &str, instance: &str) -> EntraConfig {
    let enabled = !tenant_id.is_empty() && !client_id.is_empty();
    EntraConfig {
        tenant_id: if enabled {
            tenant_id.to_string()
        } else {
            "placeholder-tenant-id".to_string()
        },
        client_id: if enabled {
            client_id.to_string()
        } else {
            "placeholder-client-id".to_string()
        },
        instance: instance.to_string(),
        enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_principal_id() -> PrincipalId {
        "11111111-1111-4111-8111-111111111111"
            .parse()
            .expect("canonical non-nil test principal")
    }

    #[test]
    fn test_default_entra_config_is_disabled() {
        let config = EntraConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.tenant_id, "placeholder-tenant-id");
        assert_eq!(config.client_id, "placeholder-client-id");
        assert_eq!(config.instance, "https://login.microsoftonline.com");
    }

    #[test]
    fn test_static_session_has_expected_roles() {
        let session = AuthSession::static_dry_run();
        assert_eq!(session.display_user_id, "static-user");
        assert_eq!(session.principal_id, None);
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "static-dry-run");
        assert!(session.roles.contains(&APP_ROLE_PLATFORM_ADMIN.to_string()));
        assert_eq!(session.roles.len(), 1);
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "request"));
        assert!(!check_permission(&session, "approve"));
    }

    #[test]
    fn test_unverified_entra_session_has_no_roles() {
        let session = AuthSession::unverified_entra();
        assert_eq!(session.display_user_id, "unverified-entra-user");
        assert_eq!(session.principal_id, None);
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "entra-id-unverified");
        assert!(session.roles.is_empty());
    }

    #[test]
    fn test_check_permission_returns_true_for_matching_role() {
        let session = verified_human_for_role(APP_ROLE_PLATFORM_ADMIN);
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "audit"));
    }

    #[test]
    fn test_check_permission_returns_false_for_non_matching_role() {
        let session = session_for_role(APP_ROLE_REQUESTER);
        assert!(check_permission(&session, "request"));
        assert!(!check_permission(&session, "admin"));
        assert!(!check_permission(&session, "execute"));
    }

    #[test]
    fn test_check_permission_empty_roles() {
        let mut session = session_for_role(APP_ROLE_REQUESTER);
        session.roles = vec![];
        assert!(!check_permission(&session, "admin"));
        assert!(!check_permission(&session, "audit"));
    }

    #[test]
    fn test_all_12_app_roles_have_valid_entries() {
        let roles = get_rbac_roles();
        assert_eq!(roles.len(), 12);
        for role in &roles {
            assert!(
                ALL_APP_ROLES.contains(&role.name.as_str()),
                "role '{}' not in ALL_APP_ROLES",
                role.name
            );
            assert!(!role.name.is_empty());
            assert!(!role.permissions.is_empty());
            assert!(!role.description.is_empty());
        }
    }

    #[test]
    fn test_get_untrusted_roles_from_token_empty_or_junk() {
        assert!(get_untrusted_roles_from_token("").is_empty());
        assert!(get_untrusted_roles_from_token("garbage").is_empty());
    }

    #[test]
    fn test_get_untrusted_roles_from_token_extracts_roles_claim() {
        let header = base64_url_encode(r#"{"alg":"RS256"}"#);
        let payload = base64_url_encode(r#"{"roles":["PlatformAdmin","Auditor"]}"#);
        let token = format!("{}.{}", header, payload);
        let roles = get_untrusted_roles_from_token(&token);
        assert_eq!(roles, vec!["PlatformAdmin", "Auditor"]);
    }

    #[test]
    fn test_get_untrusted_roles_from_token_no_roles_claim() {
        let header = base64_url_encode(r#"{"alg":"RS256"}"#);
        let payload = base64_url_encode(r#"{"sub":"user123"}"#);
        let token = format!("{}.{}", header, payload);
        assert!(get_untrusted_roles_from_token(&token).is_empty());
    }

    fn base64_url_encode(input: &str) -> String {
        let bytes = input.as_bytes();
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;

        for &b in bytes {
            buffer = (buffer << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(
                    alphabet
                        .chars()
                        .nth(((buffer >> bits) & 0x3F) as usize)
                        .unwrap(),
                );
            }
        }
        if bits > 0 {
            out.push(
                alphabet
                    .chars()
                    .nth(((buffer << (6 - bits)) & 0x3F) as usize)
                    .unwrap(),
            );
        }
        while !out.len().is_multiple_of(4) {
            out.push('=');
        }
        out.replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string()
    }

    #[test]
    fn test_auth_session_serialization_round_trip() {
        let session = verified_human_for_role(APP_ROLE_PLATFORM_ADMIN);
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: AuthSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.principal_id, None);
        assert_eq!(session.display_user_id, deserialized.display_user_id);
        assert_eq!(session.display_name, deserialized.display_name);
        assert_eq!(session.roles, deserialized.roles);
        assert_eq!(session.token_valid, deserialized.token_valid);
        assert_eq!(session.provider_mode, deserialized.provider_mode);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["user_id"].as_str(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert!(value.get("principal_id").is_none());
        assert!(!check_permission(&deserialized, "admin"));
    }

    #[test]
    fn uuid_shaped_wire_identity_cannot_deserialize_as_session_authority() {
        let payload = serde_json::json!({
            "user_id": "11111111-1111-4111-8111-111111111111",
            "display_name": "External User",
            "roles": ["PlatformAdmin"],
            "token_valid": true,
            "provider_mode": "oidc"
        });
        let session = serde_json::from_value::<AuthSession>(payload).unwrap();
        assert_eq!(
            session.display_user_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(session.principal_id, None);
        assert_eq!(session.actor_class, ActorClass::Unknown);
        assert!(!check_permission(&session, "admin"));
        assert!(!check_permission(&session, "request"));
    }

    #[test]
    fn unverified_projection_preserves_the_non_authoritative_wire_key() {
        let value = serde_json::to_value(AuthSession::unverified_entra()).unwrap();
        assert_eq!(
            value.get("user_id").and_then(serde_json::Value::as_str),
            Some("unverified-entra-user")
        );
        assert!(value.get("principal_id").is_none());
    }

    #[test]
    fn absent_principal_fails_every_permission_check() {
        let session = AuthSession {
            roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: true,
            actor_class: ActorClass::VerifiedHuman,
            ..AuthSession::default()
        };
        for permission in ["admin", "approve", "audit", "execute", "request"] {
            assert!(!check_permission(&session, permission));
        }
        assert!(!session.is_verified_human());
    }

    #[test]
    fn test_entra_config_serialization_round_trip() {
        let config = EntraConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EntraConfig = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.enabled);
        assert_eq!(config.tenant_id, deserialized.tenant_id);
        assert_eq!(config.client_id, deserialized.client_id);
        assert_eq!(config.instance, deserialized.instance);
    }

    #[test]
    fn test_rbac_roles_serialization_round_trip() {
        let roles = get_rbac_roles();
        let json = serde_json::to_string(&roles).unwrap();
        let deserialized: Vec<RbacRole> = serde_json::from_str(&json).unwrap();
        assert_eq!(roles.len(), deserialized.len());
        for (a, b) in roles.iter().zip(deserialized.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.permissions, b.permissions);
        }
    }

    #[test]
    fn test_get_entra_config_returns_disabled_config() {
        let config = get_entra_config_from_env("", "", "https://login.microsoftonline.com");
        assert!(!config.enabled);
    }

    #[test]
    fn test_platform_admin_has_all_permissions() {
        let session = verified_human_for_role(APP_ROLE_PLATFORM_ADMIN);
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "audit"));
    }

    #[test]
    fn test_avoid_secrets_never_validate_real_tokens() {
        let config = get_entra_config_from_env("", "", "https://login.microsoftonline.com");
        assert!(!config.enabled);
        assert!(config.tenant_id.contains("placeholder"));
        assert!(config.client_id.contains("placeholder"));
        assert!(!config.tenant_id.contains("@"));
        assert!(!config.client_id.contains("@"));
        assert!(
            !config
                .tenant_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        );
        assert!(
            !config
                .client_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        );
    }

    #[test]
    fn test_auditor_role_has_only_audit() {
        let roles = get_rbac_roles();
        let auditor = roles.iter().find(|r| r.name == APP_ROLE_AUDITOR).unwrap();
        assert_eq!(auditor.permissions, vec!["audit"]);
    }

    /// Invariant: every role that holds `execute` ALSO holds `audit`. This is what
    /// makes the shift-queue model sound — the queue reads at the `execute` tier
    /// (is_execute_read_path), and scans surface OTHER domains' identity data there
    /// (e.g. #17 legal-hold names/types, whose own reads are `audit`-tier). Because
    /// every execute-holder is also an audit-holder, an execute-tier queue reader can
    /// already read those audit-tier domains directly — so the queue is never a
    /// cross-tier leak. If a future role were given `execute` WITHOUT `audit`, that
    /// premise (and the legal-hold/secret/restore scan hygiene argument) would break —
    /// this test fails loudly first.
    #[test]
    fn execute_holders_also_hold_audit() {
        for role in get_rbac_roles() {
            if role.permissions.iter().any(|p| p == "execute") {
                assert!(
                    role.permissions.iter().any(|p| p == "audit"),
                    "role {:?} holds execute but NOT audit — this breaks the shift-queue \
                     execute-read cross-tier hygiene invariant",
                    role.name
                );
            }
        }
    }

    fn verified_human_for_role(role: &str) -> AuthSession {
        AuthSession {
            display_user_id: test_principal_id().to_string(),
            principal_id: Some(test_principal_id()),
            display_name: "Verified Human".to_string(),
            roles: vec![role.to_string()],
            token_valid: true,
            provider_mode: "test-carrier".to_string(),
            actor_class: ActorClass::VerifiedHuman,
            ..AuthSession::default()
        }
    }

    #[test]
    fn test_platform_admin_is_superuser() {
        // PlatformAdmin's `admin` permission remains a superuser for ordinary
        // operations. Approval additionally requires admitted-human provenance.
        let session = verified_human_for_role(APP_ROLE_PLATFORM_ADMIN);
        assert!(check_permission(&session, "execute"));
        assert!(check_permission(&session, "request"));
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "audit"));
    }

    #[test]
    fn test_break_glass_admin_is_superuser() {
        // BreakGlassAdmin carries `admin` (and `audit`); the superuser model
        // makes it pass every coarse permission when the actor is human.
        let session = verified_human_for_role(APP_ROLE_BREAK_GLASS_ADMIN);
        assert!(check_permission(&session, "execute"));
        assert!(check_permission(&session, "request"));
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "audit"));
    }

    #[test]
    fn test_superuser_does_not_leak_to_audit_only_roles() {
        // Auditor holds only `audit`, never `admin`, so the superuser fallthrough
        // does not apply: it must remain locked out of every mutating permission.
        let session = session_for_role(APP_ROLE_AUDITOR);
        assert!(check_permission(&session, "audit"));
        assert!(!check_permission(&session, "execute"));
        assert!(!check_permission(&session, "request"));
        assert!(!check_permission(&session, "approve"));
        assert!(!check_permission(&session, "admin"));
    }

    #[test]
    fn test_operator_holds_execute_but_not_admin_tier() {
        // A plain operator holds `execute`/`audit` and passes execute, but the
        // superuser fallthrough never grants it approve/request/admin.
        let session = session_for_role(APP_ROLE_VMWARE_OPERATOR);
        assert!(check_permission(&session, "execute"));
        assert!(check_permission(&session, "audit"));
        assert!(!check_permission(&session, "approve"));
        assert!(!check_permission(&session, "request"));
        assert!(!check_permission(&session, "admin"));
    }

    #[test]
    fn test_approver_holds_approve_but_not_execute() {
        let session = verified_human_for_role(APP_ROLE_DATACENTER_APPROVER);
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "audit"));
        assert!(!check_permission(&session, "execute"));
        assert!(!check_permission(&session, "request"));
        assert!(!check_permission(&session, "admin"));
    }

    #[test]
    fn non_human_actor_classes_cannot_resolve_approval() {
        let workload = AuthSession {
            display_user_id: test_principal_id().to_string(),
            principal_id: Some(test_principal_id()),
            roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: true,
            provider_mode: "api-token".to_string(),
            actor_class: ActorClass::Workload,
            ..AuthSession::default()
        };
        assert!(!check_permission(&workload, "approve"));
        assert!(!check_human_signoff_permission(&workload, "admin"));
        assert!(check_permission(&workload, "admin"));
        assert!(check_permission(&workload, "execute"));

        let unknown = AuthSession {
            display_user_id: test_principal_id().to_string(),
            principal_id: Some(test_principal_id()),
            roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: true,
            actor_class: ActorClass::Unknown,
            ..AuthSession::default()
        };
        assert!(!check_permission(&unknown, "admin"));
        assert!(!check_permission(&unknown, "execute"));
    }

    #[test]
    fn simulated_authority_is_limited_to_non_token_dry_run_modes() {
        let static_session = AuthSession::static_dry_run();
        assert!(check_permission(&static_session, "admin"));
        let mock_session = AuthSession {
            provider_mode: "mock-dry-run".to_string(),
            ..AuthSession::static_dry_run()
        };
        assert!(check_permission(&mock_session, "admin"));

        for session in [
            AuthSession {
                token_valid: true,
                ..AuthSession::static_dry_run()
            },
            AuthSession {
                provider_mode: "entra-id".to_string(),
                ..AuthSession::static_dry_run()
            },
            AuthSession {
                actor_class: ActorClass::Unknown,
                ..AuthSession::static_dry_run()
            },
        ] {
            assert!(!check_permission(&session, "admin"));
            assert!(!check_permission(&session, "execute"));
        }
    }

    #[test]
    fn actor_class_persistence_spelling_is_stable() {
        assert_eq!(ActorClass::VerifiedHuman.as_str(), "verified-human");
        assert_eq!(ActorClass::Workload.as_str(), "workload");
        assert_eq!(ActorClass::Simulated.as_str(), "simulated");
        assert_eq!(ActorClass::Unknown.as_str(), "unknown");
    }

    #[test]
    fn invalid_verified_human_cannot_resolve_approval() {
        let mut session = verified_human_for_role(APP_ROLE_DATACENTER_APPROVER);
        session.token_valid = false;
        assert!(!session.is_verified_human());
        assert!(!check_permission(&session, "approve"));
        assert!(!check_permission(&session, "admin"));
    }

    fn session_for_role(role: &str) -> AuthSession {
        AuthSession {
            display_user_id: test_principal_id().to_string(),
            principal_id: Some(test_principal_id()),
            display_name: "Capability Test User".to_string(),
            roles: vec![role.to_string()],
            token_valid: true,
            provider_mode: "test-provider".to_string(),
            actor_class: ActorClass::Workload,
            ..AuthSession::default()
        }
    }

    #[test]
    fn generic_execute_never_implies_a_functional_operation_capability() {
        for role in [
            APP_ROLE_VMWARE_OPERATOR,
            APP_ROLE_HYPERV_OPERATOR,
            APP_ROLE_PROXMOX_OPERATOR,
            APP_ROLE_BACKUP_OPERATOR,
        ] {
            let session = session_for_role(role);
            assert!(check_permission(&session, "execute"));
            for capability in OperationCapability::ALL {
                assert!(
                    !check_operation_capability(&session, capability),
                    "coarse execute role {role} unexpectedly inherited {}",
                    capability.as_str()
                );
            }
        }
    }

    #[test]
    fn functional_capabilities_are_role_specific_and_do_not_cross_domains() {
        let monitoring = session_for_role(APP_ROLE_MONITORING_OPERATOR);
        assert!(check_operation_capability(
            &monitoring,
            OperationCapability::MonitoringAlertRoutingManage
        ));
        assert!(check_operation_capability(
            &monitoring,
            OperationCapability::MonitoringAlertRead
        ));
        assert!(check_operation_capability(
            &monitoring,
            OperationCapability::MonitoringAlertAcknowledge
        ));
        assert!(!check_operation_capability(
            &monitoring,
            OperationCapability::SoftwareDeploymentExecute
        ));

        let wintel = session_for_role(APP_ROLE_WINTEL_LINUX_OPERATOR);
        assert!(check_operation_capability(
            &wintel,
            OperationCapability::SoftwareDeploymentExecute
        ));
        assert!(!check_operation_capability(
            &wintel,
            OperationCapability::MonitoringAlertRoutingManage
        ));

        for capability in [
            OperationCapability::IdentityAdComputerDelete,
            OperationCapability::NetworkFirewallManage,
            OperationCapability::StorageArrayDecommission,
        ] {
            assert!(!check_operation_capability(&monitoring, capability));
            assert!(!check_operation_capability(&wintel, capability));
        }
    }

    #[test]
    fn admin_roles_intentionally_override_every_functional_capability() {
        for role in [APP_ROLE_PLATFORM_ADMIN, APP_ROLE_BREAK_GLASS_ADMIN] {
            let session = session_for_role(role);
            for capability in OperationCapability::ALL {
                assert!(
                    check_operation_capability(&session, capability),
                    "admin role {role} must intentionally satisfy {}",
                    capability.as_str()
                );
            }
        }
    }

    #[test]
    fn unknown_and_ungranted_roles_have_no_functional_capabilities() {
        for role in [
            "UnknownExternalRole",
            APP_ROLE_DATACENTER_APPROVER,
            APP_ROLE_SERVICE_DESK,
            APP_ROLE_AUDITOR,
            APP_ROLE_REQUESTER,
        ] {
            let session = session_for_role(role);
            for capability in OperationCapability::ALL {
                assert!(!check_operation_capability(&session, capability));
            }
        }
    }

    #[test]
    fn role_registry_serializes_stable_capability_identifiers() {
        let roles = serde_json::to_value(get_rbac_roles()).unwrap();
        let monitoring = roles
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["name"] == APP_ROLE_MONITORING_OPERATOR)
            .unwrap();
        assert_eq!(
            monitoring["capabilities"],
            serde_json::json!([
                "monitoring.alert-routing.manage",
                "monitoring.alert.read",
                "monitoring.alert.acknowledge"
            ])
        );
        assert!(
            monitoring["execution_domains"]
                .as_array()
                .unwrap()
                .iter()
                .any(|domain| domain == "alert-routing")
        );
    }

    #[test]
    fn scope_permits_matrix() {
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // EMPTY scopes => unrestricted (the common no-scoping case).
        assert!(scope_permits(&[], Some("GBLON")));
        assert!(scope_permits(&[], None));

        // A request that names no scope is not constrained by this check.
        assert!(scope_permits(&s(&["GBLON"]), None));

        // In-scope is permitted; out-of-scope is denied (THE cross-tenant gap).
        assert!(scope_permits(&s(&["GBLON", "DEFRA"]), Some("DEFRA")));
        assert!(!scope_permits(&s(&["GBLON", "DEFRA"]), Some("FRPAR")));

        // Whitespace is trimmed on both sides; the match is case-SENSITIVE.
        assert!(scope_permits(&s(&[" GBLON "]), Some("GBLON")));
        assert!(scope_permits(&s(&["GBLON"]), Some("  GBLON  ")));
        assert!(
            !scope_permits(&s(&["GBLON"]), Some("gblon")),
            "site identifiers are canonical/case-sensitive"
        );
    }

    #[test]
    fn resolve_scope_filter_matrix() {
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        use ScopeFilter::{Allow, Deny};

        // UNRESTRICTED: the requested value passes through verbatim (blank/None
        // stays None — an admin/operator legitimately reads all scopes).
        assert_eq!(resolve_scope_filter(&[], None), Allow(None));
        assert_eq!(
            resolve_scope_filter(&[], Some("GBLON")),
            Allow(Some("GBLON".into()))
        );
        assert_eq!(resolve_scope_filter(&[], Some("  ")), Allow(None));

        // SINGLE-scope principal: an explicit in-scope value is allowed; an
        // omitted filter is NARROWED to that one scope (never widened to all).
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON"]), Some("GBLON")),
            Allow(Some("GBLON".into()))
        );
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON"]), None),
            Allow(Some("GBLON".into())),
            "an omitted filter must narrow to the principal's own scope, not all scopes"
        );
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON"]), Some("  ")),
            Allow(Some("GBLON".into())),
            "a blank filter is treated as omission and narrows to scope"
        );

        // Out-of-scope explicit value is denied (THE cross-tenant gap).
        assert_eq!(resolve_scope_filter(&s(&["GBLON"]), Some("DEFRA")), Deny);

        // MULTI-scope principal: an in-scope value is allowed, but an OMITTED
        // filter is denied — the single-value query cannot express the set, so
        // the principal must name one in-scope value (no silent all-scopes read).
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON", "DEFRA"]), Some("DEFRA")),
            Allow(Some("DEFRA".into()))
        );
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON", "DEFRA"]), Some("FRPAR")),
            Deny
        );
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON", "DEFRA"]), None),
            Deny,
            "a multi-scope principal must not get an unfiltered (all-scopes) read"
        );

        // Whitespace is trimmed on both sides; the match is case-SENSITIVE.
        assert_eq!(
            resolve_scope_filter(&s(&[" GBLON "]), Some("GBLON")),
            Allow(Some("GBLON".into()))
        );
        assert_eq!(resolve_scope_filter(&s(&["GBLON"]), Some("gblon")), Deny);

        // Duplicate scopes collapse to ONE distinct scope: an omitted filter
        // narrows (does NOT deny as if multi-scope).
        assert_eq!(
            resolve_scope_filter(&s(&["GBLON", " GBLON "]), None),
            Allow(Some("GBLON".into())),
            "a repeated single scope must narrow, not be treated as multi-scope"
        );

        // An all-blank scope set has no USABLE scope, so it collapses to the
        // unrestricted case (this cannot arise from a real token — parse_token_scope
        // strips blanks, yielding an empty Vec — but the engine stays well-defined).
        assert_eq!(resolve_scope_filter(&s(&["  ", ""]), None), Allow(None));
        assert_eq!(
            resolve_scope_filter(&s(&["  ", ""]), Some("GBLON")),
            Allow(Some("GBLON".into()))
        );
    }
}
