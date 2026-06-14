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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub user_id: String,
    pub display_name: String,
    pub roles: Vec<String>,
    pub token_valid: bool,
    pub provider_mode: String,
}

impl AuthSession {
    pub fn static_dry_run() -> Self {
        Self {
            user_id: "static-user".to_string(),
            display_name: "Platform Operator (Static)".to_string(),
            roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: false,
            provider_mode: "static-dry-run".to_string(),
        }
    }

    pub fn unverified_entra() -> Self {
        Self {
            user_id: "unverified-entra-user".to_string(),
            display_name: "Unverified Entra ID User".to_string(),
            roles: vec![],
            token_valid: false,
            provider_mode: "entra-id-unverified".to_string(),
        }
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
        },
        RbacRole {
            name: APP_ROLE_DATACENTER_APPROVER.to_string(),
            description: "Approvers — datacenter-level approval and audit".to_string(),
            permissions: vec!["approve".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_VMWARE_OPERATOR.to_string(),
            description: "VMware Operators — virtualization execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_HYPERV_OPERATOR.to_string(),
            description: "Hyper-V Operators — virtualization execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_PROXMOX_OPERATOR.to_string(),
            description: "Proxmox Operators — virtualization execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_WINTEL_LINUX_OPERATOR.to_string(),
            description: "Wintel/Linux Operators — OS execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_BACKUP_OPERATOR.to_string(),
            description: "Backup Operators — backup execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_MONITORING_OPERATOR.to_string(),
            description: "Monitoring Operators — monitoring execution and audit".to_string(),
            permissions: vec!["execute".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_SERVICE_DESK.to_string(),
            description: "Service Desk — triage, request, and audit access".to_string(),
            permissions: vec!["request".to_string(), "audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_AUDITOR.to_string(),
            description: "Auditor — read-only audit access".to_string(),
            permissions: vec!["audit".to_string()],
        },
        RbacRole {
            name: APP_ROLE_REQUESTER.to_string(),
            description: "Requester — request-only access".to_string(),
            permissions: vec!["request".to_string()],
        },
        RbacRole {
            name: APP_ROLE_BREAK_GLASS_ADMIN.to_string(),
            description: "Break-Glass — emergency administration and audit".to_string(),
            permissions: vec!["admin".to_string(), "audit".to_string()],
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
    let roles = get_rbac_roles();
    let mut held = std::collections::HashSet::new();
    for role_name in &session.roles {
        if let Some(role) = roles.iter().find(|r| &r.name == role_name) {
            held.extend(role.permissions.iter().map(String::as_str));
        }
    }
    held.contains("admin") || held.contains(permission)
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
        assert_eq!(session.user_id, "static-user");
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "static-dry-run");
        assert!(session.roles.contains(&APP_ROLE_PLATFORM_ADMIN.to_string()));
        assert_eq!(session.roles.len(), 1);
    }

    #[test]
    fn test_unverified_entra_session_has_no_roles() {
        let session = AuthSession::unverified_entra();
        assert_eq!(session.user_id, "unverified-entra-user");
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "entra-id-unverified");
        assert!(session.roles.is_empty());
    }

    #[test]
    fn test_check_permission_returns_true_for_matching_role() {
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_PLATFORM_ADMIN.to_string()];
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "audit"));
    }

    #[test]
    fn test_check_permission_returns_false_for_non_matching_role() {
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_REQUESTER.to_string()];
        assert!(check_permission(&session, "request"));
        assert!(!check_permission(&session, "admin"));
        assert!(!check_permission(&session, "execute"));
    }

    #[test]
    fn test_check_permission_empty_roles() {
        let mut session = AuthSession::static_dry_run();
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
        let session = AuthSession::static_dry_run();
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: AuthSession = serde_json::from_str(&json).unwrap();
        assert_eq!(session.user_id, deserialized.user_id);
        assert_eq!(session.display_name, deserialized.display_name);
        assert_eq!(session.roles, deserialized.roles);
        assert_eq!(session.token_valid, deserialized.token_valid);
        assert_eq!(session.provider_mode, deserialized.provider_mode);
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
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_PLATFORM_ADMIN.to_string()];
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

    #[test]
    fn test_platform_admin_is_superuser() {
        // PlatformAdmin's role permissions are [admin, approve, audit] — it does
        // NOT literally hold "execute" or "request". The superuser model makes
        // the `admin` permission satisfy every check, so PlatformAdmin now passes
        // execute/request/approve/admin alike (these were false before the fix).
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_PLATFORM_ADMIN.to_string()];
        assert!(check_permission(&session, "execute"));
        assert!(check_permission(&session, "request"));
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "admin"));
        assert!(check_permission(&session, "audit"));
    }

    #[test]
    fn test_break_glass_admin_is_superuser() {
        // BreakGlassAdmin carries `admin` (and `audit`); the superuser model
        // makes it pass every coarse permission too.
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_BREAK_GLASS_ADMIN.to_string()];
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
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_AUDITOR.to_string()];
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
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_VMWARE_OPERATOR.to_string()];
        assert!(check_permission(&session, "execute"));
        assert!(check_permission(&session, "audit"));
        assert!(!check_permission(&session, "approve"));
        assert!(!check_permission(&session, "request"));
        assert!(!check_permission(&session, "admin"));
    }

    #[test]
    fn test_approver_holds_approve_but_not_execute() {
        let mut session = AuthSession::static_dry_run();
        session.roles = vec![APP_ROLE_DATACENTER_APPROVER.to_string()];
        assert!(check_permission(&session, "approve"));
        assert!(check_permission(&session, "audit"));
        assert!(!check_permission(&session, "execute"));
        assert!(!check_permission(&session, "request"));
        assert!(!check_permission(&session, "admin"));
    }
}
