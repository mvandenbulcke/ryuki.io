use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LbProtocol {
    Http,
    Https,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PersistenceMethod {
    Cookie,
    SourceIp,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VirtualServerStatus {
    Online,
    Offline,
    Draining,
    Creating,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PoolAlgorithm {
    RoundRobin,
    LeastConnections,
    Weighted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PoolMemberStatus {
    Up,
    Down,
    Disabled,
    Draining,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LbRequestStatus {
    Draft,
    Validated,
    Provisioned,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbVirtualServer {
    pub id: String,
    pub name: String,
    pub vip: String,
    pub port: u16,
    pub protocol: LbProtocol,
    pub pool_id: String,
    pub site: String,
    pub ssl_profile: Option<String>,
    pub persistence_method: PersistenceMethod,
    pub status: VirtualServerStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbPool {
    pub id: String,
    pub name: String,
    pub site: String,
    pub members: Vec<PoolMember>,
    pub algorithm: PoolAlgorithm,
    pub health_monitor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMember {
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub weight: u16,
    pub status: PoolMemberStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbRequest {
    pub id: String,
    pub requester: String,
    pub virtual_server_name: String,
    pub vip: String,
    pub port: u16,
    pub protocol: LbProtocol,
    pub site: String,
    pub pool_members: Vec<String>,
    pub status: LbRequestStatus,
}

// ─── Input parsing helpers (pure) ────────────────────────────────────────────

pub fn parse_protocol(protocol: &str) -> Result<LbProtocol, String> {
    match protocol.to_ascii_uppercase().as_str() {
        "HTTP" => Ok(LbProtocol::Http),
        "HTTPS" => Ok(LbProtocol::Https),
        "TCP" => Ok(LbProtocol::Tcp),
        other => Err(format!(
            "Invalid protocol: {}. Must be HTTP, HTTPS, or TCP",
            other
        )),
    }
}

pub fn parse_algorithm(algorithm: &str) -> Result<PoolAlgorithm, String> {
    match algorithm
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "roundrobin" => Ok(PoolAlgorithm::RoundRobin),
        "leastconnections" => Ok(PoolAlgorithm::LeastConnections),
        "weighted" => Ok(PoolAlgorithm::Weighted),
        other => Err(format!(
            "Invalid algorithm: {}. Must be RoundRobin, LeastConnections, or Weighted",
            other
        )),
    }
}

pub fn member_from_input(member: &str, default_port: u16) -> Result<PoolMember, String> {
    let parts: Vec<&str> = member.split(':').collect();
    let hostname = parts
        .first()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "pool member hostname cannot be empty".to_string())?;
    let ip = parts
        .get(1)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("0.0.0.0");
    let port = match parts.get(2) {
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| format!("Invalid pool member port: {}", value))?,
        None => default_port,
    };
    // Reject port 0 here (engine -> 400) rather than letting it reach the DB
    // CHECK (port >= 1) and surface as a 500.
    if port == 0 {
        return Err("pool member port must be greater than zero".into());
    }

    Ok(PoolMember {
        hostname: hostname.to_string(),
        ip: ip.to_string(),
        port,
        weight: 1,
        status: PoolMemberStatus::Up,
    })
}

// ─── Pure builder for provision_lb ───────────────────────────────────────────

/// Validate inputs and build the (LbPool, LbVirtualServer, LbRequest) triple.
/// Does NOT check VIP uniqueness — the caller (handler/repo) is responsible for that.
pub fn build_provision(
    name: &str,
    vip: &str,
    port: u16,
    protocol: &str,
    site: &str,
    members: Vec<String>,
    algorithm: &str,
) -> Result<(LbPool, LbVirtualServer, LbRequest), String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    if vip.trim().is_empty() {
        return Err("vip cannot be empty".into());
    }
    if port == 0 {
        return Err("port must be greater than zero".into());
    }
    if members.is_empty() {
        return Err("members cannot be empty".into());
    }

    let protocol = parse_protocol(protocol)?;
    let algorithm = parse_algorithm(algorithm)?;
    let pool_members = members
        .iter()
        .map(|member| member_from_input(member, port))
        .collect::<Result<Vec<_>, _>>()?;

    // Reject duplicate member hostnames within one request here (engine -> 400),
    // rather than letting the second one hit the lb_pool_members PK
    // (pool_id, hostname) and surface as a unique-violation/500.
    let mut seen_hostnames = std::collections::HashSet::new();
    for m in &pool_members {
        if !seen_hostnames.insert(m.hostname.as_str()) {
            return Err(format!("duplicate pool member hostname '{}'", m.hostname));
        }
    }

    // Full UUID (not just the first 8-hex segment) for the generated ids, so a
    // birthday collision can't fail the PK insert with a (now 409-mapped) error.
    let suffix = Uuid::new_v4().to_string();
    let pool = LbPool {
        id: format!("pool-{}-{}", site.to_lowercase(), suffix),
        name: format!("{}-pool", name),
        site: site.to_string(),
        members: pool_members,
        algorithm,
        health_monitor: Some("tcp-connect".into()),
    };
    let virtual_server = LbVirtualServer {
        id: format!("vs-{}-{}", site.to_lowercase(), suffix),
        name: name.to_string(),
        vip: vip.to_string(),
        port,
        protocol: protocol.clone(),
        pool_id: pool.id.clone(),
        site: site.to_string(),
        ssl_profile: if protocol == LbProtocol::Https {
            Some("standard-tls".into())
        } else {
            None
        },
        persistence_method: PersistenceMethod::None,
        status: VirtualServerStatus::Online,
    };
    let request = LbRequest {
        id: format!("lbr-{}-{}", site.to_lowercase(), suffix),
        requester: "mock-requester".into(),
        virtual_server_name: name.to_string(),
        vip: vip.to_string(),
        port,
        protocol,
        site: site.to_string(),
        pool_members: members,
        status: LbRequestStatus::Provisioned,
    };

    Ok((pool, virtual_server, request))
}

// ─── Pure read functions (degrade to empty when called without DB data) ───────

/// Build the list_virtual_servers JSON response from provided data.
pub fn list_virtual_servers(
    site: &str,
    virtual_servers: &[LbVirtualServer],
) -> Result<Value, String> {
    let filtered: Vec<&LbVirtualServer> = if site.is_empty() {
        virtual_servers.iter().collect()
    } else {
        virtual_servers
            .iter()
            .filter(|vs| vs.site == site)
            .collect()
    };

    Ok(json!({
        "source": "db",
        "site": site,
        "count": filtered.len(),
        "virtual_servers": filtered
    }))
}

/// Build the get_virtual_server JSON response from provided vs and pool.
pub fn get_virtual_server(vs: &LbVirtualServer, pool: &LbPool) -> Value {
    json!({
        "source": "db",
        "virtual_server": vs,
        "pool": pool,
        "pool_members": pool.members
    })
}

/// Build the get_lb_status JSON response from aggregate counts.
pub fn get_lb_status(
    site: &str,
    vs_count: i64,
    pool_count: i64,
    up_members: i64,
    down_members: i64,
    offline_vs: i64,
    draining_vs: i64,
) -> Value {
    json!({
        "source": "db",
        "site": site,
        "virtual_server_count": vs_count,
        "pool_count": pool_count,
        "up_members": up_members,
        "down_members": down_members,
        "offline_virtual_servers": offline_vs,
        "draining_virtual_servers": draining_vs
    })
}

/// Validate that a VIP is available at a site (pure computation over provided data).
pub fn validate_vip(
    vip: &str,
    site: &str,
    conflict: Option<&LbVirtualServer>,
) -> Result<Value, String> {
    if vip.trim().is_empty() {
        return Err("vip cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    Ok(json!({
        "source": "db",
        "vip": vip,
        "site": site,
        "available": conflict.is_none(),
        "conflict": conflict
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_provision_https_sets_ssl_profile() {
        let (pool, vs, req) = build_provision(
            "test-web-vs",
            "10.99.10.10",
            443,
            "HTTPS",
            "TESTSITE",
            vec!["test-web-01:10.99.20.11:8443".into()],
            "RoundRobin",
        )
        .unwrap();

        assert_eq!(vs.name, "test-web-vs");
        assert_eq!(vs.ssl_profile, Some("standard-tls".into()));
        assert_eq!(vs.protocol, LbProtocol::Https);
        assert_eq!(vs.status, VirtualServerStatus::Online);
        assert_eq!(vs.persistence_method, PersistenceMethod::None);
        assert_eq!(pool.members.len(), 1);
        assert_eq!(pool.members[0].hostname, "test-web-01");
        assert_eq!(pool.members[0].port, 8443);
        assert_eq!(pool.members[0].status, PoolMemberStatus::Up);
        assert_eq!(req.status, LbRequestStatus::Provisioned);
        assert_eq!(req.pool_members, vec!["test-web-01:10.99.20.11:8443"]);
    }

    #[test]
    fn test_build_provision_tcp_no_ssl_profile() {
        let (_, vs, _) = build_provision(
            "test-tcp-vs",
            "10.99.10.11",
            9000,
            "TCP",
            "TESTSITE",
            vec!["tcp-node-01:10.1.1.1:9000".into()],
            "LeastConnections",
        )
        .unwrap();

        assert_eq!(vs.protocol, LbProtocol::Tcp);
        assert!(vs.ssl_profile.is_none());
    }

    #[test]
    fn test_build_provision_validation_errors() {
        assert!(
            build_provision(
                "",
                "10.1.1.1",
                80,
                "HTTP",
                "S",
                vec!["x".into()],
                "RoundRobin"
            )
            .is_err()
        );
        assert!(
            build_provision("name", "", 80, "HTTP", "S", vec!["x".into()], "RoundRobin").is_err()
        );
        assert!(
            build_provision(
                "name",
                "10.1.1.1",
                80,
                "HTTP",
                "",
                vec!["x".into()],
                "RoundRobin"
            )
            .is_err()
        );
        assert!(
            build_provision(
                "name",
                "10.1.1.1",
                0,
                "HTTP",
                "S",
                vec!["x".into()],
                "RoundRobin"
            )
            .is_err()
        );
        assert!(
            build_provision("name", "10.1.1.1", 80, "HTTP", "S", vec![], "RoundRobin").is_err()
        );
        assert!(
            build_provision(
                "name",
                "10.1.1.1",
                80,
                "INVALID",
                "S",
                vec!["x".into()],
                "RoundRobin"
            )
            .is_err()
        );
        assert!(
            build_provision(
                "name",
                "10.1.1.1",
                80,
                "HTTP",
                "S",
                vec!["x".into()],
                "BadAlgo"
            )
            .is_err()
        );
        // A member with an explicit port 0 must be rejected (engine -> 400), not
        // pass through to the DB CHECK (port >= 1) as a 500.
        assert!(
            build_provision(
                "name",
                "10.1.1.1",
                80,
                "HTTP",
                "S",
                vec!["host:10.0.0.1:0".into()],
                "RoundRobin"
            )
            .is_err(),
            "member port 0 must be rejected"
        );
        // Duplicate member hostnames within one request must be rejected (engine ->
        // 400), not hit the lb_pool_members (pool_id, hostname) PK as a 500.
        assert!(
            build_provision(
                "name",
                "10.1.1.1",
                80,
                "HTTP",
                "S",
                vec!["dup".into(), "dup".into()],
                "RoundRobin"
            )
            .is_err(),
            "duplicate member hostnames must be rejected"
        );
    }

    #[test]
    fn test_list_virtual_servers_filter() {
        let vss = vec![
            LbVirtualServer {
                id: "vs-a".into(),
                name: "a".into(),
                vip: "1.1.1.1".into(),
                port: 80,
                protocol: LbProtocol::Http,
                pool_id: "p-a".into(),
                site: "SITEА".into(),
                ssl_profile: None,
                persistence_method: PersistenceMethod::None,
                status: VirtualServerStatus::Online,
            },
            LbVirtualServer {
                id: "vs-b".into(),
                name: "b".into(),
                vip: "2.2.2.2".into(),
                port: 443,
                protocol: LbProtocol::Https,
                pool_id: "p-b".into(),
                site: "SITEB".into(),
                ssl_profile: None,
                persistence_method: PersistenceMethod::Cookie,
                status: VirtualServerStatus::Offline,
            },
        ];

        let all = list_virtual_servers("", &vss).unwrap();
        assert_eq!(all["count"], 2);

        let filtered = list_virtual_servers("SITEА", &vss).unwrap();
        assert_eq!(filtered["count"], 1);
        assert_eq!(filtered["virtual_servers"][0]["id"], "vs-a");
    }

    #[test]
    fn test_validate_vip_pure() {
        let result = validate_vip("10.1.1.1", "SITE", None).unwrap();
        assert_eq!(result["available"], true);
        assert!(result["conflict"].is_null());

        let conflict_vs = LbVirtualServer {
            id: "vs-x".into(),
            name: "x".into(),
            vip: "10.1.1.1".into(),
            port: 80,
            protocol: LbProtocol::Http,
            pool_id: "p-x".into(),
            site: "SITE".into(),
            ssl_profile: None,
            persistence_method: PersistenceMethod::None,
            status: VirtualServerStatus::Online,
        };
        let conflict_result = validate_vip("10.1.1.1", "SITE", Some(&conflict_vs)).unwrap();
        assert_eq!(conflict_result["available"], false);
        assert_eq!(conflict_result["conflict"]["id"], "vs-x");
    }

    #[test]
    fn test_enum_serde_kebab_forms() {
        // Verify each enum's serde output matches the DB CHECK values exactly.
        let proto_http = serde_json::to_value(&LbProtocol::Http).unwrap();
        assert_eq!(proto_http.as_str().unwrap(), "http");
        let proto_https = serde_json::to_value(&LbProtocol::Https).unwrap();
        assert_eq!(proto_https.as_str().unwrap(), "https");
        let proto_tcp = serde_json::to_value(&LbProtocol::Tcp).unwrap();
        assert_eq!(proto_tcp.as_str().unwrap(), "tcp");

        let pm_cookie = serde_json::to_value(&PersistenceMethod::Cookie).unwrap();
        assert_eq!(pm_cookie.as_str().unwrap(), "cookie");
        let pm_sourceip = serde_json::to_value(&PersistenceMethod::SourceIp).unwrap();
        assert_eq!(pm_sourceip.as_str().unwrap(), "source-ip");
        let pm_none = serde_json::to_value(&PersistenceMethod::None).unwrap();
        assert_eq!(pm_none.as_str().unwrap(), "none");

        let vs_online = serde_json::to_value(&VirtualServerStatus::Online).unwrap();
        assert_eq!(vs_online.as_str().unwrap(), "online");
        let vs_offline = serde_json::to_value(&VirtualServerStatus::Offline).unwrap();
        assert_eq!(vs_offline.as_str().unwrap(), "offline");
        let vs_draining = serde_json::to_value(&VirtualServerStatus::Draining).unwrap();
        assert_eq!(vs_draining.as_str().unwrap(), "draining");
        let vs_creating = serde_json::to_value(&VirtualServerStatus::Creating).unwrap();
        assert_eq!(vs_creating.as_str().unwrap(), "creating");

        let algo_rr = serde_json::to_value(&PoolAlgorithm::RoundRobin).unwrap();
        assert_eq!(algo_rr.as_str().unwrap(), "round-robin");
        let algo_lc = serde_json::to_value(&PoolAlgorithm::LeastConnections).unwrap();
        assert_eq!(algo_lc.as_str().unwrap(), "least-connections");
        let algo_w = serde_json::to_value(&PoolAlgorithm::Weighted).unwrap();
        assert_eq!(algo_w.as_str().unwrap(), "weighted");

        let ms_up = serde_json::to_value(&PoolMemberStatus::Up).unwrap();
        assert_eq!(ms_up.as_str().unwrap(), "up");
        let ms_down = serde_json::to_value(&PoolMemberStatus::Down).unwrap();
        assert_eq!(ms_down.as_str().unwrap(), "down");
        let ms_disabled = serde_json::to_value(&PoolMemberStatus::Disabled).unwrap();
        assert_eq!(ms_disabled.as_str().unwrap(), "disabled");
        let ms_draining = serde_json::to_value(&PoolMemberStatus::Draining).unwrap();
        assert_eq!(ms_draining.as_str().unwrap(), "draining");

        let rs_draft = serde_json::to_value(&LbRequestStatus::Draft).unwrap();
        assert_eq!(rs_draft.as_str().unwrap(), "draft");
        let rs_validated = serde_json::to_value(&LbRequestStatus::Validated).unwrap();
        assert_eq!(rs_validated.as_str().unwrap(), "validated");
        let rs_provisioned = serde_json::to_value(&LbRequestStatus::Provisioned).unwrap();
        assert_eq!(rs_provisioned.as_str().unwrap(), "provisioned");
        let rs_verified = serde_json::to_value(&LbRequestStatus::Verified).unwrap();
        assert_eq!(rs_verified.as_str().unwrap(), "verified");
    }

    #[test]
    fn test_parse_algorithm_variants() {
        assert_eq!(
            parse_algorithm("RoundRobin").unwrap(),
            PoolAlgorithm::RoundRobin
        );
        assert_eq!(
            parse_algorithm("round-robin").unwrap(),
            PoolAlgorithm::RoundRobin
        );
        assert_eq!(
            parse_algorithm("LeastConnections").unwrap(),
            PoolAlgorithm::LeastConnections
        );
        assert_eq!(
            parse_algorithm("least-connections").unwrap(),
            PoolAlgorithm::LeastConnections
        );
        assert_eq!(
            parse_algorithm("Weighted").unwrap(),
            PoolAlgorithm::Weighted
        );
        assert!(parse_algorithm("bad").is_err());
    }
}
