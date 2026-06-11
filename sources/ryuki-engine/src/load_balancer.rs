use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
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

type LbStore = (Vec<LbVirtualServer>, Vec<LbPool>, Vec<LbRequest>);

static LB_STORE: OnceLock<Mutex<LbStore>> = OnceLock::new();

fn lb_store() -> &'static Mutex<LbStore> {
    LB_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> LbStore {
    let pools = vec![
        LbPool {
            id: "pool-defra-web".into(),
            name: "defra-web-pool".into(),
            site: "DEFRA".into(),
            members: vec![
                PoolMember {
                    hostname: "defra-web-01".into(),
                    ip: "10.10.20.11".into(),
                    port: 8080,
                    weight: 1,
                    status: PoolMemberStatus::Up,
                },
                PoolMember {
                    hostname: "defra-web-02".into(),
                    ip: "10.10.20.12".into(),
                    port: 8080,
                    weight: 1,
                    status: PoolMemberStatus::Up,
                },
            ],
            algorithm: PoolAlgorithm::RoundRobin,
            health_monitor: Some("http-200".into()),
        },
        LbPool {
            id: "pool-gblon-api".into(),
            name: "gblon-api-pool".into(),
            site: "GBLON".into(),
            members: vec![
                PoolMember {
                    hostname: "gblon-api-01".into(),
                    ip: "10.20.30.21".into(),
                    port: 8443,
                    weight: 2,
                    status: PoolMemberStatus::Up,
                },
                PoolMember {
                    hostname: "gblon-api-02".into(),
                    ip: "10.20.30.22".into(),
                    port: 8443,
                    weight: 1,
                    status: PoolMemberStatus::Down,
                },
            ],
            algorithm: PoolAlgorithm::Weighted,
            health_monitor: Some("https-api".into()),
        },
        LbPool {
            id: "pool-frpar-tcp".into(),
            name: "frpar-tcp-pool".into(),
            site: "FRPAR".into(),
            members: vec![PoolMember {
                hostname: "frpar-tcp-01".into(),
                ip: "10.30.40.31".into(),
                port: 9000,
                weight: 1,
                status: PoolMemberStatus::Disabled,
            }],
            algorithm: PoolAlgorithm::LeastConnections,
            health_monitor: None,
        },
    ];

    let virtual_servers = vec![
        LbVirtualServer {
            id: "vs-defra-web".into(),
            name: "defra-web-vs".into(),
            vip: "10.10.10.50".into(),
            port: 443,
            protocol: LbProtocol::Https,
            pool_id: "pool-defra-web".into(),
            site: "DEFRA".into(),
            ssl_profile: Some("standard-tls".into()),
            persistence_method: PersistenceMethod::Cookie,
            status: VirtualServerStatus::Online,
        },
        LbVirtualServer {
            id: "vs-defra-admin".into(),
            name: "defra-admin-vs".into(),
            vip: "10.10.10.51".into(),
            port: 80,
            protocol: LbProtocol::Http,
            pool_id: "pool-defra-web".into(),
            site: "DEFRA".into(),
            ssl_profile: None,
            persistence_method: PersistenceMethod::SourceIp,
            status: VirtualServerStatus::Draining,
        },
        LbVirtualServer {
            id: "vs-gblon-api".into(),
            name: "gblon-api-vs".into(),
            vip: "10.20.10.50".into(),
            port: 443,
            protocol: LbProtocol::Https,
            pool_id: "pool-gblon-api".into(),
            site: "GBLON".into(),
            ssl_profile: Some("api-tls".into()),
            persistence_method: PersistenceMethod::None,
            status: VirtualServerStatus::Online,
        },
        LbVirtualServer {
            id: "vs-frpar-tcp".into(),
            name: "frpar-tcp-vs".into(),
            vip: "10.30.10.50".into(),
            port: 9000,
            protocol: LbProtocol::Tcp,
            pool_id: "pool-frpar-tcp".into(),
            site: "FRPAR".into(),
            ssl_profile: None,
            persistence_method: PersistenceMethod::None,
            status: VirtualServerStatus::Offline,
        },
    ];

    let requests = vec![
        LbRequest {
            id: "lbr-defra-001".into(),
            requester: "alice.operator".into(),
            virtual_server_name: "defra-web-vs".into(),
            vip: "10.10.10.50".into(),
            port: 443,
            protocol: LbProtocol::Https,
            site: "DEFRA".into(),
            pool_members: vec!["defra-web-01".into(), "defra-web-02".into()],
            status: LbRequestStatus::Provisioned,
        },
        LbRequest {
            id: "lbr-gblon-001".into(),
            requester: "bob.engineer".into(),
            virtual_server_name: "gblon-api-vs".into(),
            vip: "10.20.10.50".into(),
            port: 443,
            protocol: LbProtocol::Https,
            site: "GBLON".into(),
            pool_members: vec!["gblon-api-01".into(), "gblon-api-02".into()],
            status: LbRequestStatus::Verified,
        },
        LbRequest {
            id: "lbr-frpar-001".into(),
            requester: "carol.admin".into(),
            virtual_server_name: "frpar-tcp-vs".into(),
            vip: "10.30.10.50".into(),
            port: 9000,
            protocol: LbProtocol::Tcp,
            site: "FRPAR".into(),
            pool_members: vec!["frpar-tcp-01".into()],
            status: LbRequestStatus::Validated,
        },
    ];

    (virtual_servers, pools, requests)
}

fn parse_protocol(protocol: &str) -> Result<LbProtocol, String> {
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

fn parse_algorithm(algorithm: &str) -> Result<PoolAlgorithm, String> {
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

fn member_from_input(member: &str, default_port: u16) -> Result<PoolMember, String> {
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

    Ok(PoolMember {
        hostname: hostname.to_string(),
        ip: ip.to_string(),
        port,
        weight: 1,
        status: PoolMemberStatus::Up,
    })
}

fn pool_for_vs<'a>(pools: &'a [LbPool], vs: &LbVirtualServer) -> Option<&'a LbPool> {
    pools.iter().find(|pool| pool.id == vs.pool_id)
}

pub fn list_virtual_servers(site: &str) -> Result<Value, String> {
    let store = lb_store().lock().unwrap();
    let virtual_servers: Vec<LbVirtualServer> = if site.is_empty() {
        store.0.clone()
    } else {
        store
            .0
            .iter()
            .filter(|vs| vs.site == site)
            .cloned()
            .collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "count": virtual_servers.len(),
        "virtual_servers": virtual_servers
    }))
}

pub fn get_virtual_server(id: &str) -> Result<Value, String> {
    let store = lb_store().lock().unwrap();
    let vs = store
        .0
        .iter()
        .find(|candidate| candidate.id == id)
        .ok_or_else(|| format!("Virtual server '{}' not found", id))?;
    let pool = pool_for_vs(&store.1, vs).ok_or_else(|| {
        format!(
            "Pool '{}' for virtual server '{}' not found",
            vs.pool_id, id
        )
    })?;

    Ok(json!({
        "source": "dry-run",
        "virtual_server": vs,
        "pool": pool,
        "pool_members": pool.members
    }))
}

pub fn provision_lb(
    name: &str,
    vip: &str,
    port: u16,
    protocol: &str,
    site: &str,
    members: Vec<String>,
    algorithm: &str,
) -> Result<Value, String> {
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

    let mut store = lb_store().lock().unwrap();
    if store.0.iter().any(|vs| vs.vip == vip && vs.site == site) {
        return Err(format!(
            "VIP '{}' is already in use at site '{}'",
            vip, site
        ));
    }

    let suffix = Uuid::new_v4()
        .to_string()
        .split('-')
        .next()
        .unwrap_or("unknown")
        .to_string();
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

    store.1.push(pool.clone());
    store.0.push(virtual_server.clone());
    store.2.push(request.clone());

    Ok(json!({
        "source": "dry-run",
        "action": "provision-lb",
        "providerCallsEnabled": false,
        "virtual_server": virtual_server,
        "pool": pool,
        "request": request
    }))
}

pub fn add_pool_member(vs_id: &str, hostname: &str, ip: &str, port: u16) -> Result<Value, String> {
    if hostname.trim().is_empty() {
        return Err("hostname cannot be empty".into());
    }
    if ip.trim().is_empty() {
        return Err("ip cannot be empty".into());
    }
    if port == 0 {
        return Err("port must be greater than zero".into());
    }

    let mut store = lb_store().lock().unwrap();
    let pool_id = store
        .0
        .iter()
        .find(|vs| vs.id == vs_id)
        .map(|vs| vs.pool_id.clone())
        .ok_or_else(|| format!("Virtual server '{}' not found", vs_id))?;
    let pool = store
        .1
        .iter_mut()
        .find(|candidate| candidate.id == pool_id)
        .ok_or_else(|| format!("Pool '{}' not found", pool_id))?;

    if pool
        .members
        .iter()
        .any(|member| member.hostname == hostname)
    {
        return Err(format!(
            "Pool member '{}' already exists on virtual server '{}'",
            hostname, vs_id
        ));
    }

    let member = PoolMember {
        hostname: hostname.to_string(),
        ip: ip.to_string(),
        port,
        weight: 1,
        status: PoolMemberStatus::Up,
    };
    pool.members.push(member.clone());

    Ok(json!({
        "source": "dry-run",
        "action": "add-pool-member",
        "virtual_server_id": vs_id,
        "pool_id": pool.id,
        "member": member,
        "member_count": pool.members.len()
    }))
}

pub fn remove_pool_member(vs_id: &str, hostname: &str) -> Result<Value, String> {
    let mut store = lb_store().lock().unwrap();
    let pool_id = store
        .0
        .iter()
        .find(|vs| vs.id == vs_id)
        .map(|vs| vs.pool_id.clone())
        .ok_or_else(|| format!("Virtual server '{}' not found", vs_id))?;
    let pool = store
        .1
        .iter_mut()
        .find(|candidate| candidate.id == pool_id)
        .ok_or_else(|| format!("Pool '{}' not found", pool_id))?;
    let original_len = pool.members.len();
    pool.members.retain(|member| member.hostname != hostname);

    if pool.members.len() == original_len {
        return Err(format!(
            "Pool member '{}' not found on virtual server '{}'",
            hostname, vs_id
        ));
    }

    Ok(json!({
        "source": "dry-run",
        "action": "remove-pool-member",
        "virtual_server_id": vs_id,
        "pool_id": pool.id,
        "removed_hostname": hostname,
        "member_count": pool.members.len()
    }))
}

pub fn drain_virtual_server(id: &str) -> Result<Value, String> {
    update_virtual_server_status(id, VirtualServerStatus::Draining, "drain-virtual-server")
}

pub fn disable_virtual_server(id: &str) -> Result<Value, String> {
    update_virtual_server_status(id, VirtualServerStatus::Offline, "disable-virtual-server")
}

pub fn enable_virtual_server(id: &str) -> Result<Value, String> {
    update_virtual_server_status(id, VirtualServerStatus::Online, "enable-virtual-server")
}

fn update_virtual_server_status(
    id: &str,
    status: VirtualServerStatus,
    action: &str,
) -> Result<Value, String> {
    let mut store = lb_store().lock().unwrap();
    let vs = store
        .0
        .iter_mut()
        .find(|candidate| candidate.id == id)
        .ok_or_else(|| format!("Virtual server '{}' not found", id))?;

    vs.status = status;

    Ok(json!({
        "source": "dry-run",
        "action": action,
        "providerCallsEnabled": false,
        "virtual_server": vs,
        "new_connections": if vs.status == VirtualServerStatus::Draining { "stopped" } else { "allowed" }
    }))
}

pub fn get_lb_status(site: &str) -> Result<Value, String> {
    let store = lb_store().lock().unwrap();
    let virtual_servers: Vec<&LbVirtualServer> = store
        .0
        .iter()
        .filter(|vs| site.is_empty() || vs.site == site)
        .collect();
    let pools: Vec<&LbPool> = store
        .1
        .iter()
        .filter(|pool| site.is_empty() || pool.site == site)
        .collect();
    let up_members = pools
        .iter()
        .flat_map(|pool| &pool.members)
        .filter(|member| member.status == PoolMemberStatus::Up)
        .count();
    let down_members = pools
        .iter()
        .flat_map(|pool| &pool.members)
        .filter(|member| member.status == PoolMemberStatus::Down)
        .count();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "virtual_server_count": virtual_servers.len(),
        "pool_count": pools.len(),
        "up_members": up_members,
        "down_members": down_members,
        "offline_virtual_servers": virtual_servers
            .iter()
            .filter(|vs| vs.status == VirtualServerStatus::Offline)
            .count(),
        "draining_virtual_servers": virtual_servers
            .iter()
            .filter(|vs| vs.status == VirtualServerStatus::Draining)
            .count()
    }))
}

pub fn validate_vip(vip: &str, site: &str) -> Result<Value, String> {
    if vip.trim().is_empty() {
        return Err("vip cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let store = lb_store().lock().unwrap();
    let conflict = store.0.iter().find(|vs| vs.vip == vip && vs.site == site);

    Ok(json!({
        "source": "dry-run",
        "vip": vip,
        "site": site,
        "available": conflict.is_none(),
        "conflict": conflict
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_site(prefix: &str) -> String {
        format!(
            "{}{}",
            prefix,
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("site")
                .to_ascii_uppercase()
        )
    }

    #[test]
    fn test_provision_and_list_lb() {
        let site = unique_site("LB");
        let provisioned = provision_lb(
            "test-web-vs",
            "10.99.10.10",
            443,
            "HTTPS",
            &site,
            vec!["test-web-01:10.99.20.11:8443".into()],
            "RoundRobin",
        )
        .unwrap();

        assert_eq!(provisioned["source"], "dry-run");
        assert_eq!(provisioned["virtual_server"]["name"], "test-web-vs");
        assert_eq!(provisioned["pool"]["members"].as_array().unwrap().len(), 1);

        let listed = list_virtual_servers(&site).unwrap();
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["virtual_servers"][0]["site"], site);
    }

    #[test]
    fn test_add_and_remove_pool_member() {
        let site = unique_site("LR");
        let provisioned = provision_lb(
            "member-test-vs",
            "10.99.10.11",
            80,
            "HTTP",
            &site,
            vec!["member-test-01:10.99.20.12:8080".into()],
            "LeastConnections",
        )
        .unwrap();
        let vs_id = provisioned["virtual_server"]["id"].as_str().unwrap();

        let added = add_pool_member(vs_id, "member-test-02", "10.99.20.13", 8080).unwrap();
        assert_eq!(added["member_count"], 2);
        assert_eq!(added["member"]["status"], "up");

        let removed = remove_pool_member(vs_id, "member-test-02").unwrap();
        assert_eq!(removed["member_count"], 1);
    }

    #[test]
    fn test_drain_and_enable_vs() {
        let site = unique_site("LD");
        let provisioned = provision_lb(
            "drain-test-vs",
            "10.99.10.12",
            443,
            "HTTPS",
            &site,
            vec!["drain-test-01:10.99.20.14:8443".into()],
            "Weighted",
        )
        .unwrap();
        let vs_id = provisioned["virtual_server"]["id"].as_str().unwrap();

        let drained = drain_virtual_server(vs_id).unwrap();
        assert_eq!(drained["virtual_server"]["status"], "draining");
        assert_eq!(drained["new_connections"], "stopped");

        let enabled = enable_virtual_server(vs_id).unwrap();
        assert_eq!(enabled["virtual_server"]["status"], "online");
        assert_eq!(enabled["new_connections"], "allowed");
    }

    #[test]
    fn test_validate_vip_conflict() {
        let validation = validate_vip("10.10.10.50", "DEFRA").unwrap();
        assert_eq!(validation["available"], false);
        assert_eq!(validation["conflict"]["id"], "vs-defra-web");
    }

    #[test]
    fn test_get_lb_status() {
        let status = get_lb_status("GBLON").unwrap();
        assert_eq!(status["source"], "dry-run");
        assert_eq!(status["virtual_server_count"], 1);
        assert_eq!(status["pool_count"], 1);
        assert_eq!(status["up_members"], 1);
        assert_eq!(status["down_members"], 1);
    }

    #[test]
    fn test_disable_vs() {
        let site = unique_site("LO");
        let provisioned = provision_lb(
            "disable-test-vs",
            "10.99.10.13",
            9000,
            "TCP",
            &site,
            vec!["disable-test-01:10.99.20.15:9000".into()],
            "RoundRobin",
        )
        .unwrap();
        let vs_id = provisioned["virtual_server"]["id"].as_str().unwrap();

        let disabled = disable_virtual_server(vs_id).unwrap();
        assert_eq!(disabled["virtual_server"]["status"], "offline");
    }

    #[test]
    fn test_pool_member_status() {
        let details = get_virtual_server("vs-gblon-api").unwrap();
        let members = details["pool_members"].as_array().unwrap();

        assert!(members.iter().any(|member| member["status"] == "up"));
        assert!(members.iter().any(|member| member["status"] == "down"));
    }
}
