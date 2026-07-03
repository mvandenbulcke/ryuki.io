use chrono::{Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    SRV,
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::AAAA => write!(f, "AAAA"),
            DnsRecordType::CNAME => write!(f, "CNAME"),
            DnsRecordType::MX => write!(f, "MX"),
            DnsRecordType::TXT => write!(f, "TXT"),
            DnsRecordType::SRV => write!(f, "SRV"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DnsRecordStatus {
    Active,
    Pending,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpamSubnetStatus {
    Available,
    Exhausted,
    Reserved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub zone: String,
    pub ttl: u32,
    pub site: String,
    pub status: DnsRecordStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamSubnet {
    pub id: String,
    pub cidr: String,
    pub gateway: String,
    pub vlan_id: u16,
    pub site: String,
    pub total_ips: u32,
    pub used_ips: u32,
    pub available_ips: u32,
    pub status: IpamSubnetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReservation {
    pub id: String,
    pub ip_address: String,
    pub subnet_id: String,
    pub hostname: String,
    pub purpose: String,
    pub reserved_by: String,
    pub reserved_at: String,
    pub expiry: String,
}

type DnsIpamStore = (Vec<DnsRecord>, Vec<IpamSubnet>, Vec<IpReservation>);

static STORE: OnceLock<Mutex<DnsIpamStore>> = OnceLock::new();

fn store() -> &'static Mutex<DnsIpamStore> {
    STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn parse_record_type(record_type: &str) -> Result<DnsRecordType, String> {
    match record_type {
        "A" => Ok(DnsRecordType::A),
        "AAAA" => Ok(DnsRecordType::AAAA),
        "CNAME" => Ok(DnsRecordType::CNAME),
        "MX" => Ok(DnsRecordType::MX),
        "TXT" => Ok(DnsRecordType::TXT),
        "SRV" => Ok(DnsRecordType::SRV),
        other => Err(format!(
            "Invalid record_type: {}. Must be A, AAAA, CNAME, MX, TXT, or SRV",
            other
        )),
    }
}

fn seed_data() -> DnsIpamStore {
    let now = Utc::now();
    let records = vec![
        DnsRecord {
            id: "dns-defra-001".into(),
            name: "portal.defra.ryuki.local".into(),
            record_type: DnsRecordType::A,
            value: "10.42.10.21".into(),
            zone: "defra.ryuki.local".into(),
            ttl: 300,
            site: "DEFRA".into(),
            status: DnsRecordStatus::Active,
        },
        DnsRecord {
            id: "dns-defra-002".into(),
            name: "api.defra.ryuki.local".into(),
            record_type: DnsRecordType::CNAME,
            value: "portal.defra.ryuki.local".into(),
            zone: "defra.ryuki.local".into(),
            ttl: 300,
            site: "DEFRA".into(),
            status: DnsRecordStatus::Active,
        },
        DnsRecord {
            id: "dns-defra-003".into(),
            name: "_sip._tcp.defra.ryuki.local".into(),
            record_type: DnsRecordType::SRV,
            value: "10 20 5060 sip.defra.ryuki.local".into(),
            zone: "defra.ryuki.local".into(),
            ttl: 600,
            site: "DEFRA".into(),
            status: DnsRecordStatus::Pending,
        },
        DnsRecord {
            id: "dns-gblon-001".into(),
            name: "portal.gblon.ryuki.local".into(),
            record_type: DnsRecordType::A,
            value: "10.42.20.21".into(),
            zone: "gblon.ryuki.local".into(),
            ttl: 300,
            site: "GBLON".into(),
            status: DnsRecordStatus::Active,
        },
        DnsRecord {
            id: "dns-gblon-002".into(),
            name: "mail.gblon.ryuki.local".into(),
            record_type: DnsRecordType::MX,
            value: "10 smtp.gblon.ryuki.local".into(),
            zone: "gblon.ryuki.local".into(),
            ttl: 3600,
            site: "GBLON".into(),
            status: DnsRecordStatus::Active,
        },
        DnsRecord {
            id: "dns-gblon-003".into(),
            name: "legacy.gblon.ryuki.local".into(),
            record_type: DnsRecordType::A,
            value: "10.42.20.45".into(),
            zone: "gblon.ryuki.local".into(),
            ttl: 300,
            site: "GBLON".into(),
            status: DnsRecordStatus::Deprecated,
        },
        DnsRecord {
            id: "dns-nlams-001".into(),
            name: "portal.nlams.ryuki.local".into(),
            record_type: DnsRecordType::AAAA,
            value: "2001:db8:42:30::21".into(),
            zone: "nlams.ryuki.local".into(),
            ttl: 300,
            site: "NLAMS".into(),
            status: DnsRecordStatus::Active,
        },
        DnsRecord {
            id: "dns-nlams-002".into(),
            name: "txt.nlams.ryuki.local".into(),
            record_type: DnsRecordType::TXT,
            value: "site-verification=dry-run".into(),
            zone: "nlams.ryuki.local".into(),
            ttl: 3600,
            site: "NLAMS".into(),
            status: DnsRecordStatus::Active,
        },
    ];

    let subnets = vec![
        IpamSubnet {
            id: "subnet-defra-001".into(),
            cidr: "10.42.10.0/24".into(),
            gateway: "10.42.10.1".into(),
            vlan_id: 110,
            site: "DEFRA".into(),
            total_ips: 254,
            used_ips: 60,
            available_ips: 194,
            status: IpamSubnetStatus::Available,
        },
        IpamSubnet {
            id: "subnet-defra-002".into(),
            cidr: "10.42.11.0/24".into(),
            gateway: "10.42.11.1".into(),
            vlan_id: 111,
            site: "DEFRA".into(),
            total_ips: 254,
            used_ips: 254,
            available_ips: 0,
            status: IpamSubnetStatus::Exhausted,
        },
        IpamSubnet {
            id: "subnet-gblon-001".into(),
            cidr: "10.42.20.0/24".into(),
            gateway: "10.42.20.1".into(),
            vlan_id: 210,
            site: "GBLON".into(),
            total_ips: 254,
            used_ips: 80,
            available_ips: 174,
            status: IpamSubnetStatus::Available,
        },
        IpamSubnet {
            id: "subnet-nlams-001".into(),
            cidr: "10.42.30.0/24".into(),
            gateway: "10.42.30.1".into(),
            vlan_id: 310,
            site: "NLAMS".into(),
            total_ips: 254,
            used_ips: 120,
            available_ips: 134,
            status: IpamSubnetStatus::Reserved,
        },
    ];

    let reservations = vec![
        IpReservation {
            id: "res-defra-001".into(),
            ip_address: "10.42.10.21".into(),
            subnet_id: "subnet-defra-001".into(),
            hostname: "portal-defra-01".into(),
            purpose: "Portal frontend".into(),
            reserved_by: "netops".into(),
            reserved_at: (now - chrono::Duration::days(10)).to_rfc3339(),
            expiry: (now + Days::new(80)).to_rfc3339(),
        },
        IpReservation {
            id: "res-defra-002".into(),
            ip_address: "10.42.10.22".into(),
            subnet_id: "subnet-defra-001".into(),
            hostname: "api-defra-01".into(),
            purpose: "API node".into(),
            reserved_by: "platform".into(),
            reserved_at: (now - chrono::Duration::days(8)).to_rfc3339(),
            expiry: (now + Days::new(82)).to_rfc3339(),
        },
        IpReservation {
            id: "res-gblon-001".into(),
            ip_address: "10.42.20.21".into(),
            subnet_id: "subnet-gblon-001".into(),
            hostname: "portal-gblon-01".into(),
            purpose: "Portal frontend".into(),
            reserved_by: "netops".into(),
            reserved_at: (now - chrono::Duration::days(9)).to_rfc3339(),
            expiry: (now + Days::new(81)).to_rfc3339(),
        },
        IpReservation {
            id: "res-gblon-002".into(),
            ip_address: "10.42.20.45".into(),
            subnet_id: "subnet-gblon-001".into(),
            hostname: "legacy-gblon-01".into(),
            purpose: "Legacy service".into(),
            reserved_by: "ops".into(),
            reserved_at: (now - chrono::Duration::days(30)).to_rfc3339(),
            expiry: (now + Days::new(15)).to_rfc3339(),
        },
        IpReservation {
            id: "res-nlams-001".into(),
            ip_address: "10.42.30.21".into(),
            subnet_id: "subnet-nlams-001".into(),
            hostname: "portal-nlams-01".into(),
            purpose: "Portal frontend".into(),
            reserved_by: "netops".into(),
            reserved_at: (now - chrono::Duration::days(7)).to_rfc3339(),
            expiry: (now + Days::new(83)).to_rfc3339(),
        },
    ];

    (records, subnets, reservations)
}

fn next_ip(subnet: &IpamSubnet, reservations: &[IpReservation]) -> Result<String, String> {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    // Honor the REAL CIDR. The old allocator took only the first 3 octets and scanned
    // a hardcoded `.10..=.254`, which (a) ignored the prefix entirely — so for any
    // non-/24 subnet it could return an address OUTSIDE the range (e.g. a /30 or the
    // wrong half of a /25), and (b) never offered `.2..=.9`. parse_cidr canonicalises
    // the network address + prefix via Ipv4Addr.
    let (addr, prefix) = parse_cidr(&subnet.cidr)?;
    // /31 and /32 have no conventional usable host range (matches usable_hosts -> 0).
    if prefix >= 31 {
        return Err(format!(
            "No allocatable IPs remain in subnet '{}'",
            subnet.id
        ));
    }
    let host_bits = 32 - prefix; // prefix is 0..=30 here, so host_bits is 2..=32
    // Avoid an out-of-range shift for a /0 (host_bits == 32).
    let mask: u32 = if host_bits >= 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let base = u32::from(addr) & mask; // network base (also normalises a non-aligned CIDR)
    let broadcast = base | !mask;
    // Usable hosts are the addresses strictly between network and broadcast.
    let first = base.wrapping_add(1);
    let last = broadcast.wrapping_sub(1);

    // Skip the gateway and any already-reserved IP. A u32 HashSet gives O(1) membership
    // so a large subnet doesn't re-scan the reservation list per candidate; the loop
    // returns the FIRST free address (the first gap at or after `first`).
    let gateway = subnet.gateway.parse::<Ipv4Addr>().map(u32::from).ok();
    let reserved: HashSet<u32> = reservations
        .iter()
        .filter_map(|r| r.ip_address.parse::<Ipv4Addr>().ok().map(u32::from))
        .collect();

    let mut candidate = first;
    loop {
        if Some(candidate) != gateway && !reserved.contains(&candidate) {
            return Ok(Ipv4Addr::from(candidate).to_string());
        }
        if candidate == last {
            break;
        }
        candidate = candidate.wrapping_add(1);
    }
    Err(format!(
        "No allocatable IPs remain in subnet '{}'",
        subnet.id
    ))
}

pub fn list_dns_records(site: &str, record_type: &str) -> Result<Value, String> {
    let parsed_record_type = if record_type.is_empty() {
        None
    } else {
        Some(parse_record_type(record_type)?)
    };
    let store = store().lock().unwrap();
    let records: Vec<DnsRecord> = store
        .0
        .iter()
        .filter(|record| site.is_empty() || record.site == site)
        .filter(|record| {
            parsed_record_type
                .as_ref()
                .is_none_or(|record_type| record.record_type == *record_type)
        })
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "records": records,
        "count": records.len()
    }))
}

pub fn get_dns_record(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let record = store
        .0
        .iter()
        .find(|record| record.id == id)
        .ok_or_else(|| format!("DNS record '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "record": record
    }))
}

/// Pure validation + construction of a DNS record — NO store mutation, NO I/O.
/// This is the building block the persistence layer (ryuki-api) uses: it can
/// construct the typed record, persist it to the database, and reconstruct the
/// same shape on read, while the engine stays storage-free. `create_dns_record`
/// keeps the in-memory (no-DB) behavior by pushing the result onto the static.
pub fn build_dns_record(
    name: &str,
    record_type: &str,
    value: &str,
    zone: &str,
    ttl: u32,
    site: &str,
) -> Result<DnsRecord, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if value.trim().is_empty() {
        return Err("value cannot be empty".into());
    }
    if zone.trim().is_empty() {
        return Err("zone cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    // RFC 2181 caps a DNS TTL at i32::MAX; reject anything larger so it can never
    // wrap to a negative value when persisted to the INTEGER `ttl` column.
    if ttl > i32::MAX as u32 {
        return Err(format!("ttl {ttl} exceeds the maximum {}", i32::MAX));
    }

    let record_type = parse_record_type(record_type)?;
    let id = format!(
        "dns-{}-{}",
        site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    Ok(DnsRecord {
        id,
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        zone: zone.to_string(),
        ttl,
        site: site.to_string(),
        status: DnsRecordStatus::Pending,
    })
}

/// Parse an IPv4 CIDR `a.b.c.d/N` into its address and prefix. Uses
/// `Ipv4Addr` (canonical — rejects leading-zero octets and out-of-range bytes).
/// Pure helper.
fn parse_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u32), String> {
    use std::str::FromStr;
    let (network, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR '{cidr}' must be in a.b.c.d/N form"))?;
    let addr = std::net::Ipv4Addr::from_str(network)
        .map_err(|_| format!("CIDR network '{network}' is not a valid IPv4 address"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| format!("CIDR prefix '{prefix_str}' is not a number"))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix /{prefix} must be 0..=32"));
    }
    Ok((addr, prefix))
}

/// Usable host count for a prefix length — `2^(32-N) - 2` (excluding the network
/// and broadcast addresses), saturating to 0 for /31 and /32. Computed in u64 so
/// a /0 cannot overflow.
fn usable_hosts(prefix: u32) -> u32 {
    let host_bits = 32 - prefix;
    let total: u64 = 1u64 << host_bits; // host_bits is 0..=32, fits u64
    u32::try_from(total.saturating_sub(2)).unwrap_or(u32::MAX)
}

/// Usable host count for an IPv4 CIDR `a.b.c.d/N`. Errors on a malformed CIDR or
/// an out-of-range prefix. Pure.
pub fn usable_hosts_from_cidr(cidr: &str) -> Result<u32, String> {
    let (_, prefix) = parse_cidr(cidr)?;
    Ok(usable_hosts(prefix))
}

/// Validate the user-settable fields of a subnet and return its usable-host
/// count. The gateway must be a valid IPv4 address WITHIN the subnet, and not
/// the network or broadcast address (for /0../30). Shared by create and update
/// so the two cannot diverge. Pure.
pub fn validate_subnet_fields(cidr: &str, gateway: &str, vlan_id: u16) -> Result<u32, String> {
    use std::str::FromStr;
    // 0 and 4095 are reserved VLAN ids; usable range is 1..=4094.
    if vlan_id == 0 || vlan_id > 4094 {
        return Err(format!("vlan_id {vlan_id} must be in 1..=4094"));
    }
    let (addr, prefix) = parse_cidr(cidr)?;
    let gw = std::net::Ipv4Addr::from_str(gateway)
        .map_err(|_| format!("gateway '{gateway}' is not a valid IPv4 address"))?;
    // Mask for the prefix (guarding the prefix==0 shift-by-32, which is UB).
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(addr) & mask; // canonicalize whatever host bits were given
    let gw_u = u32::from(gw);
    if gw_u & mask != network {
        return Err(format!("gateway '{gateway}' is not within {cidr}"));
    }
    // For a subnet with usable hosts, the gateway cannot be the network or
    // broadcast address.
    if prefix <= 30 {
        let broadcast = network | !mask;
        if gw_u == network {
            return Err(format!(
                "gateway '{gateway}' cannot be the network address of {cidr}"
            ));
        }
        if gw_u == broadcast {
            return Err(format!(
                "gateway '{gateway}' cannot be the broadcast address of {cidr}"
            ));
        }
    }
    Ok(usable_hosts(prefix))
}

/// Validate and construct a fresh IPAM subnet (no static mutation — the caller
/// persists it). `total_ips`/`available_ips` are derived from the CIDR; the
/// subnet starts empty (`used_ips = 0`) and `Available`. Mirrors
/// [`build_dns_record`]'s validate-then-construct contract.
pub fn build_ipam_subnet(
    cidr: &str,
    gateway: &str,
    vlan_id: u16,
    site: &str,
) -> Result<IpamSubnet, String> {
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    let total_ips = validate_subnet_fields(cidr, gateway, vlan_id)?;
    // Slug the site into the id so it is always URL-path-safe (the id appears in
    // /api/network/ipam/subnets/{id}); fall back to "site" if it slugs empty.
    let slug: String = site
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let slug = if slug.is_empty() {
        "site".to_string()
    } else {
        slug
    };
    let id = format!(
        "subnet-{}-{}",
        slug,
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    Ok(IpamSubnet {
        id,
        cidr: cidr.to_string(),
        gateway: gateway.to_string(),
        vlan_id,
        site: site.to_string(),
        total_ips,
        used_ips: 0,
        available_ips: total_ips,
        status: IpamSubnetStatus::Available,
    })
}

pub fn create_dns_record(
    name: &str,
    record_type: &str,
    value: &str,
    zone: &str,
    ttl: u32,
    site: &str,
) -> Result<Value, String> {
    let record = build_dns_record(name, record_type, value, zone, ttl, site)?;
    store().lock().unwrap().0.push(record.clone());

    Ok(json!({
        "source": "dry-run",
        "record": record
    }))
}

pub fn delete_dns_record(id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let before = store.0.len();
    store.0.retain(|record| record.id != id);
    if store.0.len() == before {
        return Err(format!("DNS record '{}' not found", id));
    }

    Ok(json!({
        "source": "dry-run",
        "deleted": true,
        "record_id": id
    }))
}

pub fn list_subnets(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let subnets: Vec<Value> = store
        .1
        .iter()
        .filter(|subnet| site.is_empty() || subnet.site == site)
        .map(|subnet| {
            let utilization = if subnet.total_ips == 0 {
                0.0
            } else {
                (subnet.used_ips as f64 / subnet.total_ips as f64) * 100.0
            };
            json!({
                "subnet": subnet,
                "utilization_percent": utilization
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "subnets": subnets,
        "count": subnets.len()
    }))
}

pub fn get_subnet(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let subnet = store
        .1
        .iter()
        .find(|subnet| subnet.id == id)
        .ok_or_else(|| format!("Subnet '{}' not found", id))?;
    let reservations: Vec<IpReservation> = store
        .2
        .iter()
        .filter(|reservation| reservation.subnet_id == id)
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "subnet": subnet,
        "available_ips": subnet.available_ips,
        "reservations": reservations
    }))
}

/// PURE: validate the inputs, pick the next free IP within `subnet` (skipping
/// the gateway and any address already in `existing`), and construct the
/// reservation — WITHOUT touching the static store. ryuki-api calls this to
/// persist a reservation durably (then UPDATEs the subnet counters in SQL); the
/// static `reserve_ip` below calls it then mutates the in-process fallback
/// store. Keeping the id/IP/timestamp construction here means DB mode and the
/// no-DB demo mint identical reservations.
pub fn build_reservation(
    subnet: &IpamSubnet,
    existing: &[IpReservation],
    hostname: &str,
    purpose: &str,
    reserved_by: &str,
    ttl_days: u64,
) -> Result<IpReservation, String> {
    if hostname.trim().is_empty() {
        return Err("hostname cannot be empty".into());
    }
    if purpose.trim().is_empty() {
        return Err("purpose cannot be empty".into());
    }
    if reserved_by.trim().is_empty() {
        return Err("reserved_by cannot be empty".into());
    }
    if subnet.available_ips == 0 {
        return Err(format!("Subnet '{}' has no available IPs", subnet.id));
    }

    let ip_address = next_ip(subnet, existing)?;
    Ok(IpReservation {
        id: format!(
            "res-{}-{}",
            subnet.site.to_lowercase(),
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("unknown")
        ),
        ip_address,
        subnet_id: subnet.id.clone(),
        hostname: hostname.to_string(),
        purpose: purpose.to_string(),
        reserved_by: reserved_by.to_string(),
        reserved_at: now_iso(),
        expiry: (Utc::now() + Days::new(ttl_days)).to_rfc3339(),
    })
}

pub fn reserve_ip(
    subnet_id: &str,
    hostname: &str,
    purpose: &str,
    reserved_by: &str,
    ttl_days: u64,
) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let subnet_index = store
        .1
        .iter()
        .position(|subnet| subnet.id == subnet_id)
        .ok_or_else(|| format!("Subnet '{}' not found", subnet_id))?;

    let reservation = build_reservation(
        &store.1[subnet_index],
        &store.2,
        hostname,
        purpose,
        reserved_by,
        ttl_days,
    )?;

    store.1[subnet_index].used_ips += 1;
    store.1[subnet_index].available_ips -= 1;
    if store.1[subnet_index].available_ips == 0 {
        store.1[subnet_index].status = IpamSubnetStatus::Exhausted;
    }
    store.2.push(reservation.clone());

    Ok(json!({
        "source": "dry-run",
        "reservation": reservation,
        "subnet": store.1[subnet_index]
    }))
}

pub fn release_ip(reservation_id: &str) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let reservation_index = store
        .2
        .iter()
        .position(|reservation| reservation.id == reservation_id)
        .ok_or_else(|| format!("Reservation '{}' not found", reservation_id))?;
    let reservation = store.2.remove(reservation_index);

    if let Some(subnet) = store
        .1
        .iter_mut()
        .find(|subnet| subnet.id == reservation.subnet_id)
    {
        subnet.used_ips = subnet.used_ips.saturating_sub(1);
        // Saturating + clamped to capacity (matches the DB path's
        // LEAST(available_ips + 1, total_ips)): a release can never push the counter
        // past total_ips or wrap, symmetric with the used_ips saturating_sub above.
        subnet.available_ips = subnet.available_ips.saturating_add(1).min(subnet.total_ips);
        if subnet.status == IpamSubnetStatus::Exhausted {
            subnet.status = IpamSubnetStatus::Available;
        }
    }

    Ok(json!({
        "source": "dry-run",
        "released": true,
        "reservation": reservation
    }))
}

pub fn get_ipam_summary(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let subnets: Vec<&IpamSubnet> = store
        .1
        .iter()
        .filter(|subnet| site.is_empty() || subnet.site == site)
        .collect();
    let total_ips: u32 = subnets.iter().map(|subnet| subnet.total_ips).sum();
    let used_ips: u32 = subnets.iter().map(|subnet| subnet.used_ips).sum();
    let available_ips: u32 = subnets.iter().map(|subnet| subnet.available_ips).sum();

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "ALL" } else { site },
        "total_ips": total_ips,
        "used_ips": used_ips,
        "available_ips": available_ips,
        "subnet_count": subnets.len()
    }))
}

pub fn check_ip_availability(subnet_id: &str, count: u32) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let subnet = store
        .1
        .iter()
        .find(|subnet| subnet.id == subnet_id)
        .ok_or_else(|| format!("Subnet '{}' not found", subnet_id))?;

    Ok(json!({
        "source": "dry-run",
        "subnet_id": subnet_id,
        "requested_ips": count,
        "available_ips": subnet.available_ips,
        "can_allocate": subnet.available_ips >= count
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dns_record_validates_and_constructs() {
        // Pure validation + construction — it never touches the static store
        // (that is create_dns_record's / the DB layer's job), so this test makes
        // no global-state assertions that would race other parallel tests.
        let record = build_dns_record(
            "pure.defra.ryuki.local",
            "CNAME",
            "alias.defra.ryuki.local",
            "defra.ryuki.local",
            300,
            "DEFRA",
        )
        .expect("valid record builds");
        assert!(record.id.starts_with("dns-defra-"));
        assert_eq!(record.record_type, DnsRecordType::CNAME);
        assert_eq!(record.status, DnsRecordStatus::Pending);
        // The Display string the DB persists matches the serde serialization.
        assert_eq!(record.record_type.to_string(), "CNAME");

        // Validation rejects empties and bad record types.
        assert!(build_dns_record("", "A", "v", "z", 1, "S").is_err());
        assert!(build_dns_record("n", "BOGUS", "v", "z", 1, "S").is_err());
    }

    #[test]
    fn usable_hosts_from_cidr_computes_and_validates() {
        assert_eq!(usable_hosts_from_cidr("10.0.0.0/24"), Ok(254));
        assert_eq!(usable_hosts_from_cidr("10.0.0.0/30"), Ok(2));
        assert_eq!(usable_hosts_from_cidr("10.0.0.0/31"), Ok(0));
        assert_eq!(usable_hosts_from_cidr("10.0.0.0/32"), Ok(0));
        // /0 is 2^32-2, which fits a u32.
        assert_eq!(usable_hosts_from_cidr("0.0.0.0/0"), Ok(4_294_967_294));
        assert!(usable_hosts_from_cidr("10.0.0.0").is_err(), "no prefix");
        assert!(
            usable_hosts_from_cidr("not-an-ip/24").is_err(),
            "bad network"
        );
        assert!(
            usable_hosts_from_cidr("10.0.0.0/33").is_err(),
            "prefix > 32"
        );
        assert!(
            usable_hosts_from_cidr("10.0.0.0/x").is_err(),
            "non-numeric prefix"
        );
    }

    #[test]
    fn build_ipam_subnet_validates_and_constructs() {
        let s = build_ipam_subnet("10.20.30.0/24", "10.20.30.1", 100, "DEFRA")
            .expect("valid subnet builds");
        assert!(s.id.starts_with("subnet-defra-"));
        assert_eq!(s.total_ips, 254);
        assert_eq!(s.available_ips, 254);
        assert_eq!(s.used_ips, 0);
        assert_eq!(s.status, IpamSubnetStatus::Available);

        // Rejections: empty site, bad gateway, out-of-range VLAN, bad CIDR.
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.1", 100, "").is_err());
        assert!(build_ipam_subnet("10.0.0.0/24", "not-an-ip", 100, "S").is_err());
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.1", 0, "S").is_err());
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.1", 5000, "S").is_err());
        assert!(build_ipam_subnet("bogus", "10.0.0.1", 100, "S").is_err());
    }

    #[test]
    fn gateway_must_be_inside_the_subnet() {
        // Outside the CIDR.
        assert!(build_ipam_subnet("10.0.0.0/24", "192.168.1.1", 100, "S").is_err());
        // The network address itself.
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.0", 100, "S").is_err());
        // The broadcast address.
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.255", 100, "S").is_err());
        // A valid interior host is accepted.
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.42", 100, "S").is_ok());
        // Leading-zero octets are rejected (non-canonical).
        assert!(build_ipam_subnet("10.0.0.0/24", "10.0.0.01", 100, "S").is_err());
    }

    #[test]
    fn test_create_and_list_dns_records() {
        let created = create_dns_record(
            "test-create.defra.ryuki.local",
            "A",
            "10.42.10.200",
            "defra.ryuki.local",
            300,
            "DEFRA",
        )
        .unwrap();
        let record_id = created["record"]["id"].as_str().unwrap();

        let listed = list_dns_records("DEFRA", "").unwrap();
        let records = listed["records"].as_array().unwrap();
        assert!(records.iter().any(|record| record["id"] == record_id));
    }

    #[test]
    fn test_delete_dns_record() {
        let created = create_dns_record(
            "test-delete.gblon.ryuki.local",
            "TXT",
            "delete-me",
            "gblon.ryuki.local",
            300,
            "GBLON",
        )
        .unwrap();
        let record_id = created["record"]["id"].as_str().unwrap();

        let deleted = delete_dns_record(record_id).unwrap();
        assert_eq!(deleted["deleted"], true);
        assert!(get_dns_record(record_id).is_err());
    }

    #[test]
    fn test_list_dns_by_type() {
        let listed = list_dns_records("", "MX").unwrap();
        let records = listed["records"].as_array().unwrap();
        assert!(!records.is_empty());
        assert!(
            records
                .iter()
                .all(|record| record["record_type"].as_str().unwrap() == "MX")
        );
    }

    #[test]
    fn test_reserve_and_release_ip() {
        let reserved = reserve_ip(
            "subnet-defra-001",
            "test-reservation-defra-01",
            "Integration test",
            "tester",
            7,
        )
        .unwrap();
        let reservation_id = reserved["reservation"]["id"].as_str().unwrap();

        let released = release_ip(reservation_id).unwrap();
        assert_eq!(released["released"], true);
        assert_eq!(released["reservation"]["id"], reservation_id);
    }

    #[test]
    fn build_reservation_is_pure_and_allocates_free_ip() {
        // No store access: build_reservation works purely off its arguments, so
        // ryuki-api can drive it against DB-loaded subnets/reservations.
        let subnet = IpamSubnet {
            id: "subnet-x-001".into(),
            cidr: "10.0.0.0/24".into(),
            gateway: "10.0.0.1".into(),
            vlan_id: 10,
            site: "X".into(),
            total_ips: 254,
            used_ips: 5,
            available_ips: 249,
            status: IpamSubnetStatus::Available,
        };
        let existing = vec![];
        let reservation =
            build_reservation(&subnet, &existing, "host-a", "purpose", "tester", 7).unwrap();
        assert_eq!(reservation.subnet_id, "subnet-x-001");
        // First usable host is network+1 = .1, which is the gateway, so the first
        // OFFERED address is .2 (the allocator now honors the real host range and no
        // longer skips .2..=.9 or hardcodes a .10 start).
        assert_eq!(reservation.ip_address, "10.0.0.2");
        assert!(reservation.id.starts_with("res-x-"));

        // Empty required fields are rejected.
        assert!(build_reservation(&subnet, &existing, "", "p", "t", 7).is_err());
        // An exhausted subnet cannot allocate.
        let exhausted = IpamSubnet {
            available_ips: 0,
            ..subnet.clone()
        };
        assert!(build_reservation(&exhausted, &existing, "h", "p", "t", 7).is_err());
    }

    /// next_ip (via build_reservation) honors the REAL CIDR prefix — it never returns
    /// an address outside the subnet, and allocates from the correct host range.
    #[test]
    fn next_ip_honors_the_cidr_prefix() {
        let mk = |cidr: &str, gateway: &str| IpamSubnet {
            id: "sn".into(),
            cidr: cidr.into(),
            gateway: gateway.into(),
            vlan_id: 10,
            site: "X".into(),
            total_ips: 100,
            used_ips: 0,
            available_ips: 100,
            status: IpamSubnetStatus::Available,
        };
        let alloc = |subnet: &IpamSubnet, existing: &[IpReservation]| {
            build_reservation(subnet, existing, "h", "p", "t", 7).map(|r| r.ip_address)
        };

        // /25 upper half: the allocated IP must be in .129..=.254, NOT .10 (the old bug
        // would have returned "10.0.0.10", which is in the OTHER /25).
        let s25 = mk("10.0.0.128/25", "10.0.0.129");
        let ip = alloc(&s25, &[]).unwrap();
        let last_octet: u32 = ip.rsplit('.').next().unwrap().parse().unwrap();
        assert!(
            ip.starts_with("10.0.0.") && (130..=254).contains(&last_octet),
            "/25 upper-half allocation must be within .130..=.254, got {ip}"
        );

        // /30 (10.0.0.0/30): usable .1/.2; gateway .1 -> only .2 is allocatable.
        let s30 = mk("10.0.0.0/30", "10.0.0.1");
        assert_eq!(
            alloc(&s30, &[]).unwrap(),
            "10.0.0.2",
            "/30 allocates the lone .2"
        );
        // With .2 reserved, the /30 is exhausted (NOT a bogus out-of-range .3+).
        let r2 = IpReservation {
            id: "r".into(),
            ip_address: "10.0.0.2".into(),
            subnet_id: "sn".into(),
            hostname: "h".into(),
            purpose: "p".into(),
            reserved_by: "t".into(),
            reserved_at: "x".into(),
            expiry: "x".into(),
        };
        assert!(
            alloc(&s30, std::slice::from_ref(&r2)).is_err(),
            "/30 with .2 taken is exhausted"
        );

        // /16: allocates within the subnet (network+1 skipping the gateway), in range.
        let s16 = mk("10.42.0.0/16", "10.42.0.1");
        let ip16 = alloc(&s16, &[]).unwrap();
        assert_eq!(
            ip16, "10.42.0.2",
            "/16 first offered host is network+2 (gateway is +1)"
        );
    }

    #[test]
    fn test_check_ip_availability() {
        let available = check_ip_availability("subnet-gblon-001", 10).unwrap();
        assert_eq!(available["can_allocate"], true);

        let unavailable = check_ip_availability("subnet-defra-002", 1).unwrap();
        assert_eq!(unavailable["can_allocate"], false);
    }

    #[test]
    fn test_ipam_summary() {
        let summary = get_ipam_summary("GBLON").unwrap();
        assert_eq!(summary["site"], "GBLON");
        assert_eq!(summary["subnet_count"], 1);
        assert!(summary["total_ips"].as_u64().unwrap() >= summary["used_ips"].as_u64().unwrap());
    }

    #[test]
    fn test_subnet_not_found_error() {
        assert!(get_subnet("subnet-missing-001").is_err());
        assert!(reserve_ip("subnet-missing-001", "host", "purpose", "tester", 7).is_err());
    }
}
