use dns_lookup;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Instant, Duration};

lazy_static::lazy_static! {
    static ref SHOULD_RUN: AtomicBool = AtomicBool::new(true);
    static ref HEURISTICS_ENABLED: AtomicBool = AtomicBool::new(true);
    static ref SELECTED_INTERFACE: Mutex<Option<String>> = Mutex::new(None);
    static ref PORT_MAP: Mutex<HashMap<u16, (u32, String)>> = Mutex::new(HashMap::new());
    static ref GEO_CACHE: Mutex<HashMap<String, GeoInfo>> = Mutex::new(HashMap::new());
    static ref GEO_IN_FLIGHT: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    // IPs that couldn't be resolved this session — skip retrying until next launch
    static ref GEO_FAILED: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref HOSTNAME_CACHE: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref HOSTNAME_IN_FLIGHT: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub index: u32,
}

// Advanced Heuristics Engine (Guardian Core v1.0)
const MALICIOUS_IPS: &[&str] = &[
    "45.182.18.5", 
    "185.220.101.4",
    "103.212.222.11",
];

const SUSPICIOUS_PORTS: &[u16] = &[
    6667, 4444, 31337, 1337,
];

// ─── Local Network Intelligence ──────────────────────────────────────────────

fn is_local_ip(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return v4.is_private() || v4.is_loopback() || v4.is_link_local()
            || v4.is_broadcast() || v4.is_multicast();
    }
    if let Ok(_v6) = ip.parse::<std::net::Ipv6Addr>() {
        // fe80::/10 link-local, fc00::/7 ULA, ::1 loopback, ff00::/8 multicast
        return ip.starts_with("fe80") || ip.starts_with("fc") || ip.starts_with("fd")
            || ip == "::1" || ip.starts_with("ff");
    }
    false
}

fn is_multicast_ip(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return v4.is_multicast();
    }
    if let Ok(_) = ip.parse::<std::net::Ipv6Addr>() {
        return ip.starts_with("ff");
    }
    false
}

/// Returns a human-readable service label for well-known LAN server ports.
fn local_port_service(port: u16) -> Option<&'static str> {
    match port {
        22   => Some("SSH"),
        23   => Some("Telnet"),
        25   => Some("SMTP"),
        53   => Some("DNS"),
        67 | 68 => Some("DHCP"),
        80   => Some("HTTP"),
        110  => Some("POP3"),
        143  => Some("IMAP"),
        161  => Some("SNMP"),
        389  => Some("LDAP"),
        443  => Some("HTTPS"),
        445  => Some("SMB"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        8080 | 8443 | 8888 => Some("Web (alt)"),
        9200 => Some("Elasticsearch"),
        27017 => Some("MongoDB"),
        _    => None,
    }
}

/// Cheap MAC OUI lookup — covers the most common device vendors.
fn lookup_oui(mac_bytes: &[u8]) -> &'static str {
    if mac_bytes.len() < 3 { return "Unknown"; }
    match (mac_bytes[0], mac_bytes[1], mac_bytes[2]) {
        // Apple
        (0x00, 0x17, 0xf2) | (0x00, 0x1b, 0x63) | (0x00, 0x1c, 0xb3)
        | (0x00, 0x23, 0xdf) | (0x00, 0x25, 0x4b) | (0x00, 0x26, 0xb9)
        | (0x28, 0xcf, 0xda) | (0x3c, 0x07, 0x71) | (0x3c, 0x15, 0xc2)
        | (0xac, 0xde, 0x48) | (0xf0, 0xb4, 0x79) | (0x00, 0x3e, 0xe1)
        | (0x58, 0xd9, 0xd5) | (0xa8, 0x96, 0x8a) | (0x10, 0x9a, 0xdd) => "Apple",
        // Samsung
        (0x00, 0x12, 0xfb) | (0x00, 0x15, 0x99) | (0x00, 0x1e, 0xe1)
        | (0x08, 0xec, 0xa9) | (0x5c, 0x0a, 0x5b) | (0x8c, 0x77, 0x12)
        | (0xa0, 0x10, 0x81) | (0xcc, 0x07, 0xab) => "Samsung",
        // Intel (Wi-Fi adapters, common in laptops)
        (0x00, 0x1b, 0x21) | (0x00, 0x21, 0x6a) | (0x5c, 0x51, 0x4f)
        | (0x8c, 0x8d, 0x28) | (0xa4, 0xc3, 0xf0) | (0xe0, 0xd5, 0x5e) => "Intel",
        // Raspberry Pi
        (0xb8, 0x27, 0xeb) | (0xdc, 0xa6, 0x32) | (0xe4, 0x5f, 0x01) => "Raspberry Pi",
        // TP-Link
        (0x14, 0xcc, 0x20) | (0x50, 0xc7, 0xbf) | (0x64, 0x70, 0x02)
        | (0x6c, 0x4b, 0x90) | (0xa0, 0xf3, 0xc1) | (0xec, 0x08, 0x6b) => "TP-Link",
        // Netgear
        (0x00, 0x09, 0x5b) | (0x00, 0x14, 0x6c) | (0x1c, 0x1b, 0x0d)
        | (0x20, 0x4e, 0x7f) | (0x2c, 0xb0, 0x5d) | (0x30, 0x46, 0x9a) => "Netgear",
        // ASUS
        (0x00, 0x1a, 0x92) | (0x04, 0x92, 0x26) | (0x10, 0x7b, 0x44)
        | (0x2c, 0xfd, 0xa1) | (0x50, 0x46, 0x5d) | (0xac, 0x9e, 0x17) => "ASUS",
        // Ubiquiti
        (0x00, 0x27, 0x22) | (0x04, 0x18, 0xd6) | (0x24, 0xa4, 0x3c)
        | (0x44, 0xd9, 0xe7) | (0x68, 0x72, 0x51) | (0xdc, 0x9f, 0xdb) => "Ubiquiti",
        // VMware (virtual)
        (0x00, 0x50, 0x56) | (0x00, 0x0c, 0x29) | (0x00, 0x05, 0x69) => "VMware (Virtual)",
        _ => "Unknown",
    }
}

/// Infer OS from TTL and TCP window. TTL=128 is Windows-exclusive;
/// TTL=255 is network equipment; anything else is ambiguous so we
/// only return a label when we have a strong signal.
fn infer_os(ttl: u8, tcp_window: u16) -> Option<&'static str> {
    match ttl {
        128 => Some("Windows"),
        255 => Some("Network Equipment"),
        64 | 63 => {
            match tcp_window {
                65535 => Some("macOS/iOS"),
                14600 | 29200 | 43800 => Some("Linux"),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Build a GeoInfo for a local-network IP, using what we know from
/// the packet itself (MAC OUI, TTL, window, hostname, ports).
fn classify_local_ip(
    ip: &str,
    mac: &str,
    ttl: u8,
    tcp_window: u16,
    port: u16,
) -> GeoInfo {
    let manufacturer = if !mac.is_empty() {
        let parts: Vec<u8> = mac.split(':')
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        lookup_oui(&parts).to_string()
    } else {
        "Unknown".to_string()
    };

    let os_guess = infer_os(ttl, tcp_window)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown OS".to_string());

    let service = local_port_service(port)
        .map(|s| format!(" · {}", s))
        .unwrap_or_default();

    let hostname = HOSTNAME_CACHE.lock().unwrap().get(ip).cloned()
        .unwrap_or_default();

    let city = if hostname.is_empty() { ip.to_string() } else { hostname };
    let region = os_guess;
    let asn = manufacturer;
    let org = format!("LAN Device{}", service);

    GeoInfo {
        city,
        region,
        country_code: "LAN".to_string(),
        asn,
        org,
    }
}

fn hostname_cache_path() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        std::path::PathBuf::from(home).join(".vigilance_hostname_cache.json")
    }
    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
        let dir = std::path::PathBuf::from(base).join("Vigilance");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("hostname_cache.json")
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    { std::env::temp_dir().join("vigilance_hostname_cache.json") }
}

fn load_hostname_disk_cache() {
    if let Ok(data) = std::fs::read_to_string(hostname_cache_path()) {
        if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&data) {
            *HOSTNAME_CACHE.lock().unwrap() = map;
        }
    }
}

fn save_hostname_disk_cache() {
    if let Ok(data) = serde_json::to_string(&*HOSTNAME_CACHE.lock().unwrap()) {
        let _ = std::fs::write(hostname_cache_path(), data);
    }
}

// Heuristic Scoring Model
fn calculate_risk_score(
    ip: &str, 
    port: u16, 
    protocol: &str, 
    last_seen: Option<(Instant, Duration)>
) -> (String, u32) {
    if !HEURISTICS_ENABLED.load(Ordering::SeqCst) {
        return ("Guardian Engine Active (Safe Mode)".to_string(), 0);
    }

    // Standard local broadcast addresses - ignore to prevent false positives
    if ip == "255.255.255.255" || ip.ends_with(".255") {
        return ("Direct Broadcast (Normal)".to_string(), 0);
    }

    // Multicast — three tiers based on scope and protocol
    if is_multicast_ip(ip) {
        // Well-known benign discovery addresses
        let benign_multicast = [
            "224.0.0.1",   // All-hosts
            "224.0.0.2",   // All-routers
            "224.0.0.251", // mDNS
            "224.0.0.252", // LLMNR
            "239.255.255.250", // SSDP/UPnP
            "ff02::1",     // IPv6 all-nodes
            "ff02::2",     // IPv6 all-routers
            "ff02::fb",    // IPv6 mDNS
            "ff02::1:2",   // IPv6 DHCP
            "ff02::1:3",   // IPv6 LLMNR
        ];
        if benign_multicast.contains(&ip) {
            return ("Multicast: Discovery (Normal)".to_string(), 0);
        }
        // Protocol-specific multicast — routing protocols that should only appear on routers
        let routing_multicast = ["224.0.0.5", "224.0.0.6", "224.0.0.9", "224.0.0.10",
            "224.0.0.13", "224.0.0.18", "224.0.0.19", "224.0.0.20",
            "ff02::5", "ff02::6", "ff02::9"];
        if routing_multicast.contains(&ip) {
            // Routing protocol multicast on a desktop is unusual
            return ("Multicast: Routing Protocol (Investigate if not a router)".to_string(), 20);
        }
        // All other multicast — flag lightly for visibility
        return ("Multicast: Unknown Group".to_string(), 10);
    }

    let mut score = 0;
    let mut reasons = Vec::new();

    // 1. Reputation Check (Blacklist)
    if MALICIOUS_IPS.contains(&ip) {
        score += 90;
        reasons.push("Blacklisted IP");
    }

    // 2. Suspicious Port Check
    if SUSPICIOUS_PORTS.contains(&port) {
        score += 40;
        reasons.push("Uncommon/Exploit Port");
    }

    // 3. Protocol Mismatch (Example: Non-HTTPS on 443)
    // Simplified: Flagging non-TCP traffic on standard TCP ports
    if (port == 443 || port == 80) && protocol == "UDP" {
        score += 30;
        reasons.push("Protocol Mismatch (UDP on Web Port)");
    }

    // 4. Beaconing Detection (Heuristic timing analysis)
    if let Some((prev_time, prev_interval)) = last_seen {
        let current_interval = prev_time.elapsed();
        
        // Check if current interval is within 10% jitter of previous interval
        if prev_interval.as_millis() > 10000 {
            let diff = if current_interval > prev_interval {
                current_interval - prev_interval
            } else {
                prev_interval - current_interval
            };
            
            let threshold = prev_interval.as_millis() / 10;
            if diff.as_millis() < threshold {
                score += 45;
                reasons.push("Beaconing (Stable Heartbeat)");
            }
        }
    }

    // 5. Data Volume Heuristic (Exfiltration spike)
    // (This would require byte counts over time, simplified for v1.0)

    let label = if score >= 85 {
        format!("HIGH RISK: {}", reasons.join(" + "))
    } else if score >= 45 {
        format!("Suspicious Activity: {}", reasons.join(", "))
    } else if score > 0 {
        format!("Caution: {}", reasons.join(", "))
    } else {
        "Verified Stream".to_string()
    };

    (label, score.min(100))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub city: String,
    pub region: String,
    pub country_code: String,
    pub asn: String,
    pub org: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub process: String,
    pub pid: u32,
    pub remote_addr: String,
    pub remote_port: u16,
    pub bytes: usize,
    pub protocol: String,
    pub direction: String,
    pub threat_score: u32,
    pub threat_label: String,
    pub geo_info: Option<GeoInfo>,
}

fn parse_asn_org(raw: &str) -> (String, String) {
    if let Some(first_space) = raw.find(' ') {
        let first = &raw[..first_space];
        if first.starts_with("AS") && first[2..].chars().all(|c| c.is_ascii_digit()) {
            return (first.to_string(), raw[first_space + 1..].to_string());
        }
    }
    ("".to_string(), raw.to_string())
}

fn geo_cache_path() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        std::path::PathBuf::from(home).join(".vigilance_geo_cache.json")
    }
    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
        let dir = std::path::PathBuf::from(base).join("Vigilance");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("geo_cache.json")
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    { std::env::temp_dir().join("vigilance_geo_cache.json") }
}

fn load_geo_disk_cache() {
    if let Ok(data) = std::fs::read_to_string(geo_cache_path()) {
        if let Ok(map) = serde_json::from_str::<HashMap<String, GeoInfo>>(&data) {
            *GEO_CACHE.lock().unwrap() = map;
        }
    }
}

fn save_geo_disk_cache() {
    if let Ok(data) = serde_json::to_string(&*GEO_CACHE.lock().unwrap()) {
        let _ = std::fs::write(geo_cache_path(), data);
    }
}

/// Resolve a single IP (IPv4 or IPv6) to GeoInfo.
/// Tries 6 providers in order, stopping at the first that returns a country_code.
async fn resolve_geo_ip(client: &reqwest::Client, ip: &str) -> Option<GeoInfo> {
    // 1. ipinfo.io — primary (50K req/month free, HTTPS)
    let url = format!("https://ipinfo.io/{}/json", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let country_code = json["country"].as_str().unwrap_or("").to_string();
                if !country_code.is_empty() {
                    let city   = json["city"].as_str().unwrap_or("").to_string();
                    let region = json["region"].as_str().unwrap_or("").to_string();
                    let (asn, org) = parse_asn_org(json["org"].as_str().unwrap_or(""));
                    return Some(GeoInfo { city, region, country_code, asn, org });
                }
            }
        }
    }

    // 2. ipapi.co — 1K req/day free, HTTPS
    let url = format!("https://ipapi.co/{}/json/", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if json["error"].as_bool() != Some(true) {
                    let country_code = json["country_code"].as_str().unwrap_or("").to_string();
                    if !country_code.is_empty() {
                        let city   = json["city"].as_str().unwrap_or("").to_string();
                        let region = json["region"].as_str().unwrap_or("").to_string();
                        let asn    = json["asn"].as_str().unwrap_or("").to_string();
                        let org_raw = json["org"].as_str().unwrap_or("").to_string();
                        let (_, org) = parse_asn_org(&org_raw);
                        return Some(GeoInfo { city, region, country_code, asn, org });
                    }
                }
            }
        }
    }

    // 3. ipwhois.app — no stated limit, HTTPS
    let url = format!("https://ipwhois.app/json/{}", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if json["success"].as_bool() != Some(false) {
                    let country_code = json["country_code"].as_str().unwrap_or("").to_string();
                    if !country_code.is_empty() {
                        let city   = json["city"].as_str().unwrap_or("").to_string();
                        let region = json["region"].as_str().unwrap_or("").to_string();
                        let (asn, org) = parse_asn_org(json["isp"].as_str().unwrap_or(""));
                        return Some(GeoInfo { city, region, country_code, asn, org });
                    }
                }
            }
        }
    }

    // 4. api.ip.sb — no key required, HTTPS (asn is numeric)
    let url = format!("https://api.ip.sb/geoip/{}", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let country_code = json["country_code"].as_str().unwrap_or("").to_string();
                if !country_code.is_empty() {
                    let city   = json["city"].as_str().unwrap_or("").to_string();
                    let region = json["region"].as_str().unwrap_or("").to_string();
                    let asn    = json["asn"].as_u64().map(|n| format!("AS{}", n)).unwrap_or_default();
                    let org    = json["asn_organization"].as_str().unwrap_or("").to_string();
                    return Some(GeoInfo { city, region, country_code, asn, org });
                }
            }
        }
    }

    // 5. geojs.io — no key, no stated limit, HTTPS
    let url = format!("https://get.geojs.io/v1/ip/geo/{}.json", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let country_code = json["country_code"].as_str().unwrap_or("").to_string();
                if !country_code.is_empty() {
                    let city   = json["city"].as_str().unwrap_or("").to_string();
                    let region = json["region"].as_str().unwrap_or("").to_string();
                    let asn    = json["asn"].as_str().unwrap_or("").to_string();
                    let org    = json["organization_name"].as_str().unwrap_or("").to_string();
                    return Some(GeoInfo { city, region, country_code, asn, org });
                }
            }
        }
    }

    // 6. ip-api.com — last resort (HTTP only on free tier, 45 req/min)
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,as,org",
        ip
    );
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if json["status"].as_str() == Some("success") {
                let city         = json["city"].as_str().unwrap_or("").to_string();
                let region       = json["regionName"].as_str().unwrap_or("").to_string();
                let country_code = json["countryCode"].as_str().unwrap_or("").to_string();
                let as_str       = json["as"].as_str().unwrap_or("").to_string();
                let org_str      = json["org"].as_str().unwrap_or("").to_string();
                let src          = if as_str.is_empty() { &org_str } else { &as_str };
                let (asn, org)   = parse_asn_org(src);
                let org          = if org.is_empty() { org_str } else { org };
                return Some(GeoInfo { city, region, country_code, asn, org });
            }
        }
    }

    None
}

pub fn start_active_probe(app: AppHandle) {
    // GeoIP Resolution Thread — concurrent lookups, IPv4 + IPv6, 6-provider fallback chain
    let geo_app = app.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            load_geo_disk_cache();
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .user_agent("Vigilance/1.0")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            loop {
                // Collect pending IPs that aren't cached or known-failed
                let pending: Vec<String> = {
                    let flight  = GEO_IN_FLIGHT.lock().unwrap();
                    let cache   = GEO_CACHE.lock().unwrap();
                    let failed  = GEO_FAILED.lock().unwrap();
                    flight.iter()
                        .filter(|ip| !cache.contains_key(*ip) && !failed.contains(*ip))
                        .cloned()
                        .take(8) // max 8 concurrent per tick — friendly to free-tier rate limits
                        .collect()
                };

                if !pending.is_empty() {
                    // Spawn all lookups concurrently
                    let handles: Vec<_> = pending.into_iter().map(|ip| {
                        let c = client.clone();
                        tokio::spawn(async move {
                            let geo = resolve_geo_ip(&c, &ip).await;
                            (ip, geo)
                        })
                    }).collect();

                    let mut had_new = false;
                    for handle in handles {
                        if let Ok((ip, geo)) = handle.await {
                            if let Some(info) = geo {
                                {
                                    let mut cache = GEO_CACHE.lock().unwrap();
                                    if cache.len() >= 2000 {
                                        let keys: Vec<_> = cache.keys().take(500).cloned().collect();
                                        for k in keys { cache.remove(&k); }
                                    }
                                    cache.insert(ip.clone(), info.clone());
                                }
                                had_new = true;
                                let _ = geo_app.emit("geo-resolved", serde_json::json!({
                                    "ip": ip,
                                    "geo": info
                                }));
                            } else {
                                // All providers failed — don't retry this session
                                GEO_FAILED.lock().unwrap().insert(ip.clone());
                            }
                            GEO_IN_FLIGHT.lock().unwrap().remove(&ip);
                        }
                    }
                    if had_new {
                        save_geo_disk_cache();
                    }
                }

                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    });

    // Port-to-Process resolution thread
    std::thread::spawn(move || {
        // sys is only needed on Windows for PID→process name resolution via sysinfo
        #[cfg(target_os = "windows")]
        let mut sys = sysinfo::System::new_all();

        loop {
            let mut new_map = HashMap::new();

            // Port→PID resolution — platform specific
            #[cfg(target_os = "windows")]
            let pid_output = Command::new("netstat")
                .args(["-ano", "-p", "tcp"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            #[cfg(target_os = "macos")]
            let pid_output = Command::new("lsof")
                .args(["-i", "-P", "-n", "-sTCP:LISTEN,ESTABLISHED"])
                .output();
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            let pid_output = Command::new("ss").args(["-tunp"]).output();

            if let Ok(out) = pid_output {
                let stdout = String::from_utf8_lossy(&out.stdout);

                #[cfg(target_os = "windows")]
                sys.refresh_all();

                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();

                    #[cfg(target_os = "windows")]
                    // netstat -ano: Protocol LocalAddr RemoteAddr State PID
                    if parts.len() >= 5 {
                        if let Some(local_addr) = parts.get(1) {
                            if let Some(port_str) = local_addr.split(':').last() {
                                if let Ok(port) = port_str.parse::<u16>() {
                                    if let Some(pid_str) = parts.get(4) {
                                        if let Ok(pid_val) = pid_str.parse::<usize>() {
                                            let pid = sysinfo::Pid::from(pid_val);
                                            let proc_name = sys.process(pid)
                                                .map(|p| p.name().to_string())
                                                .unwrap_or_else(|| "System Process".to_string());
                                            new_map.insert(port, (pid_val as u32, proc_name));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    #[cfg(target_os = "macos")]
                    // lsof: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                    // NAME: 192.168.1.1:port->remote:port or *:port (LISTEN)
                    if parts.len() >= 9 && parts[0] != "COMMAND" {
                        if let (Some(cmd), Some(pid_str), Some(name)) =
                            (parts.get(0), parts.get(1), parts.get(8))
                        {
                            let local_part = name.split("->").next().unwrap_or(name);
                            if let Some(port_str) = local_part.split(':').last() {
                                if let Ok(port) = port_str.parse::<u16>() {
                                    if let Ok(pid_val) = pid_str.parse::<usize>() {
                                        new_map.insert(port, (pid_val as u32, cmd.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            {
                let mut guard = PORT_MAP.lock().unwrap();
                *guard = new_map;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });

    // Hostname resolution thread — reverse DNS for LAN devices, persisted to disk
    let hostname_app = app.clone();
    std::thread::spawn(move || {
        load_hostname_disk_cache();

        loop {
            let pending: Vec<String> = {
                let in_flight = HOSTNAME_IN_FLIGHT.lock().unwrap();
                let cache = HOSTNAME_CACHE.lock().unwrap();
                in_flight.iter()
                    .filter(|ip| !cache.contains_key(*ip))
                    .take(8)
                    .cloned()
                    .collect()
            };

            let mut had_new = false;
            for ip in pending {
                let hostname = dns_lookup::lookup_addr(&ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
                    .unwrap_or_default();
                let resolved = if hostname.is_empty() || hostname == ip {
                    ip.clone()
                } else {
                    hostname.trim_end_matches('.').to_string()
                };
                HOSTNAME_CACHE.lock().unwrap().insert(ip.clone(), resolved.clone());
                HOSTNAME_IN_FLIGHT.lock().unwrap().remove(&ip);
                had_new = true;
                let _ = hostname_app.emit("hostname-resolved", serde_json::json!({
                    "ip": ip,
                    "hostname": resolved
                }));
            }
            if had_new {
                save_hostname_disk_cache();
            }

            std::thread::sleep(Duration::from_secs(2));
        }
    });

    std::thread::spawn(move || {
        let mut connection_history: HashMap<String, (Instant, Duration)> = HashMap::new();
        let mut aggregated_stats: HashMap<String, NetworkEvent> = HashMap::new();
        let mut last_emit = Instant::now();

        loop {
            // Wait for the frontend to pick an interface — it always does on init.
            // Never auto-select: on installed builds WebView2 takes 1-3s to cold-start,
            // and an early wrong guess races rx.next() blocking before the correction lands.
            let name = match SELECTED_INTERFACE.lock().unwrap().clone() {
                Some(n) => n,
                None => {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };

            let all_ifaces = datalink::interfaces();
            let interface = match all_ifaces.iter().find(|iface| iface.name == name).cloned() {
                Some(i) => i,
                None => {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };

            // Collect this interface's own IPs so we can detect inbound vs outbound
            let local_ips: Vec<String> = interface.ips.iter()
                .map(|ip| ip.ip().to_string())
                .collect();

            let channel_cfg = pnet::datalink::Config {
                read_timeout: Some(Duration::from_millis(100)),
                ..Default::default()
            };
            let (_, mut rx) = match datalink::channel(&interface, channel_cfg) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    let _ = app.emit("capture-error", format!(
                        "Adapter '{}' returned a non-Ethernet channel — try selecting a different interface in Settings.",
                        interface.description
                    ));
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                },
                Err(e) => {
                    let _ = app.emit("capture-error", format!(
                        "Cannot open '{}': {} — Is Npcap installed with WinPcap compatibility mode? Try running as Administrator.",
                        interface.description, e
                    ));
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };

            // Set running state for this interface capture
            SHOULD_RUN.store(true, Ordering::SeqCst);

            while SHOULD_RUN.load(Ordering::SeqCst) {
                // Check if interface changed
                {
                    let guard = SELECTED_INTERFACE.lock().unwrap();
                    if let Some(ref name) = *guard {
                        if interface.name != *name {
                            SHOULD_RUN.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }

                match rx.next() {
                    Ok(packet) => {
                        if let Some(eth_packet) = EthernetPacket::new(packet) {
                            // Dispatch by EtherType.
                        // IPv6 is mandatory: Apple TV, Netflix, YouTube all prefer IPv6 (QUIC/HTTP3).
                        // Without this, ALL streaming traffic from modern CDNs is invisible.
                        let ethertype = eth_packet.get_ethertype();

                        // Grab source MAC before consuming eth_packet into layer3 parse
                        let src_mac = {
                            let m = eth_packet.get_source();
                            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                m.0, m.1, m.2, m.3, m.4, m.5)
                        };

                        // Returns (src, dst, protocol, remote_port, local_port, ttl, tcp_window)
                        let layer3: Option<(String, String, String, u16, u16, u8, u16)> =
                            if ethertype == EtherTypes::Ipv4 {
                                Ipv4Packet::new(eth_packet.payload()).map(|ipv4| {
                                    let src = ipv4.get_source().to_string();
                                    let dst = ipv4.get_destination().to_string();
                                    let is_in = local_ips.iter().any(|ip| ip == &dst);
                                    let ttl = ipv4.get_ttl();
                                    let mut rport = 0u16;
                                    let mut lport = 0u16;
                                    let mut tcp_window = 0u16;
                                    let proto = match ipv4.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                                tcp_window = tcp.get_window();
                                                if is_in { rport = tcp.get_source(); lport = tcp.get_destination(); }
                                                else     { rport = tcp.get_destination(); lport = tcp.get_source(); }
                                            }
                                            "TCP".to_string()
                                        },
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                if is_in { rport = udp.get_source(); lport = udp.get_destination(); }
                                                else     { rport = udp.get_destination(); lport = udp.get_source(); }
                                            }
                                            "UDP".to_string()
                                        },
                                        IpNextHeaderProtocols::Icmp   => "ICMP".to_string(),
                                        IpNextHeaderProtocols::Icmpv6 => "ICMPv6".to_string(),
                                        p => match p.0 {
                                            2   => "IGMP".to_string(),
                                            4   => "IPIP".to_string(),
                                            47  => "GRE".to_string(),
                                            50  => "ESP".to_string(),
                                            51  => "AH".to_string(),
                                            89  => "OSPF".to_string(),
                                            103 => "PIM".to_string(),
                                            112 => "VRRP".to_string(),
                                            132 => "SCTP".to_string(),
                                            n   => format!("PROTO-{}", n),
                                        },
                                    };
                                    (src, dst, proto, rport, lport, ttl, tcp_window)
                                })
                            } else if ethertype == EtherTypes::Ipv6 {
                                Ipv6Packet::new(eth_packet.payload()).map(|ipv6| {
                                    let src = ipv6.get_source().to_string();
                                    let dst = ipv6.get_destination().to_string();
                                    let is_in = local_ips.iter().any(|ip| ip == &dst);
                                    let hop_limit = ipv6.get_hop_limit();
                                    let mut rport = 0u16;
                                    let mut lport = 0u16;
                                    let mut tcp_window = 0u16;
                                    let proto = match ipv6.get_next_header() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                                tcp_window = tcp.get_window();
                                                if is_in { rport = tcp.get_source(); lport = tcp.get_destination(); }
                                                else     { rport = tcp.get_destination(); lport = tcp.get_source(); }
                                            }
                                            "TCP".to_string()
                                        },
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                                if is_in { rport = udp.get_source(); lport = udp.get_destination(); }
                                                else     { rport = udp.get_destination(); lport = udp.get_source(); }
                                            }
                                            "UDP".to_string()
                                        },
                                        p => format!("PROTO-{}", p.0),
                                    };
                                    (src, dst, proto, rport, lport, hop_limit, tcp_window)
                                })
                            } else {
                                None // ARP and other non-IP frames — ignore
                            };

                        if let Some((src_addr, dst_addr, protocol, remote_port, local_port, ttl, tcp_window)) = layer3 {
                            // Only count traffic that involves this machine (promiscuous filter)
                            let is_inbound  = local_ips.iter().any(|ip| ip == &dst_addr);
                            let is_outbound = local_ips.iter().any(|ip| ip == &src_addr);
                            if !is_inbound && !is_outbound {
                                continue;
                            }

                            let (remote_addr, direction, pkt_mac) = if is_inbound {
                                (src_addr, "Inbound", src_mac.clone())
                            } else {
                                (dst_addr, "Outbound", String::new())
                            };

                            let flow_key = format!("{}:{}:{}:{}", remote_addr, remote_port, protocol, direction);

                            // GeoIP: local IPs get instant classification; public IPs queued for resolution
                            let geo_info: Option<GeoInfo> = if is_local_ip(&remote_addr) {
                                Some(classify_local_ip(&remote_addr, &pkt_mac, ttl, tcp_window, remote_port))
                            } else {
                                let cache = GEO_CACHE.lock().unwrap();
                                let resolved = cache.get(&remote_addr).cloned();
                                if resolved.is_none() {
                                    let is_public = remote_addr.parse::<std::net::Ipv4Addr>()
                                        .map(|ip| !ip.is_private() && !ip.is_loopback() && !ip.is_link_local())
                                        .unwrap_or_else(|_| {
                                            remote_addr.parse::<std::net::Ipv6Addr>()
                                                .map(|_| !remote_addr.starts_with("fe80")
                                                    && remote_addr != "::1")
                                                .unwrap_or(false)
                                        });
                                    if is_public && !GEO_FAILED.lock().unwrap().contains(&remote_addr) {
                                        GEO_IN_FLIGHT.lock().unwrap().insert(remote_addr.clone());
                                    }
                                    // Queue for hostname resolution too
                                    if is_public {
                                        let mut in_flight = HOSTNAME_IN_FLIGHT.lock().unwrap();
                                        let cached = HOSTNAME_CACHE.lock().unwrap();
                                        if !cached.contains_key(&remote_addr) && !in_flight.contains(&remote_addr) {
                                            in_flight.insert(remote_addr.clone());
                                        }
                                    }
                                    resolved
                                } else {
                                    resolved
                                }
                            };

                            let entry = aggregated_stats.entry(flow_key.clone()).or_insert_with(|| {
                                let last_seen = connection_history.get(&remote_addr).cloned();
                                let (threat_label, threat_score) = calculate_risk_score(
                                    &remote_addr,
                                    remote_port,
                                    &protocol,
                                    last_seen
                                );

                                let (pid, process) = if local_port == 0 {
                                    (0u32, "Guardian Kernel".to_string())
                                } else {
                                    let guard = PORT_MAP.lock().unwrap();
                                    guard.get(&local_port).cloned()
                                        .unwrap_or((0, "Guardian Kernel".to_string()))
                                };

                                NetworkEvent {
                                    process,
                                    pid,
                                    remote_addr: remote_addr.clone(),
                                    remote_port,
                                    bytes: 0,
                                    protocol,
                                    direction: direction.to_string(),
                                    threat_score,
                                    threat_label,
                                    geo_info: geo_info.clone(),
                                }
                            });
                            entry.geo_info = geo_info;
                            entry.bytes += packet.len();

                            // Update history — cap at 5000 entries
                            let now = Instant::now();
                            let interval = if let Some((prev_time, _)) = connection_history.get(&remote_addr) {
                                now.duration_since(*prev_time)
                            } else {
                                Duration::from_secs(0)
                            };
                            if connection_history.len() >= 5000 {
                                if let Some(oldest_key) = connection_history.keys().next().cloned() {
                                    connection_history.remove(&oldest_key);
                                }
                            }
                            connection_history.insert(remote_addr, (now, interval));

                            // Periodic emit
                            if last_emit.elapsed() >= Duration::from_millis(500) {
                                for event in aggregated_stats.values() {
                                    let _ = app.emit("network-event", event);
                                }
                                aggregated_stats.clear();
                                last_emit = Instant::now();
                            }
                        }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_e) => { std::thread::sleep(Duration::from_millis(10)); }
                }
            }
        }
    });
}

// ─── macOS pfctl helpers ──────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn get_rules_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".vigilance_desktop_rules.json")
}

#[cfg(target_os = "macos")]
fn load_blocked_ips() -> Vec<String> {
    std::fs::read_to_string(get_rules_path())
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn save_blocked_ips(ips: &[String]) {
    if let Ok(json) = serde_json::to_string(ips) {
        let _ = std::fs::write(get_rules_path(), json);
    }
}

#[cfg(target_os = "macos")]
fn apply_pf_rules(ips: &[String]) -> bool {
    if ips.is_empty() {
        return Command::new("sudo")
            .args(["pfctl", "-a", "com.vigilance.desktop", "-F", "rules"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    }
    let rules: String = ips.iter()
        .map(|ip| format!("block out quick from any to {}\n", ip))
        .collect();
    if std::fs::write("/tmp/vigilance_desktop.pf", &rules).is_err() {
        return false;
    }
    Command::new("sudo")
        .args(["pfctl", "-a", "com.vigilance.desktop", "-f", "/tmp/vigilance_desktop.pf"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── Firewall commands — Windows ─────────────────────────────────────────────

#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn block_ip(ip: String) -> Result<String, String> {
    let rule_name = format!("Vigilance Block - {}", ip);
    let output = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", rule_name),
            "dir=out", "action=block",
            &format!("remoteip={}", ip),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(format!("Guardian Rule Active: IP {} is now blacklisted.", ip))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn get_firewall_rules() -> Result<Vec<String>, String> {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();
    for line in stdout.lines() {
        if line.contains("Vigilance Block -") {
            if let Some(ip) = line.split('-').last() {
                rules.push(ip.trim().to_string());
            }
        }
    }
    Ok(rules)
}

#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn delete_firewall_rule(ip: String) -> Result<String, String> {
    let rule_name = format!("Vigilance Block - {}", ip);
    let output = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "delete", "rule",
            &format!("name={}", rule_name),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(format!("Rule for {} deleted successfully.", ip))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ─── Firewall commands — macOS ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn block_ip(ip: String) -> Result<String, String> {
    let mut ips = load_blocked_ips();
    if !ips.contains(&ip) {
        ips.push(ip.clone());
        save_blocked_ips(&ips);
    }
    if apply_pf_rules(&ips) {
        Ok(format!("Guardian Rule Active: IP {} is now blacklisted.", ip))
    } else {
        Err("Failed to apply pf rule — app requires sudo for firewall blocking".to_string())
    }
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn get_firewall_rules() -> Result<Vec<String>, String> {
    Ok(load_blocked_ips())
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn delete_firewall_rule(ip: String) -> Result<String, String> {
    let mut ips = load_blocked_ips();
    ips.retain(|i| i != &ip);
    save_blocked_ips(&ips);
    if apply_pf_rules(&ips) {
        Ok(format!("Rule for {} deleted successfully.", ip))
    } else {
        Err("Failed to reload pf rules".to_string())
    }
}

#[tauri::command]
pub fn get_interfaces() -> Vec<InterfaceInfo> {
    datalink::interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .map(|iface| InterfaceInfo {
            name: iface.name,
            description: iface.description,
            index: iface.index,
        })
        .collect()
}

#[tauri::command]
pub fn set_capture_interface(name: String) -> Result<String, String> {
    let mut guard = SELECTED_INTERFACE.lock().unwrap();
    *guard = Some(name.clone());
    SHOULD_RUN.store(false, Ordering::SeqCst) ; // Trigger loop restart
    Ok(format!("Guardian switching to interface: {}", name))
}

#[tauri::command]
pub fn toggle_heuristics(enabled: bool) {
    HEURISTICS_ENABLED.store(enabled, Ordering::SeqCst);
}

#[tauri::command]
pub async fn save_traffic_csv(csv_data: String, filename: String) -> Result<String, String> {
    let path = rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .set_file_name(&filename)
        .save_file();

    if let Some(path) = path {
        std::fs::write(path, csv_data).map_err(|e| e.to_string())?;
        Ok("Forensic log exported successfully.".to_string())
    } else {
        Err("Operation cancelled by user.".to_string())
    }
}
