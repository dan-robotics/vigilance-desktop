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

    // Multicast range (224.0.0.0/4) — includes mDNS (224.0.0.251), SSDP (239.255.255.250), etc.
    if let Some(first) = ip.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
        if first >= 224 {
            return ("Multicast (Normal)".to_string(), 0);
        }
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

                        // Returns (src, dst, protocol, remote_port, local_port)
                        let layer3: Option<(String, String, String, u16, u16)> =
                            if ethertype == EtherTypes::Ipv4 {
                                Ipv4Packet::new(eth_packet.payload()).map(|ipv4| {
                                    let src = ipv4.get_source().to_string();
                                    let dst = ipv4.get_destination().to_string();
                                    let is_in = local_ips.iter().any(|ip| ip == &dst);
                                    let mut rport = 0u16;
                                    let mut lport = 0u16;
                                    let proto = match ipv4.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
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
                                    (src, dst, proto, rport, lport)
                                })
                            } else if ethertype == EtherTypes::Ipv6 {
                                Ipv6Packet::new(eth_packet.payload()).map(|ipv6| {
                                    let src = ipv6.get_source().to_string();
                                    let dst = ipv6.get_destination().to_string();
                                    let is_in = local_ips.iter().any(|ip| ip == &dst);
                                    let mut rport = 0u16;
                                    let mut lport = 0u16;
                                    let proto = match ipv6.get_next_header() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
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
                                    (src, dst, proto, rport, lport)
                                })
                            } else {
                                None // ARP and other non-IP frames — ignore
                            };

                        if let Some((src_addr, dst_addr, protocol, remote_port, local_port)) = layer3 {
                            // Only count traffic that involves this machine (promiscuous filter)
                            let is_inbound  = local_ips.iter().any(|ip| ip == &dst_addr);
                            let is_outbound = local_ips.iter().any(|ip| ip == &src_addr);
                            if !is_inbound && !is_outbound {
                                continue;
                            }

                            let (remote_addr, direction) = if is_inbound {
                                (src_addr, "Inbound")
                            } else {
                                (dst_addr, "Outbound")
                            };

                            let flow_key = format!("{}:{}:{}:{}", remote_addr, remote_port, protocol, direction);

                            // Check GeoIP cache; queue public IPs (IPv4 and IPv6) for resolution
                            let geo_info = {
                                let cache = GEO_CACHE.lock().unwrap();
                                let resolved = cache.get(&remote_addr).cloned();
                                if resolved.is_none() {
                                    let is_public = remote_addr.parse::<std::net::Ipv4Addr>()
                                        .map(|ip| !ip.is_private() && !ip.is_loopback() && !ip.is_link_local())
                                        .unwrap_or_else(|_| {
                                            remote_addr.parse::<std::net::Ipv6Addr>()
                                                .map(|ip| !ip.is_loopback() && !ip.is_unspecified()
                                                    && !remote_addr.starts_with("fe80"))
                                                .unwrap_or(false)
                                        });
                                    if is_public && !GEO_FAILED.lock().unwrap().contains(&remote_addr) {
                                        GEO_IN_FLIGHT.lock().unwrap().insert(remote_addr.clone());
                                    }
                                }
                                resolved
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
