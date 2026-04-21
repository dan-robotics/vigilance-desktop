use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};
use std::cmp::Reverse;
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;
use std::collections::HashMap;
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Instant, Duration};

lazy_static::lazy_static! {
    static ref SHOULD_RUN: AtomicBool = AtomicBool::new(true);
    static ref HEURISTICS_ENABLED: AtomicBool = AtomicBool::new(true);
    static ref SELECTED_INTERFACE: Mutex<Option<String>> = Mutex::new(None);
    static ref PORT_MAP: Mutex<HashMap<u16, (u32, String)>> = Mutex::new(HashMap::new());
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
}

pub fn start_active_probe(app: AppHandle) {
    // Port-to-Process resolution thread (Production Grade Background Resolver)
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
            // Find interface to capture on
            let interface_name = {
                let guard = SELECTED_INTERFACE.lock().unwrap();
                guard.clone()
            };

            fn adapter_priority(iface: &datalink::NetworkInterface) -> i32 {
                let combined = format!("{} {}", iface.name, iface.description).to_lowercase();
                if combined.contains("virtual") || combined.contains("vmware")
                    || combined.contains("hyper-v") || combined.contains("vethernet")
                    || combined.contains("virtualbox") || combined.contains("tunnel")
                    || combined.contains("bluetooth") || combined.contains("pseudo")
                    || combined.contains("miniport") || combined.contains("wan ")
                    || combined.contains("isatap") || combined.contains("teredo")
                    || combined.contains("6to4") || combined.contains("loopback")
                    || combined.contains("npcap loopback") {
                    return 0;
                }
                if combined.contains("wi-fi") || combined.contains("wifi")
                    || combined.contains("wlan") || combined.contains("wireless")
                    || combined.contains("802.11") {
                    return 3;
                }
                if combined.contains("ethernet") || combined.contains(" lan") {
                    return 2;
                }
                1
            }

            let all_ifaces = datalink::interfaces();
            let interface = if let Some(ref name) = interface_name {
                all_ifaces.iter().find(|iface| iface.name == *name).cloned()
            } else {
                let mut candidates: Vec<_> = all_ifaces.iter()
                    .filter(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
                    .cloned()
                    .collect();
                candidates.sort_by_key(|iface| Reverse(adapter_priority(iface)));
                candidates.into_iter().next()
                    .or_else(|| all_ifaces.iter().find(|iface| !iface.is_loopback() && !iface.ips.is_empty()).cloned())
                    .or_else(|| all_ifaces.into_iter().next())
            };

            let interface = match interface {
                Some(i) => i,
                None => {
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };

            // Collect this interface's own IPs so we can detect inbound vs outbound
            let local_ips: Vec<String> = interface.ips.iter()
                .map(|ip| ip.ip().to_string())
                .collect();

            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
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
                            if let Some(ipv4) = Ipv4Packet::new(eth_packet.payload()) {
                                let src_addr = ipv4.get_source().to_string();
                                let dst_addr = ipv4.get_destination().to_string();

                                // Inbound = packet destined for one of our own IPs
                                let is_inbound = local_ips.iter().any(|ip| ip == &dst_addr);
                                let (remote_addr, direction) = if is_inbound {
                                    (src_addr, "Inbound")
                                } else {
                                    (dst_addr, "Outbound")
                                };

                                let mut remote_port: u16 = 0;
                                let mut local_port: u16 = 0;

                                let protocol: String = match ipv4.get_next_level_protocol() {
                                    IpNextHeaderProtocols::Tcp => {
                                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                            if is_inbound {
                                                remote_port = tcp.get_source();
                                                local_port = tcp.get_destination();
                                            } else {
                                                remote_port = tcp.get_destination();
                                                local_port = tcp.get_source();
                                            }
                                        }
                                        "TCP".to_string()
                                    },
                                    IpNextHeaderProtocols::Udp => {
                                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                            if is_inbound {
                                                remote_port = udp.get_source();
                                                local_port = udp.get_destination();
                                            } else {
                                                remote_port = udp.get_destination();
                                                local_port = udp.get_source();
                                            }
                                        }
                                        "UDP".to_string()
                                    },
                                    // Kernel-handled protocols — no port numbers, no user process
                                    IpNextHeaderProtocols::Icmp   => "ICMP".to_string(),
                                    IpNextHeaderProtocols::Icmpv6 => "ICMPv6".to_string(),
                                    p => match p.0 {
                                        2   => "IGMP".to_string(),   // multicast group mgmt
                                        4   => "IPIP".to_string(),   // IP-in-IP tunnel
                                        47  => "GRE".to_string(),    // VPN encapsulation
                                        50  => "ESP".to_string(),    // IPsec encrypted
                                        51  => "AH".to_string(),     // IPsec auth header
                                        89  => "OSPF".to_string(),   // routing protocol
                                        103 => "PIM".to_string(),    // multicast routing
                                        112 => "VRRP".to_string(),   // router redundancy
                                        132 => "SCTP".to_string(),   // stream transport
                                        n   => format!("PROTO-{}", n), // unknown — show number
                                    },
                                };

                                // Simplified aggregation to prevent bridge flooding
                                let flow_key = format!("{}:{}:{}:{}", remote_addr, remote_port, protocol, direction);

                                let entry = aggregated_stats.entry(flow_key.clone()).or_insert_with(|| {
                                    let last_seen = connection_history.get(&remote_addr).cloned();
                                    let (threat_label, threat_score) = calculate_risk_score(
                                        &remote_addr,
                                        remote_port,
                                        &protocol,
                                        last_seen
                                    );

                                    // Non-TCP/UDP has no port → kernel owns it, not a user process.
                                    // Both cases group under "Guardian Kernel" so system traffic
                                    // stays in one place; protocol detail is visible in sub-rows.
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
                                    }
                                });

                                entry.bytes += packet.len();
                                
                                // Update history
                                let now = Instant::now();
                                let interval = if let Some((prev_time, _)) = connection_history.get(&remote_addr) {
                                    now.duration_since(*prev_time)
                                } else {
                                    Duration::from_secs(0)
                                };
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
                    Err(_e) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
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
