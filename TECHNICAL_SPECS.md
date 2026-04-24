# Vigilance-Desktop: Technical Specification & Architecture

## 1. Release Notes: Version 3.2.0 - Stable
**Supreme Visibility Update**

### Key Improvements
* **SUPREME Style Device Fingerprinting**: Integrated a multi-vector identification suite to eliminate "Unknown" labels on local networks.
    * **`dns_read_name`**: Custom DNS wire-format parser with compression pointer support for high-fidelity mDNS mapping.
    * **`extract_mdns`**: Parsers for PTR (services), TXT (Apple model strings/metadata), and A/AAAA records.
    * **`extract_dhcp`**: Captures Option 12 (hostname) and Option 60 (vendor class) to identify hardware roles.
    * **`extract_ssdp`**: Extracts UPnP device type URNs from discovery packets.
    * **`tcp_syn_os`**: Sophisticated OS fingerprinting using TCP window scaling and TTL patterns.
* **Deep Packet Inspection (DPI) Visibility**:
    * **TLS SNI Extraction**: Handshake traversal allows viewing hostnames (e.g., `youtube.com`) for encrypted streams instead of raw IP addresses.
    * **Live DNS Parsing**: Intercepts DNS responses in real-time to backfill hostname labels instantly, bypassing reverse-lookup latency.
* **Auto-Block Integration**: Backend now supports automatic one-click rule creation; if a threat score exceeds the user-defined threshold, `block_ip` can be invoked automatically.
* **Beaconing Refinement**: Improved timing analysis with a 10% jitter threshold to accurately flag stable "heartbeat" connections from malicious agents.

---

## 2. Overview
Vigilance is a professional-grade, local-first network monitoring and security suite for Windows and macOS. It provides kernel-level packet inspection, real-time process name resolution, GeoIP enrichment, LAN device classification, and dynamic firewall management through a high-performance Rust backend and a polished React/Tauri frontend.

**Current version: v3.2.0 Stable**

---

## 3. System Architecture
The application follows a standard **Tauri** architecture, separating the high-privilege system logic (Rust) from the user interface (React).

### 3.1 Backend (Rust Core) — `src-tauri/src/sniffer.rs`

#### Packet Sniffer Thread

- Uses `pnet` to open a raw socket on the selected network adapter with `read_timeout: 100ms` so the interface-change check fires without waiting for a packet.
- **Interface selection**: Backend never auto-selects. It polls `SELECTED_INTERFACE` every 200ms until the frontend sends `set_capture_interface`. This eliminates the WebView2 cold-start race on installed builds (1–3s delay before frontend fires).
- **IPv4 + IPv6**: Dispatches on Ethernet EtherType (`0x0800` IPv4 / `0x86DD` IPv6). TCP/UDP ports extracted from both IPv4 and IPv6 headers.
- **Direction detection**: Destination IP compared to `local_ips` (from `interface.ips`) → Inbound or Outbound. For inbound: `remote_addr = src_ip`, `remote_port = src_port`. For outbound: `remote_addr = dst_ip`, `remote_port = dst_port`.
- **MAC capture**: Source MAC extracted from each Ethernet frame (`eth_packet.get_source()`) before IP parsing. Used for OUI vendor lookup on LAN IPs.
- **Extended layer3 tuple**: `(src, dst, protocol, remote_port, local_port, ttl, tcp_window)` — TTL and TCP window size captured from IPv4 header (`get_ttl()`) and IPv6 hop limit (`get_hop_limit()`), plus TCP window (`get_window()`) from the TCP header.
- **Protocol identification**: Full named decoding: `TCP`, `UDP`, `ICMP`, `ICMPv6`, `IGMP` (2), `IPIP` (4), `GRE` (47), `ESP` (50), `AH` (51), `OSPF` (89), `PIM` (103), `VRRP` (112), `SCTP` (132). Unknown protocol numbers emit `PROTO-N`. Non-TCP/UDP packets grouped under "Guardian Kernel".
- **Flow aggregation**: Keyed by `remote_ip:remote_port:protocol:direction`, accumulated over 500ms windows.
- **Promiscuous filter**: Packets where neither source nor destination matches `local_ips` are skipped — eliminates other LAN devices' traffic from counts.

#### Heuristic Engine (`calculate_risk_score`)

Assigns `threat_score` (0–100):

| Signal | Score |
|---|---|
| IP reputation blacklist | +90 |
| Suspicious ports (6667, 4444, 31337, 1337) | +40 |
| Protocol mismatch (UDP on port 80/443) | +30 |
| Beaconing — consistent-interval heartbeat (≥10s threshold, ±10% jitter) | +45 |

**Multicast scoring — three tiers (replaces blanket score-0 in v3.0.1):**

| Tier | Addresses | Score |
|---|---|---|
| Discovery (normal) | mDNS 224.0.0.251/ff02::fb, SSDP 239.255.255.250, LLMNR 224.0.0.252, all-hosts/routers, IPv6 equivalents | 0 |
| Routing protocols | OSPF 224.0.0.5/6, PIM 224.0.0.13, VRRP 224.0.0.18, RIP 224.0.0.9, IPv6 equivalents | 20 (investigate on desktop) |
| Unknown group | Any other multicast address | 10 (visible, no alert) |

Broadcast (`255.255.255.255`, `*.255`) always scores 0.

#### Local Network Intelligence (v3.0.1)

Five helper functions build a complete LAN device profile from packet metadata alone — no external API:

**`is_local_ip(ip)`** — RFC 1918 IPv4 (`10.x`, `172.16–31.x`, `192.168.x`), loopback, link-local, broadcast, multicast; IPv6 `fe80::/10`, `fc00::/7` ULA, `::1`, `ff00::/8` multicast.

**`local_port_service(port)`** — Maps 20 well-known ports to service labels: SSH (22), SMTP (25), DNS (53), DHCP (67/68), HTTP (80), IMAP (143), HTTPS (443), SMB (445), MySQL (3306), PostgreSQL (5432), Redis (6379), Elasticsearch (9200), MongoDB (27017), etc.

**`lookup_oui(mac_bytes)`** — Built-in OUI table (no network call) covering Apple, Samsung, Intel, Raspberry Pi, TP-Link, Netgear, ASUS, Ubiquiti, VMware virtual adapters.

**`infer_os(ttl, tcp_window)`** — Strong signals only:
- TTL 128 → Windows (exclusive)
- TTL 255 → Network Equipment (routers/switches)
- TTL 64 + window 65535 → macOS/iOS
- TTL 64 + window 14600/29200/43800 → Linux
- All other combinations → `None` (not emitted, no false guesses)

**`classify_local_ip(ip, mac, ttl, tcp_window, port)`** — Combines all of the above into a `GeoInfo` struct with `country_code = "LAN"` as the LAN marker:
- `city` = hostname (from `HOSTNAME_CACHE`) or raw IP if not yet resolved
- `region` = OS guess
- `asn` = manufacturer (OUI)
- `org` = `"LAN Device · ServiceName"` if port matches, else `"LAN Device"`

#### GeoIP Thread

- Dedicated async Tokio runtime thread.
- Sniffer queues **public** IPs into `GEO_IN_FLIGHT`. Local IPs (`is_local_ip()`) are never queued — they get instant classification via `classify_local_ip()` instead.
- Polls `GEO_IN_FLIGHT` every 500ms, resolves up to 8 IPs concurrently via `tokio::spawn`.
- **6-provider fallback chain**: `ipinfo.io` → `ipapi.co` → `ipwhois.app` → `api.ip.sb` → `geojs.io` → `ip-api.com` (HTTP fallback). Stops at first successful country_code.
- **TLS**: `rustls-tls` with embedded Mozilla root bundle — consistent on Windows (no Schannel) and macOS.
- **`GEO_CACHE`**: `Mutex<HashMap<String, GeoInfo>>`, capped at 2000 entries (evicts 500 oldest when full).
- **`GEO_FAILED`**: `Mutex<HashSet<String>>` — IPs that failed all 6 providers are never retried this session.
- **Disk cache** (`geo_cache_path()`): Loaded at thread startup, saved after each successful batch.
  - Windows: `%LOCALAPPDATA%\Vigilance\geo_cache.json`
  - macOS: `~/.vigilance_geo_cache.json`
- Emits `geo-resolved` event immediately on resolution with `{ ip, geo }` — independent of sniffer cycle.

#### Hostname Resolution Thread

- Dedicated background thread (non-async, blocking DNS calls).
- Queues public IPs from the sniffer into `HOSTNAME_IN_FLIGHT`. Resolves up to 8 per 2-second tick.
- Uses `dns_lookup::lookup_addr()` — calls the OS `getnameinfo()` system call (Win32 on Windows, BSD on macOS). Queries the local DNS resolver (router, Pi-hole, mDNS). **No external Vigilance API.**
- **`HOSTNAME_CACHE`**: `Mutex<HashMap<String, String>>` (IP → hostname).
- **Disk cache** (`hostname_cache_path()`): Loaded at startup, saved after each resolution batch. Hostnames are stable — persisting avoids re-querying across restarts.
  - Windows: `%LOCALAPPDATA%\Vigilance\hostname_cache.json`
  - macOS: `~/.vigilance_hostname_cache.json`
- Emits `hostname-resolved` event with `{ ip, hostname }` for frontend live update.

#### Process Resolver Thread

- Polls every 3s using the platform-native tool: `netstat -ano -p tcp` (Windows), `lsof -i -P -n -sTCP:LISTEN,ESTABLISHED` (macOS).
- Builds `PORT_MAP`: local port → `(PID, process_name)`.
- On Windows: PID resolved via `sysinfo`. On macOS: process name from `lsof` COMMAND column.
- On Windows: `CREATE_NO_WINDOW` flag prevents CMD flicker.

#### Runtime Config & Portable Mode

- `get_api_key()` Tauri command resolves `config.json` via `BaseDirectory::Resource` (installed) or `./config/config.json` (portable — detected by `--portable` flag or presence of `config/` folder next to exe).
- `GEMINI_API_KEY` returned at runtime. Never embedded in JS bundle.

#### Native Firewall & Export

- `block_ip` — platform conditional:
  - **Windows**: `netsh advfirewall` (WFP). Rules persist across reboots.
  - **macOS**: `pfctl` via `sudo`. Blocked IPs persisted to `~/.vigilance_desktop_rules.json`, reloaded into `com.vigilance.desktop` pf anchor on each change.
- `save_traffic_csv` — uses `rfd` crate for native Save As dialog. Export prefixes: `vigilance_traffic_log_`, `vigilance_alerts_log_`, `vigilance_heuristic_log_` — all ISO-timestamped.

---

### 3.2 Frontend (React/TypeScript) — `src/App.tsx`

#### State

| State | Type | Purpose |
|---|---|---|
| `connections` | `Connection[]` (max 50) | Rolling active stream window |
| `detections` | detection[] (max 50) | Heuristic events with score ≥ 45 |
| `groupedConnections` | `useMemo` | Connections grouped by process |
| `sessionTotalDown/Up` | `number` (bytes) | Cumulative accumulators |
| `processTotals` | `Record<process, {down,up}>` | Per-process forensic totals |
| `geoCacheRef` | `useRef<Record<ip, GeoInfo>>` | Frontend geo cache (session) |
| `analyzingDetections` | `Set<string>` | In-flight AI request tracking |
| `aiAnalysis` | `Record<id, string>` | Per-connection AI results |

#### Tauri Event Listeners

| Event | Payload | Action |
|---|---|---|
| `network-event` | `NetworkEvent` | Update connections, detections, session totals |
| `geo-resolved` | `{ ip, geo }` | Backfill connections + detections with location |
| `hostname-resolved` | `{ ip, hostname }` | Update LAN connection city field in-place |
| `capture-error` | `string` | Show error banner |

#### LAN Display (v3.0.1)

- `buildLocationLabel(geo)` — if `geo.country_code === 'LAN'`: returns `"hostname · OS · Manufacturer · Service"`. Otherwise: `"City, Region, CC — ASN Org"`.
- `shortGeo(location)` — returns `"LAN"` for LAN entries, country code for internet entries.
- LAN sub-rows render in **blue** with `<Network>` icon (lucide-react). Internet connections render in slate/green with `<Globe>` icon.
- Group header geo badge: blue `<Network> LAN` for local devices, slate `<Globe> CC` for internet.

#### GeoIP

- 100% backend-handled. Frontend never makes HTTP requests to any geo provider.
- On `network-event`: if `data.geo_info` present and not yet cached, backfills all matching connections and detections.
- On `geo-resolved`: updates all connections and detections matching the IP.
- On `hostname-resolved`: updates city field of matching LAN connections.

#### AI Client

- `GoogleGenAI` not initialized at load. `getAiClient()` lazily calls `get_api_key` via Tauri IPC on first use.
- If `get_api_key` fails at startup → `useCloudAi = false`, local engine takes over silently.
- **Three analysis entry points**:
  1. **Per-connection** (`analyzeThreat`): Zap button on Live sub-rows.
  2. **Per-detection** (`analyzeDetection`): Ask AI button on each Guardian/Notifications card.
  3. **Tab-level** (`analyzeCurrentTab`): Purple Ask AI button in header — batches all items in the active tab.
- **`localExplain()`**: Rule-based fallback — uses GeoIP org, country, port semantics, heuristic reason, high-risk country flags (RU, CN, KP, IR, BY), cloud-provider context.
- Gemini model: `gemini-2.0-flash`. Rate-limit errors (HTTP 429) surface as a dismissible red banner.

#### UI Architecture

- **Static-Width Table**: `table-fixed` + `<colgroup>` — no horizontal scroll.
- **Protocol Badges**: Flex-wrap chips per protocol in group header rows.
- **Detection Deduplication**: `detectionCooldownRef` — `IP:threatLabel` key with 60s TTL.
- **Throughput Chart**: 30-second rolling `AreaChart` (Recharts), 1s `setInterval`, delta of `sessionTotalDownRef/UpRef`.

---

## 4. Data Flow

```
Raw Ethernet Frame (pnet)
    │
    ├─ EtherType dispatch (IPv4 / IPv6 / skip ARP)
    │
    ├─ Extract: src_mac, src_ip, dst_ip, protocol, ports, TTL, tcp_window
    │
    ├─ Direction check (vs local_ips) → skip if not this machine's traffic
    │
    ├─ is_local_ip(remote_addr)?
    │     YES → classify_local_ip(mac, ttl, tcp_window, port) → GeoInfo{LAN}
    │     NO  → GEO_CACHE lookup → attach geo_info if resolved
    │                           → queue in GEO_IN_FLIGHT if not
    │                           → queue in HOSTNAME_IN_FLIGHT if not
    │
    ├─ PORT_MAP lookup (local_port) → (PID, process_name)
    │
    ├─ calculate_risk_score(ip, port, protocol, beaconing_interval)
    │
    ├─ Accumulate into flow bucket (500ms window)
    │
    └─ emit("network-event", NetworkEvent) every 500ms

GeoIP Thread (async Tokio, parallel)
    GEO_IN_FLIGHT → resolve_geo_ip (6 providers) → GEO_CACHE + disk → emit("geo-resolved")

Hostname Thread (blocking, OS getnameinfo)
    HOSTNAME_IN_FLIGHT → lookup_addr → HOSTNAME_CACHE + disk → emit("hostname-resolved")

Process Thread (3s poll)
    netstat / lsof → PORT_MAP
```

---

## 5. Performance & Reliability

| Concern | Solution |
|---|---|
| Adapter race on installed build | Backend polls 200ms for frontend to call `set_capture_interface` — no guess |
| Interface change detection | `read_timeout: 100ms` — rx.next() doesn't block check loop |
| GeoIP rate limiting | GEO_FAILED set prevents retry; disk cache prevents re-query across restarts |
| GeoIP provider outage | 6-provider chain; all providers free, no key required |
| Windows TLS failures | `rustls-tls` with embedded Mozilla bundle — no Schannel dependency |
| GEO_CACHE unbounded growth | Capped at 2000 entries — evicts 500 oldest |
| connection_history unbounded | Capped at 5000 entries — evicts oldest key at limit |
| Concurrent geo resolution | Up to 8 parallel `tokio::spawn` per 500ms tick |
| CMD flicker on Windows | `CREATE_NO_WINDOW` flag on all subprocess calls |

---

## 6. Security Model

- **Local-First**: No raw packet data or identity information transmitted to external servers.
- **GeoIP via Backend Only**: All geo requests from Rust process — not the webview. Eliminates CORS/sandbox issues.
- **Hostname via OS only**: `getnameinfo` calls the local DNS resolver. No Vigilance-specific remote service.
- **API Key at Runtime**: Gemini key loaded from `config.json` via Tauri command. Excluded from git (`src-tauri/resources/config.json` in `.gitignore`). Never in JS bundle.
- **Kernel Block**: WFP (Windows) and pfctl (macOS) rules persist at OS level after UI closes.
- **GitHub Safety**: `config.json` and `src-tauri/target/` git-excluded. `config.example.json` for contributors.

---

## 7. Dependency Summary

| Crate | Purpose |
|---|---|
| `pnet 0.34` | Raw packet capture (BPF/Npcap) |
| `tauri 2.0` | Desktop app shell, IPC, event emitter |
| `tokio 1.0` (full) | Async runtime for GeoIP thread |
| `reqwest 0.11` (rustls-tls) | HTTP client for GeoIP providers |
| `dns-lookup 3.0` | OS-native reverse DNS (`getnameinfo`) |
| `serde / serde_json` | Serialization for events, caches |
| `sysinfo 0.30` | PID → process name on Windows |
| `rfd 0.14` | Native Save As dialog |
| `csv 1.3` | CSV export |
| `lazy_static 1.4` | Global statics (`GEO_CACHE`, `PORT_MAP`, etc.) |
| `anyhow` | Error handling |
