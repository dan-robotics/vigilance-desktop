# Vigilance-Desktop: Technical Specification & Architecture

## 1. Overview
Vigilance is a professional-grade, local-first network monitoring and security suite for Windows and macOS. It provides kernel-level packet inspection, real-time process name resolution, GeoIP enrichment, and dynamic firewall management through a high-performance Rust backend and a polished React/Tauri frontend.

## 2. System Architecture
The application follows a standard **Tauri** architecture, separating the high-privilege system logic (Rust) from the user interface (React).

### 2.1 Backend (Rust Core)

*   **Packet Sniffer (`sniffer.rs`)**:
    *   Uses `pnet` to open a raw socket on the selected network adapter.
    *   Computes `local_ips` once per interface selection (from `interface.ips`).
    *   **IPv4 + IPv6**: Dispatches on Ethernet EtherType (`0x0800` IPv4 / `0x86DD` IPv6) before parsing. TCP/UDP ports are extracted correctly from both IPv4 and IPv6 headers.
    *   **Direction Detection**: Classifies each packet as `Inbound` or `Outbound` by checking whether the destination IP is one of the interface's own addresses. For inbound packets, `remote_addr = src_ip` and `remote_port = src_port`. For outbound, `remote_addr = dst_ip` and `remote_port = dst_port`.
    *   **Adapter Auto-Selection**: On startup, virtual adapters (Hyper-V, VMware, VirtualBox, VPN clients) are excluded from the candidate pool via `adapter_priority() > 0`. Physical WiFi is preferred (score 3), then physical Ethernet (score 2). The user can override via the Settings dropdown.
    *   **Protocol Identification**: Full named decoding: `TCP`, `UDP`, `ICMP`, `ICMPv6`, `IGMP` (2), `IPIP` (4), `GRE` (47), `ESP` (50), `AH` (51), `OSPF` (89), `PIM` (103), `VRRP` (112), `SCTP` (132). Unknown protocol numbers emit `PROTO-N`. Non-TCP/UDP packets are grouped under "Guardian Kernel".
    *   **Flow Aggregation**: Groups packets into flows keyed by `remote_ip:remote_port:protocol:direction` within a 500ms window. Including `direction` in the key prevents inbound and outbound flows to the same remote endpoint from merging.
    *   **Heuristic Engine**: Assigns `threat_score` (0–100) based on: IP reputation blacklist (+90), suspicious ports (+40), protocol mismatch on web ports (+30), and beaconing — consistent-interval heartbeat timing analysis (+45, minimum 10s interval threshold). Multicast range `224.0.0.0/4` and broadcast addresses are excluded from scoring entirely.

*   **GeoIP Thread**:
    *   Runs as a dedicated async Tokio runtime thread, independent of the sniffer.
    *   Sniffer queues public IPs into `GEO_IN_FLIGHT` (a `Mutex<HashSet<String>>`). Private IPs (`is_private()`, `is_loopback()`, link-local, `fe80::`) are never queued.
    *   GeoIP thread polls `GEO_IN_FLIGHT` every 500ms, resolving up to 8 IPs concurrently via `tokio::spawn`.
    *   **Primary provider**: `ipinfo.io/{ip}/json` — handles both IPv4 and IPv6.
    *   **Fallback provider**: `ip-api.com/json/{ip}` — used automatically if ipinfo.io returns empty or fails.
    *   Results are stored in `GEO_CACHE` (`Mutex<HashMap<String, GeoInfo>>`), capped at 2000 entries (evicts 500 oldest when full).
    *   On resolution, immediately emits `geo-resolved` Tauri event with `{ ip, geo }`. This push is independent of whether another packet from that IP arrives — the frontend is always notified.

*   **Process Resolver**:
    *   Spawns a background thread that periodically (3s) polls active sockets using the platform-native tool: `netstat -ano -p tcp` (Windows), `lsof -i -P -n -sTCP:LISTEN,ESTABLISHED` (macOS), or `ss -tunp` (Linux).
    *   Parses output to build the `PORT_MAP`: local port → `(PID, process_name)`. On macOS, process name comes from the `lsof` COMMAND column; on Windows resolved via `sysinfo`.

*   **Runtime Config Loader**:
    *   `get_api_key()` Tauri command resolves `config.json` via `BaseDirectory::Resource`.
    *   Returns the `GEMINI_API_KEY` string at runtime. The key is **never embedded in the JavaScript bundle**.
    *   Template for contributors: `src-tauri/resources/config.example.json`.

*   **Native Firewall & Export**:
    *   `block_ip` is platform-conditional:
        *   **Windows**: interfaces with the **Windows Filtering Platform (WFP)** via `netsh advfirewall`. Rules persist across reboots.
        *   **macOS**: uses **`pfctl`** via `sudo pfctl`. Blocked IPs are persisted in `~/.vigilance_desktop_rules.json` and reloaded into pf on each change via the `com.vigilance.desktop` anchor. Requires a one-time sudoers entry for passwordless `pfctl`.
    *   `save_traffic_csv(csv_data, filename)` uses the `rfd` crate for a native "Save As" dialog. Three export types: `vigilance_traffic_log_`, `vigilance_alerts_log_`, `vigilance_heuristic_log_` — all suffixed with an ISO timestamp.

### 2.2 Frontend (React/TypeScript)

*   **State Management**:
    *   **`connections`**: Rolling window (max 50) of active network streams, updated on every `network-event`.
    *   **`groupedConnections`** (`useMemo`): Derived from `connections` — groups by process name, aggregates total download/upload, surfaces worst threat status. Used by both Live and Audit modes.
    *   **`sessionTotalDown/Up`**: Cumulative byte accumulators, incremented on `data.direction === 'Inbound'` / `'Outbound'`.
    *   **`detections`**: Security event log (max 50 entries) for heuristic matches with `threat_score >= 45`.
    *   **`expandedProcesses`**: `Set<string>` of process names with expanded sub-rows — shared across Live and Audit modes.
    *   **`aiAnalysis`**: `Record<string, string>` — per-connection AI analysis results keyed by connection ID.
    *   **`analyzingDetections`**: `Set<string>` — tracks which detection IDs currently have an in-flight AI request.

*   **GeoIP Resolution**:
    *   GeoIP is **100% handled by the Rust backend**. The frontend never makes direct HTTP requests to ipinfo.io or any GeoIP provider.
    *   On each `network-event`, the frontend checks `data.geo_info` — if present and not yet cached, it backfills all matching connections and detections immediately.
    *   A dedicated `geo-resolved` listener receives instant push notifications when the backend resolves a new IP — regardless of whether more traffic arrives from that IP. This eliminates the previous race condition where connections going idle before geo resolved would never receive location data.
    *   `geoCacheRef` (`useRef<Record<string, GeoInfo>>`) caches resolved geo per session by IP.
    *   `buildLocationLabel(geo)` formats: `"City, Region, CountryCode — ASN Org"`.
    *   `shortGeo(location)` extracts only the country code for compact display in group header rows.

*   **AI Client**:
    *   `GoogleGenAI` is **not** initialized at module load. `getAiClient()` lazily instantiates on first call by invoking `get_api_key` via Tauri IPC. Subsequent calls return the cached instance.
    *   On startup, if `get_api_key` throws, `useCloudAi` is set to `false` and the local explanation engine takes over.
    *   **Three analysis entry points**:
        1.  **Per-connection** (`analyzeThreat`): Zap button on expanded Live sub-rows — analyzes a single connection via Gemini. Result stored in `aiAnalysis[conn.id]`.
        2.  **Per-detection** (`analyzeDetection`): Ask AI button on each Guardian/Notifications card — sends IP, port, protocol, reason, score, and location for a targeted 1–2 sentence assessment. Tracks in-flight state per detection ID via `analyzingDetections`.
        3.  **Tab-level** (`analyzeCurrentTab`): Ask AI header button — batches all items in the active tab (connections, detections, or firewall rules) and returns a 2–3 sentence summary banner.
    *   **Auto-Explanation**: Every new detection (score ≥ 45) automatically generates a note via `localExplain()` or Gemini if Cloud AI is enabled.
    *   **`localExplain()`**: Rule-based fallback. Builds explanation from: GeoIP org, country, port semantics, heuristic reason keywords, high-risk country flags (RU, CN, KP, IR, BY), and cloud-provider context.

*   **UI Architecture**:
    *   **Unified Process View**: Both Live and Audit modes render `groupedConnections` — one collapsible row per application. Sub-rows show per-socket details (IP, geolocation, ASN, protocol:port, KB/s, threat label).
    *   **Static-Width Table**: `table-fixed` with `<colgroup>` declaring explicit column widths. Content never overflows horizontally.
    *   **Protocol Badges**: Group header Protocol column renders each unique protocol as a flex-wrap chip.
    *   **Detection Deduplication**: `detectionCooldownRef` (`Set<string>`) stores `IP:threatLabel` keys with a 60-second TTL.
    *   **Detection Log Export**: Notifications and Guardian tabs export to 7-column CSV: `Time, IP Address, Port, Location, Threat Reason, Risk Score, AI Note`.
    *   **Live Throughput Chart**: 30-second rolling `AreaChart` (Recharts). 1-second `setInterval` samples delta of `sessionTotalDownRef/UpRef` to compute MB/s.

## 3. Data Flow

1.  **Ingress**: Rust Sniffer thread intercepts a raw Ethernet frame via `pnet`.
2.  **Direction**: Destination IP compared to `local_ips` → packet classified as Inbound or Outbound.
3.  **Mapping**: `PORT_MAP` lookup on `local_port` → `(PID, process_name)`.
4.  **GeoIP**: `GEO_CACHE` lookup on `remote_ip` → attach `geo_info` if resolved. If not resolved, queue IP in `GEO_IN_FLIGHT` for the GeoIP thread.
5.  **Scoring**: Heuristic function evaluates remote IP, port, protocol, and beaconing interval.
6.  **Aggregation**: Bytes accumulated into flow bucket for 500ms, then emitted and cleared.
7.  **Emit**: `app.emit("network-event", event)` fires every 500ms.
8.  **GeoIP Push**: GeoIP thread resolves IPs asynchronously and emits `geo-resolved` immediately on resolution — independent of the sniffer cycle.
9.  **Reactive Update**: Frontend listeners update `connections`, `detections`, `sessionTotalDown/Up` on `network-event`; backfill geo data on `geo-resolved`.
10. **Derived State**: `groupedConnections` and `finalFilteredConnections` recomputed via `useMemo`.

## 4. Key Performance Optimizations & Modes

*   **Unified Grouped View (Live + Audit)**: Both modes render `groupedConnections`. Live mode adds real-time KB/s and action buttons; Audit mode shows cumulative forensic totals.
*   **Freeze Control**: Pauses UI state reconciliation via `isPausedRef` while Rust continues accumulating packets in the background.
*   **Aggregated Events**: Backend emits 2 pulses/second per flow — not one event per packet.
*   **Concurrent GeoIP**: Up to 8 parallel async lookups per 500ms tick — prevents slow sequential resolution blocking new IPs.
*   **Defensive Whitelisting**: Heuristic engine ignores global broadcasts (`255.255.255.255`, `*.255`) and multicast (`224.0.0.0/4`).

## 5. Security Model

*   **Local-First**: No raw packet data or identity information is ever transmitted to external servers.
*   **GeoIP via Backend Only**: All GeoIP requests originate from the Rust process, never the webview. Eliminates CORS/sandbox issues and prevents the frontend bundle from having direct internet access.
*   **API Key at Runtime Only**: Gemini API key loaded from `src-tauri/resources/config.json` at runtime via Tauri command. Excluded from git and never embedded in the JS bundle.
*   **Kernel Block**: WFP rules (Windows) and pfctl rules (macOS) persist at the OS level even after the UI is closed.
*   **Zero-Config Resolution**: Maps ports to PIDs using built-in OS tools — no additional drivers required.
*   **GitHub Safety**: `src-tauri/resources/config.json` and `src-tauri/target/` are git-excluded. `config.example.json` provided for contributors.
