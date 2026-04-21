# Vigilance-Desktop: Technical Specification & Architecture

## 1. Overview
Vigilance is a professional-grade, local-first network monitoring and security suite for Windows and macOS. It provides kernel-level packet inspection, real-time process name resolution, and dynamic firewall management through a high-performance Rust backend and a polished React/Tauri frontend.

## 2. System Architecture
The application follows a standard **Tauri** architecture, separating the high-privilege system logic (Rust) from the user interface (React).

### 2.1 Backend (Rust Core)

*   **Packet Sniffer (`sniffer.rs`)**:
    *   Uses `pnet` to open a raw socket on the selected network adapter.
    *   Computes `local_ips` once per interface selection (from `interface.ips`).
    *   **Direction Detection**: Classifies each packet as `Inbound` or `Outbound` by checking whether the destination IP is one of the interface's own addresses. For inbound packets, `remote_addr = src_ip` and `remote_port = src_port`. For outbound, `remote_addr = dst_ip` and `remote_port = dst_port`. This ensures correct process mapping and download/upload accounting.
    *   **Protocol Identification**: The `protocol` field is now a `String` with full named decoding: `TCP`, `UDP`, `ICMP`, `ICMPv6`, `IGMP` (2), `IPIP` (4), `GRE` (47), `ESP` (50), `AH` (51), `OSPF` (89), `PIM` (103), `VRRP` (112), `SCTP` (132). Unknown protocol numbers emit `PROTO-N` (e.g. `PROTO-47`) instead of a generic `OTHER`. Non-TCP/UDP packets have no port numbers and are grouped under "Guardian Kernel" in the UI.
    *   **Flow Aggregation**: Groups packets into flows keyed by `remote_ip:remote_port:protocol:direction` within a 500ms window before emitting to the frontend. Including `direction` in the key prevents inbound and outbound flows to the same remote endpoint from merging.
    *   **Heuristic Engine**: Assigns `threat_score` (0–100) based on: IP reputation blacklist (+90), suspicious ports (+40), protocol mismatch on web ports (+30), and beaconing — consistent-interval heartbeat timing analysis (+45, minimum 10s interval threshold). Multicast range `224.0.0.0/4` and broadcast addresses are excluded from scoring entirely.

*   **Process Resolver**:
    *   Spawns a background thread that periodically (3s) polls active sockets using the platform-native tool: `netstat -ano -p tcp` (Windows), `lsof -i -P -n -sTCP:LISTEN,ESTABLISHED` (macOS), or `ss -tunp` (Linux).
    *   Parses output to build the `PORT_MAP`: local port → `(PID, process_name)`. On macOS, the process name comes directly from the `lsof` COMMAND column; on Windows it is resolved via `sysinfo`.
    *   For inbound packets, `local_port = tcp.get_destination()` — ensuring the PORT_MAP lookup resolves to the correct listening process.

*   **Runtime Config Loader**:
    *   `get_api_key()` Tauri command resolves `config.json` via `BaseDirectory::Resource` using `app.path().resolve()`.
    *   Returns the `GEMINI_API_KEY` string at runtime. The key is **never embedded in the JavaScript bundle** — Vite no longer injects it as a build-time define.
    *   Template for contributors: `src-tauri/resources/config.example.json`.

*   **Native Firewall & Export**:
    *   `block_ip` is platform-conditional:
        *   **Windows**: interfaces with the **Windows Filtering Platform (WFP)** via `netsh advfirewall`. Rules are written directly to the OS firewall and persist across reboots.
        *   **macOS**: uses **`pfctl`** (pf firewall) via `sudo pfctl`. Blocked IPs are persisted in `~/.vigilance_desktop_rules.json` and reloaded into pf on each change via the `com.vigilance.desktop` anchor. Rules survive app restarts (JSON is reloaded) but require a one-time sudoers entry to run without a password prompt.
    *   `save_traffic_csv(csv_data, filename)` uses the `rfd` crate to invoke a native "Save As" dialog. Accepts both the CSV content and the suggested filename from the frontend. Three distinct export types with standardised prefixes: `vigilance_traffic_log_`, `vigilance_alerts_log_` (Notifications tab), `vigilance_heuristic_log_` (Guardian tab) — all suffixed with an ISO timestamp (`YYYY-MM-DDTHH-MM-SS`).

### 2.2 Frontend (React/TypeScript)

*   **State Management**:
    *   **`connections`**: Rolling window of active network streams, updated on every `network-event`.
    *   **`groupedConnections`** (`useMemo`): Derived from `connections` — groups by process name, aggregates total download/upload, and surfaces the worst threat status. Used by **both** Live and Audit modes.
    *   **`sessionTotalDown/Up`**: Cumulative byte accumulators — incremented correctly only when `data.direction === 'Inbound'` / `'Outbound'`.
    *   **`detections`**: Security event log (max 50 entries) for heuristic matches with `threat_score > 40`.
    *   **`expandedProcesses`**: `Set<string>` of process names with expanded sub-rows — shared across both Live and Audit modes.

*   **GeoIP Resolution**:
    *   On each new unique remote IP, the frontend fires an async `fetch` to `https://ipinfo.io/{ip}/json` (free tier, no key required).
    *   Results are cached in `geoCacheRef` (per-session, keyed by IP). Cache prevents duplicate requests for IPs seen in multiple flows.
    *   The resolved label format is `"City, Region, Country — ORG"` (e.g. `"Seoul, Gyeonggi-do, KR — AS4766 Korea Telecom"`). Both `connections` and `detections` state are retroactively updated when resolution completes.
    *   `shortGeo(location)` helper extracts only the country code for compact display in group header rows.

*   **AI Client**:
    *   `GoogleGenAI` is **not** initialized at module load. `getAiClient()` is an async function that lazily instantiates the client on first call by invoking `get_api_key` via Tauri IPC. Subsequent calls return the cached instance.
    *   On startup, if `get_api_key` throws, `useCloudAi` is set to `false` and the local explanation engine takes over for all detections.
    *   **Auto-Explanation**: Every new detection (score ≥ 45) automatically calls Gemini 2.0 Flash to explain the IP context in 1–2 sentences. On quota exhaustion or API failure, the request falls back to `localExplain()`.
    *   **`localExplain()`**: Rule-based fallback engine. Builds a human-readable explanation from: GeoIP org name, country, port semantics (well-known port descriptions), heuristic reason keywords (Beaconing, Blacklisted, Protocol Mismatch), high-risk country flags (RU, CN, KP, IR, BY), and cloud-provider context (AWS, Google, Azure, etc.).
    *   The `analyzeThreat` function on the Live tab calls `getAiClient()` for manual Deep Trace requests on individual connections.

*   **UI Architecture**:
    *   **Unified Process View**: Both Live and Audit modes render `groupedConnections` — one collapsible row per application. Expanded sub-rows show per-socket details (IP, geolocation, protocol:port, KB/s). Live sub-rows additionally expose the AI analyze and block buttons.
    *   **Static-Width Table**: Uses `table-fixed` with a `<colgroup>` declaring explicit column widths (status 40px, process 26%, endpoint 26%, protocol 18%, data rate 20%, actions 80px). Content never overflows horizontally regardless of protocol count or location string length.
    *   **Protocol Badges**: Group header Protocol column renders each unique protocol as a flex-wrap chip. Badges stack vertically when a process uses many protocols — preventing column expansion.
    *   **Detection Deduplication**: `detectionCooldownRef` (`Set<string>`) stores `IP:threatLabel` keys with a 60-second TTL, preventing duplicate cards for the same event firing from both Inbound and Outbound packet directions.
    *   **Detection Log Export**: Both the Notifications tab (`vigilance_alerts_log`) and Guardian tab (`vigilance_heuristic_log`) expose an "Export Log" button via `exportDetectionsCsv(prefix)` — serializes `detections` to 7-column CSV: `Time, IP Address, Port, Location, Threat Reason, Risk Score, AI Note`.
    *   **Live Throughput Chart**: 30-second rolling `AreaChart` (Recharts). A 1-second `setInterval` samples the delta of `sessionTotalDownRef` / `sessionTotalUpRef` to compute MB/s, appends a new point, and drops the oldest. `isAnimationActive={false}` prevents per-point transition jitter.
    *   **Atomic Components**: `StatCard`, `SidebarItem` designed for high-density information display.
    *   **Motion**: Uses `framer-motion` for layout transitions and tab switching.

## 3. Data Flow
1.  **Ingress**: Rust Sniffer thread intercepts a raw Ethernet frame via `pnet`.
2.  **Direction**: Destination IP compared to `local_ips` → packet classified as Inbound or Outbound. Addresses and ports assigned accordingly.
3.  **Mapping**: `PORT_MAP` lookup on `local_port` → `(PID, process_name)`.
4.  **Scoring**: Heuristic function evaluates the remote IP, port, protocol, and beaconing interval.
5.  **Aggregation**: Bytes accumulated into flow bucket (keyed by `ip:port:proto:direction`) for 500ms.
6.  **Emit**: `app.emit("network-event", event)` fires every 500ms; bucket is cleared.
7.  **Reactive Update**: `App.tsx` listener updates `connections`, `sessionTotalDown/Up`, and `detections`.
8.  **Derived State**: `groupedConnections` and `finalFilteredConnections` recomputed via `useMemo`.

## 4. Key Performance Optimizations & Modes

*   **Unified Grouped View (Live + Audit)**: Both modes now render `groupedConnections`. Live mode adds real-time KB/s and action buttons in the expanded sub-rows; Audit mode shows cumulative forensic totals.
*   **Audit Mode**: Prioritizes process-level cumulative volume tracking. `sessionTotalDown/Up` shown as primary stats.
*   **Active Mode**: Optimizes for real-time threat hunting. Live KB/s rates shown as primary stats.
*   **Freeze Control**: Pauses UI state reconciliation via `isPausedRef` while the Rust backend continues packet accumulation in the background.
*   **Aggregated Events**: Backend emits 2 pulses per second (500ms window) per flow, not one event per packet — essential for stability at high bandwidth.
*   **Defensive Whitelisting**: Heuristic engine ignores global discovery broadcasts (`255.255.255.255`, `*.255`) to eliminate false positives.

## 5. Security Model

*   **Local-First**: No raw packet data or identity information is ever transmitted to external servers.
*   **API Key at Runtime Only**: The Gemini API key is loaded from `src-tauri/resources/config.json` at runtime via a Tauri command. It is excluded from git (`.gitignore`) and never embedded in the distributed JavaScript bundle.
*   **Kernel Block**: On Windows, WFP rules are implemented at the OS level and persist even if the UI is closed. On macOS, `pfctl` rules persist via `~/.vigilance_desktop_rules.json` and are reloaded on each app launch; a sudoers entry enables passwordless `pfctl` execution.
*   **Zero-Config Resolution**: Maps ports to PIDs natively without additional drivers, using built-in OS tools (`netstat` on Windows, `lsof` on macOS, `ss` on Linux).
*   **GitHub Safety**: `src-tauri/resources/config.json` and `src-tauri/target/` are git-excluded. A `config.example.json` with a placeholder key is provided for contributors.
