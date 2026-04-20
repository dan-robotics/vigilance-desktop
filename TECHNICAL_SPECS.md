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
    *   **Flow Aggregation**: Groups packets into flows keyed by `remote_ip:remote_port:protocol:direction` within a 500ms window before emitting to the frontend. Including `direction` in the key prevents inbound and outbound flows to the same remote endpoint from merging.
    *   **Heuristic Engine**: Assigns `threat_score` (0–100) based on IP reputation blacklist, suspicious ports, protocol mismatches, and beaconing (fixed-interval heartbeat timing analysis).

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

*   **AI Client**:
    *   `GoogleGenAI` is **not** initialized at module load. `getAiClient()` is an async function that lazily instantiates the client on first call by invoking `get_api_key` via Tauri IPC. Subsequent calls return the cached instance.
    *   The `analyzeThreat` function calls `getAiClient()` before each Gemini request, so failures (e.g., missing config) surface only when a user explicitly requests a Deep Trace.

*   **UI Architecture**:
    *   **Unified Process View**: Both Live and Audit modes render `groupedConnections` — one collapsible row per application. Expanded sub-rows show per-socket details (IP, geolocation, protocol:port, KB/s). Live sub-rows additionally expose the AI analyze and block buttons.
    *   **Detection Log Export**: Both the Notifications tab (`vigilance_alerts_log`) and Guardian tab (`vigilance_heuristic_log`) expose an "Export Log" button (disabled when empty) via `exportDetectionsCsv(prefix)` — serializes `detections` to CSV with columns `Time, IP Address, Threat Reason, Risk Score`.
    *   **Live Throughput Chart**: 30-second rolling `AreaChart` (Recharts). A 1-second `setInterval` samples the delta of `sessionTotalDownRef` / `sessionTotalUpRef` to compute MB/s, appends a new point, and drops the oldest. `isAnimationActive={false}` prevents per-point transition jitter. Chart starts empty and builds as live data arrives.
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
