# Vigilance-Desktop Architecture Block Diagram

# Vigilance Desktop Architecture v3.2.0 (Stable)

## High-Level Logic Flow (Pure Rust)

```text
+----------------------------------------------------------------------+
|                        USER INTERFACE (egui)                         |
|                                                                      |
|  +----------------+  +-------------+  +-----------+  +-----------+  |
|  | Live Feed      |  | Walls (WFP) |  | Guardian  |  | Notifs    |  |
|  | (egui::Grid)   |  |             |  | (AI Trace)|  | + Export  |  |
|  +----------------+  +-------------+  +-----------+  +-----------+  |
|        ^                   ^               ^    ^          ^  ^      |
|        |                   |               |    |          |  |      |
|  Shared Event Vec     Invoke Logic    Geo Cache     Invoke Logic    |
|  (Mutex Guard)             |          (Immediate)          |         |
+--------|-------------------|---------------|---------------|--------+
         |                   |               |               |
         v                   v               v               v
+----------------------------------------------------------------------+
|                        RUST BACKEND (Tokio)                          |
|                                                                      |
|  +---------------------+   +--------------------+  +--------------+ |
|  | SNIFFER THREAD      |   | GEOIP THREAD       |  | PROCESS      | |
|  | (DPI Engine)        |   | (Async / Tokio)    |  | RESOLVER     | |
|  |                     |   |                    |  | (Every 3s)   | |
|  | - TLS SNI / DNS     |   | - 6-provider chain |  | netstat/lsof | |
|  | - Supreme Finger    |   | - GEO_CACHE 2000   |  | → PORT_MAP   | |
|  +----------+----------+   +--------+-----------+  +--------------+ |
|             |                       |                               |
|             v                       v                               |
|    +---------------------------------------------------------+      |
|    | GLOBAL STATE: DEVICE_FINGERPRINT, GEO_CACHE, PORT_MAP   |      |
|    +---------------------------------------------------------+      |
|             |                       |                               |
|  +-------v----------+      +-----------v---------+                  |
|  | GUARDIAN ENGINE  |      | FIREWALL ENGINE     |                  |
|  | - Beaconing      |      | Win: netsh/WFP      |                  |
|  | - Blacklist Check |      | Mac: pfctl -E       |                  |
|  +------------------+      +---------------------+                  |
+----------------------------------------------------------------------+
```

## Data Flow: Packet Lifecycle

```text
Network Card
    |
    v
[pnet raw socket] — physical adapter only (virtual/Hyper-V excluded)
    |
    v
Determine Direction
  dst_ip ∈ local_ips? → Inbound  (remote = src_ip, remote_port = src_port)
                      → Outbound (remote = dst_ip, remote_port = dst_port)
    |
    v
flow_key = "remote_ip:remote_port:protocol:direction"
    |
    v
Aggregate bytes into flow bucket (500ms window)
    |
    v
PORT_MAP lookup (local_port → PID → process name)
    |
    v
GEO_CACHE lookup (remote_ip → GeoInfo)
  hit  → attach geo_info to event
  miss → queue IP in GEO_IN_FLIGHT for async resolution
    |
    v
Heuristic score calculation
    |
    v
emit("network-event", NetworkEvent) → React frontend
    |
    v
Frontend: setConnections() → groupedConnections (by process, both modes)
           setDetections() if threat_score >= 45
           setSessionTotalDown/Up (cumulative bytes)
```

## GeoIP Push Flow

```text
GEO_IN_FLIGHT (pending IPs)
    |
    v
GeoIP Thread — tokio async, up to 8 parallel requests
    |
    +---> ipinfo.io/{ip}/json
    |         hit → GeoInfo { city, region, country_code, asn, org }
    |         miss ↓
    +---> ip-api.com/json/{ip}
              hit → GeoInfo
              miss → drop (no entry written to GEO_CACHE)
    |
    v
GEO_CACHE.insert(ip, geo_info)
    |
    v
emit("geo-resolved", { ip, geo }) → React frontend (immediate push)
    |
    v
Frontend: geoCacheRef updated
          setConnections() — backfill location + geoInfo for matching IP
          setDetections() — backfill location + geoInfo + aiNote for matching IP
```

## AI Analysis Flow

```text
User triggers AI (three entry points):
  1. "Ask AI" header button  → analyzes all items in current tab (batch)
  2. "Ask AI" per-card button (Guardian / Notifications) → single detection
  3. Zap button on sub-row (Live tab) → single connection

    |
    v
useCloudAi enabled?
  YES → getAiClient() → GoogleGenAI (Gemini 2.0 Flash)
           → generateContent(prompt)
           → write result to aiAnalysis[id] or aiTabAnalysis
  NO  → localExplain(ip, port, protocol, location, reason)
           → rule-based: org, country, port semantics, heuristic label
           → write result immediately (no API call)
```

## Module Descriptions

1. **Sniffer Module**: Low-latency wrapper around the network card. Computes `local_ips` once per interface selection and classifies every packet as Inbound or Outbound by comparing the destination IP against the interface's own addresses. Uses a 500ms aggregation buffer to prevent UI stutter during high-bandwidth events. On auto-selection, virtual adapters (Hyper-V, VMware, VPN clients) are excluded — physical WiFi is preferred, then physical Ethernet.

2. **Resolver Module**: Correlates network sockets with process IDs (PIDs) via periodic polling every 3 seconds. Uses the platform-native tool: `netstat -ano -p tcp` on Windows, `lsof -i -P -n -sTCP:LISTEN,ESTABLISHED` on macOS, `ss -tunp` on Linux. Maps local ports → PIDs → process names and writes to a shared `PORT_MAP` Mutex.

3. **GeoIP Module**: A dedicated async Tokio thread that resolves public IPs to city, region, country, ASN, and org. Processes up to 8 IPs concurrently. Primary provider: `ipinfo.io`; fallback: `ip-api.com`. Results are cached in `GEO_CACHE` (capped at 2000 entries). On resolution, emits a `geo-resolved` Tauri event so the frontend updates immediately — independent of whether more traffic arrives from that IP.

4. **Runtime Config Loader**: The `get_api_key` Tauri command reads `src-tauri/resources/config.json` at runtime using `BaseDirectory::Resource`. The Gemini API key is never embedded in the JavaScript bundle.

5. **Walls Module**: The "Bouncer." Platform-conditional firewall blocking:
   - **Windows**: communicates with the Windows Filtering Platform (WFP) via `netsh advfirewall`. Rules persist at the OS level across reboots.
   - **macOS**: applies rules via `pfctl` under the `com.vigilance.desktop` anchor. Blocked IPs are persisted in `~/.vigilance_desktop_rules.json` and reloaded on each change. Requires a one-time sudoers entry for passwordless `pfctl` access.

6. **Guardian Module**: The heuristic "Brain." Calculates internal risk scores (0–100) based on IP reputation blacklist, suspicious port usage, protocol mismatches, and beaconing (fixed-interval heartbeat) detection. Detections with score ≥ 45 are surfaced to the Guardian and Notifications tabs.

7. **AI Module**: Three-tier analysis system. (1) Per-connection analysis via the Zap button on expanded Live sub-rows. (2) Per-detection analysis via the Ask AI button on each Guardian/Notifications card. (3) Tab-level batch analysis via the Ask AI header button — summarizes all active connections, detections, or firewall rules for the current tab. Falls back to the local `localExplain` rule engine when Cloud AI is disabled.

8. **Export Module**: Handles both traffic log and heuristic detection log exports via the `rfd` native file dialog. Traffic: process, PID, IP, port, status, KB/s. Detections: timestamp, IP, threat reason, risk score, AI note.
