# Vigilance-Desktop Architecture Block Diagram

## High Level Logic Flow

```text
+----------------------------------------------------------------------+
|                      USER INTERFACE (React)                          |
|                                                                      |
|  +----------------+  +-------------+  +-----------+  +-----------+  |
|  | Live Feed      |  | Walls (WFP) |  | Guardian  |  | Notifs    |  |
|  | (Grouped View) |  |             |  | (AI Trace)|  | + Export  |  |
|  +----------------+  +-------------+  +-----------+  +-----------+  |
|        ^                   ^               ^               |         |
+--------|-------------------|---------------|---------------|--------+
         |                   |               |               |
    Tauri Events       Invoke Commands   Shared State    Invoke
         |                   |               |               |
         v                   v               v               v
+----------------------------------------------------------------------+
|                      TAURI BACKEND (Rust)                            |
|                                                                      |
|  +---------------------+       +-----------------------------+       |
|  | SNIFFER THREAD      |       | PROCESS RESOLVER THREAD     |       |
|  | (500ms Pulses)      |       | (Every 3s Poll)             |       |
|  |                     |       |                             |       |
|  | - Direction detect  |       |                             |       |
|  |   (src/dst vs       |       |                             |       |
|  |    local IPs)       |       |                             |       |
|  | - Flow key:         |       |                             |       |
|  |   IP:Port:Proto:Dir |       |                             |       |
|  +----------+----------+       +-------------+---------------+       |
|             |                                |                       |
|             +--------------+-----------------+                       |
|                            |                                         |
|                            v                                         |
|                  +--------------------+                              |
|                  |  GLOBAL PORT_MAP   |                              |
|                  | (Lazy Static Mutex)|                              |
|                  +--------------------+                              |
|                            |                                         |
|          +-----------------+-------------------+                     |
|          |                 |                   |                     |
|  +-------v----------+      |       +-----------v---------+           |
|  | HEURISTIC ENGINE |      |       | RUNTIME CONFIG      |           |
|  | (Score 0-100)    |      |       | get_api_key()       |           |
|  | - IP reputation  |      |       | reads config.json   |           |
|  | - Port analysis  |      |       | (never in bundle)   |           |
|  | - Beaconing      |      |       +---------------------+           |
|  +------------------+      |                                         |
|                            |                                         |
|          +-----------------+-------------------+                     |
|          |                                     |                     |
|  +-------v-----------+             +-----------v----------+          |
|  | FIREWALL          |             | NATIVE CSV EXPORT    |          |
|  | Win: WFP/netsh    |             | (rfd Dialog)         |          |
|  | Mac: pfctl + JSON |             | Traffic log +        |          |
|  | block_ip()        |             | Detections log       |          |
|  +-------------------+             +----------------------+          |
+----------------------------------------------------------------------+
```

## Data Flow: Packet Lifecycle

```text
Network Card
    |
    v
[pnet raw socket]
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
Heuristic score calculation
    |
    v
emit("network-event", NetworkEvent) → React frontend
    |
    v
Frontend: setConnections() → groupedConnections (by process, both modes)
           setDetections() if threat_score > 40
           setSessionTotalDown/Up (cumulative bytes)
```

## Module Descriptions

1. **Sniffer Module**: Low-latency wrapper around the network card. Computes `local_ips` once per interface selection and classifies every packet as Inbound or Outbound by comparing the destination IP against the interface's own addresses. Uses a 500ms aggregation buffer to prevent UI stutter during high-bandwidth events.

2. **Resolver Module**: Correlates network sockets with process IDs (PIDs) via periodic polling every 3 seconds. Uses the platform-native tool: `netstat -ano -p tcp` on Windows, `lsof -i -P -n -sTCP:LISTEN,ESTABLISHED` on macOS, `ss -tunp` on Linux. Maps local ports → PIDs → process names and writes to a shared `PORT_MAP` Mutex.

3. **Runtime Config Loader**: The `get_api_key` Tauri command reads `src-tauri/resources/config.json` at runtime using `BaseDirectory::Resource`. The Gemini API key is never embedded in the JavaScript bundle.

4. **Walls Module**: The "Bouncer." Platform-conditional firewall blocking:
   - **Windows**: communicates with the Windows Filtering Platform (WFP) via `netsh advfirewall`. Rules persist at the OS level across reboots.
   - **macOS**: applies rules via `pfctl` under the `com.vigilance.desktop` anchor. Blocked IPs are persisted in `~/.vigilance_desktop_rules.json` and reloaded on each change. Requires a one-time sudoers entry for passwordless `pfctl` access.

5. **Guardian Module**: The heuristic "Brain." Calculates internal risk scores (0–100) based on IP reputation blacklist, suspicious port usage, protocol mismatches, and beaconing (fixed-interval heartbeat) detection.

6. **Export Module**: Handles both traffic log and heuristic detection log exports via the `rfd` native file dialog. Traffic: process, PID, IP, port, status, KB/s. Detections: timestamp, IP, threat reason, risk score.
