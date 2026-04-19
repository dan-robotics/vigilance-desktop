# Vigilance-Desktop: Network Monitoring & Security Shield

Vigilance-Desktop is a high-performance system-wide network monitor designed for Windows. It provides real-time visibility into network traffic, process-level analysis, and firewall management through a unified Desktop experience.

## 🏗️ Architecture

The project is now a full-stack **Tauri** desktop application:
1. **Frontend (React + Vite)**: A "Professional Polish" dashboard that displays network intelligence, traffic flows, and security alerts. It connects to the backend via Tauri's high-speed IPC bridge.
2. **Backend (Rust Guardian Core)**: A kernel-level system probe located in `src-tauri`. It leverages the `pnet` crate for low-latency packet capture and sends real-time telemetry to the dashboard.

## 🛡️ Setup & Troubleshooting

For hardware setup (Npcap), compiler linker fixes (`Packet.lib`), and driver permissions, please refer to the dedicated troubleshooting guide:

👉 **[DOCS/TROUBLESHOOTING.md](./DOCS/TROUBLESHOOTING.md)**

## 🧠 Behavioral AI & Hybrid Guardian Engine
Vigilance now features a **Hybrid Security Logic** that combines cloud intelligence with hardware-level speed:

- **v1.0 Guardian Core (Local Heuristics)**: 
    - **Beaconing Detection**: Identification of fixed-interval heartbeats characteristic of C2 (Command & Control) malware.
    - **Protocol Mismatch**: Detection of spoofed protocols (e.g., non-HTTP traffic on port 80/443).
    - **Weighted Scoring**: Multi-factor risk analysis tracking timing, reputation, and port safety.
- **AI Integration**: Optionally toggle **Gemini 3 Flash** for deep behavioral analysis. It classifies connections by looking at textual intent and process metadata.
- **Automatic Fallback**: If run outside the Tauri shell, the app falls back to high-fidelity simulation mode for UI testing.

## 📜 Changelog (Production v1.0)

### 🚀 v1.2 - Unified Process View, Direction Fix & Security Hardening

- **Unified Process Grouping (Live + Audit)**: The Live mode activity feed now uses the same "Smart Folder" grouped view as Audit mode. Both modes show one collapsible row per application — click to expand and reveal individual sockets with their IP, port, protocol, live KB/s rates, AI analysis, and block controls.
- **Inbound Traffic Fix (Critical)**: Resolved a fundamental sniffer bug where all packets were incorrectly classified as `Outbound`. The Guardian Core now detects packet direction by comparing destination IP against the interface's own IP addresses — correctly identifying inbound streams (e.g. Spotify audio) and populating download metrics.
- **Port Assignment Fix**: For inbound packets, `remote_port` is now correctly sourced from the TCP/UDP source field (not destination), ensuring accurate process-to-socket mapping via `PORT_MAP`.
- **Flow Key Integrity**: The per-flow aggregation key now includes direction, preventing inbound and outbound flows to the same remote endpoint from collapsing into a single event with a corrupted direction field.
- **Heuristic Event Log Export**: Added native CSV export to both the Notifications tab and Guardian tab. Exports `Time, IP Address, Threat Reason, Risk Score` via the native Windows save dialog. Each export type has a consistent filename prefix: `vigilance_traffic_log_`, `vigilance_alerts_log_`, and `vigilance_heuristic_log_`, all suffixed with an ISO timestamp.
- **API Key Security Hardening**: Moved Gemini API key loading from Vite build-time injection (where it was baked into the JS bundle) to a runtime `get_api_key` Tauri command that reads `src-tauri/resources/config.json` on-demand. The key is never embedded in distributable assets.
- **Lazy AI Client**: `GoogleGenAI` is no longer initialized at module load — it is instantiated on first use, only when a user manually triggers a Deep Trace. Eliminates startup failures when `config.json` is absent.
- **GitHub-Safe Repository**: Fixed a critical `.gitignore` filename typo (`.gitimore` → `.gitignore`) that caused all exclusion rules to be silently ignored. Added `src-tauri/target/` and `src-tauri/resources/config.json` exclusions. A `config.example.json` template is provided for contributors.

### 🚀 v1.1 - Forensic Audit Update
- **Audit vs. Active Modes**: Introduced a global toggle to switch between real-time "Threat Hunting" (Active) and long-term "Data Accounting" (Audit).
- **Process Grouping**: Implemented a "Smart Folder" logic for the activity feed, grouping millions of individual socket connections under their parent process for a clean forensic view.
- **Freeze Control**: Added a hardware-level UI freeze to allow for manual packet inspection without losing session accounting.
- **Native CSV Export**: Re-architected data extraction to use a native Windows "Save As" dialog via Rust, ensuring 100% reliability for forensic logging.
- **Heuristic Whitelisting**: Improved the Guardian Engine to intelligently ignore OS broadcast signals (`255.255.255.255`), significantly reducing false positives.
- **Cost-Optimized AI**: Hard-coded a zero-background policy for Gemini AI. Credits are only used when a user manually requests a "Deep Trace" on a specific connection.
- **Architecture Fixes**: Updated the `sysinfo` integration to v0.30+ and resolved the JavaScript "Temporal Dead Zone" initialization bugs.

## 🛠️ Roadmap
1. **ETW Deep-Dive**: Migration from simple process detection to full Event Tracing for Windows (ETW) for 100% process-to-packet accuracy.
2. **YARA Integration**: Future support for scanning memory buffers using YARA rules.
3. **Multi-Interface Logic**: Enhanced multi-homed network interface simultaneous monitoring.

---
*Vigilance-Desktop - Production Grade Network Security.*

## License
MIT License © 2026 Daniel Andries
