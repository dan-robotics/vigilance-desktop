# Vigilance-Desktop: Network Monitoring & Security Shield

> **Current Release: v0.2.1** — [Changelog](./CHANGELOG.md)

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

- **Guardian Core (Local Heuristics)**: 
    - **Beaconing Detection**: Identification of fixed-interval heartbeats characteristic of C2 (Command & Control) malware.
    - **Protocol Mismatch**: Detection of spoofed protocols (e.g., non-HTTP traffic on port 80/443).
    - **Weighted Scoring**: Multi-factor risk analysis tracking timing, reputation, and port safety.
- **AI Integration**: Optionally toggle **Gemini 3 Flash** for deep behavioral analysis. It classifies connections by looking at textual intent and process metadata.
- **Automatic Fallback**: If run outside the Tauri shell, the app falls back to high-fidelity simulation mode for UI testing.

## 🛠️ Roadmap
1. **ETW Deep-Dive**: Migration from simple process detection to full Event Tracing for Windows (ETW) for 100% process-to-packet accuracy.
2. **YARA Integration**: Future support for scanning memory buffers using YARA rules.
3. **Multi-Interface Logic**: Enhanced multi-homed network interface simultaneous monitoring.

---
*Vigilance-Desktop - Production Grade Network Security.*

## License
MIT License © 2026 Daniel Andries
