# Vigilance-Desktop: Network Monitoring & Security Shield

https://github.com/user-attachments/assets/4f626fc0-d0f5-461b-8e2a-33757ab97c05

**Current Release: v2.1.0 Stable — The AI Clarity Update** — [Changelog](./CHANGELOG.md)

Vigilance-Desktop has officially moved from prototype to a **production-grade security engine**. It provides real-time visibility into network traffic, automated AI threat analysis, and kernel-level protocol transparency through a unified Desktop experience.

## 🏗️ Architecture

The project is a full-stack **Tauri** desktop application:
1. **Frontend (React + Vite)**: A "Professional Polish" dashboard that displays network intelligence and security alerts. Features a new static-width optimized layout for high-density monitoring.
2. **Backend (Rust Guardian Core)**: A kernel-level system probe in `src-tauri`. It leverages the `pnet` crate for packet capture and now includes specific decoding for non-TCP/UDP protocols.

## 🚀 Running on macOS (Admin Privileges)

To capture live packets, the backend requires access to BPF devices. You have two options:

### Option A: Grant BPF Access (Recommended)
This allows the sniffer to work without running the entire UI as root. Run this once per boot:
```bash
sudo chown $(whoami) /dev/bpf*
```

Then start the app normally:
```bash
npm run tauri dev
```

### Option B: Run as Root
If you prefer not to touch BPF permissions:
```bash
sudo /Applications/Vigilance.app/Contents/MacOS/vigilance
```

## 💎 v2.1.0 Key Highlights

**Per-Detection AI Analysis**: Each detection card in the Guardian and Notifications tabs now has its own **Ask AI** button. Click it to send that specific detection to Gemini and get a targeted 1–2 sentence assessment written directly into the card.

**Global Tab AI Analysis**: A purple **Ask AI** button in the top header bar analyzes the full context of the current tab — all active connections, all detections, or all blocked IPs — and displays a summary banner.

**GeoIP Instant Push**: The backend now emits a dedicated `geo-resolved` event the moment an IP resolves, pushing country, city, ASN, and org to the frontend immediately — even if that connection has gone idle. Previously geo stayed blank if traffic stopped before resolution completed.

**IPv6 Support**: Full IPv6 packet capture — the sniffer dispatches on Ethernet EtherType before parsing. Traffic from Apple CDN, Netflix, Cloudflare, and all QUIC/HTTP3 services is now fully visible.

**Direction Detection**: BPF promiscuous mode filters out unicast frames for other LAN devices. Only this machine's traffic is counted.

**Memory Safety**: `GEO_CACHE` capped at 2000 entries; `connection_history` capped at 5000 entries — both evict oldest entries when full.

🛡️ Setup & Troubleshooting
For hardware setup (Npcap), compiler linker fixes, and driver permissions:
👉 DOCS/TROUBLESHOOTING.md

📦 Binary Downloads & Verifications
To verify your download, run shasum -a 256 [filename] (macOS) or Get-FileHash [filename] (Windows).

**macOS Distributions**: 

| Platform / Architecture | Filename | SHA-256 Checksum |
|-------------------------|----------|------------------|
| **macOS Universal** | `Vigilance_2.1.0_universal.dmg` |  |
| **Apple Silicon Native** | `Vigilance_2.1.0_aarch64.dmg` |  |
| **Intel Native** | `Vigilance_2.1.0_x64.dmg` |  |
| **macOS Portable (Zip)** | `Vigilance-Portable-mac-v2.1.0.zip` |  |

## Windows Distributions
| Method | Filename | SHA-256 Checksum |
|--------|----------|------------------|
| **Windows Installer** | `Vigilance_2.1.0_x64_en-US.msi` |  |
| **Windows Installer** | `Vigilance_2.1.0_x64-setup.exe` |  |
| **Portable (Zip)** | `Vigilance-Portable-v2.1.0.zip` |  |


**macOS Note**: 
Packet capture requires BPF access. The portable binary **must** be run with `sudo ./vigilance-portable`.

🧠 Behavioral AI & Hybrid Guardian Engine

- **Guardian Core (Local Heuristics)**: 
    - **Beaconing Detection**: Now tuned to a 10s threshold to minimize false positives while catching active C2 heartbeats.
    - **Protocol Mismatch**: Flags unusual activity like QUIC/UDP on standard web ports.
- **Local Explanation Engine**: If an AI key is missing, Vigilance uses a built-in rule-based engine to explain threats based on Org, Country, and Port metadata.

**Vigilance-Desktop - Production Grade Network Security.**

## License
MIT License © 2026 Daniel Andries
