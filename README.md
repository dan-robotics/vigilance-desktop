# Vigilance-Desktop: Network Monitoring & Security Shield

https://github.com/user-attachments/assets/4f626fc0-d0f5-461b-8e2a-33757ab97c05

**Current Release: v2.0.1 — The Network Clarity Update** — [Changelog](./CHANGELOG.md)

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

## 💎 v2.0.1 Key Highlights

**IPv6 Support (Critical)**: Full IPv6 packet capture — the sniffer now dispatches on Ethernet EtherType before parsing. Previously, IPv6 frames were silently misread, causing traffic from Apple CDN, Netflix, Cloudflare, and all QUIC/HTTP3 services to be invisible or wrongly counted as upload.

**Direction Detection Fix**: BPF promiscuous mode now filters out unicast frames destined for other LAN devices. Only packets involving this machine's own IPs are counted — eliminating other devices' traffic from being measured as this machine's upload.

**GeoIP — Rebuilt**: IPv6 IPs now resolve correctly. Resolution is parallel (up to 8 simultaneous lookups via `tokio::spawn`), with automatic fallback to ip-api.com if ipinfo.io fails. The "Resolving…" ghost text that produced "located in Resolving..." in AI notes has been removed.

**AI Notes — Fixed**: GeoIP is now 100% handled by the Rust backend. Detection cards regenerate `aiNote` immediately when backend GeoIP first arrives. Fixed Gemini model name: `gemini-2.0-flash`.

**Memory Safety**: `GEO_CACHE` capped at 2000 entries; `connection_history` capped at 5000 entries — both evict oldest entries when full.

🛡️ Setup & Troubleshooting
For hardware setup (Npcap), compiler linker fixes, and driver permissions:
👉 DOCS/TROUBLESHOOTING.md

📦 Binary Downloads & Verifications
To verify your download, run shasum -a 256 [filename] (macOS) or Get-FileHash [filename] (Windows).

**macOS Distributions**: 

| Platform / Architecture | Filename | SHA-256 Checksum |
|-------------------------|----------|------------------|
| **macOS Universal** | `Vigilance_2.0.1_universal.dmg` |  |
| **Apple Silicon Native** | `Vigilance_2.0.1_aarch64.dmg` |  |
| **Intel Native** | `Vigilance_2.0.1_x64.dmg` |  |
| **macOS Portable (Zip)** | `Vigilance-Portable-mac-v2.0.1.zip` |  |

## Windows Distributions
| Method | Filename | SHA-256 Checksum |
|--------|----------|------------------|
| **Windows Installer** | `Vigilance_2.0.1_x64_en-US.msi` |  |
| **Windows Installer** | `Vigilance_2.0.1_x64-setup.exe` |  |
| **Portable (Zip)** | `Vigilance-Portable-v2.0.1.zip` |  |


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