# Vigilance-Desktop: Network Monitoring & Security Shield

https://github.com/user-attachments/assets/4f626fc0-d0f5-461b-8e2a-33757ab97c05

**Current Release: v1.0.1 — The Intelligence Update** — [Changelog](./CHANGELOG.md)

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

## 💎 v1.0.1 Key Highlights
Kernel Transparency: Transitioned from a generic "Guardian Kernel" label to specific decoding for ICMP, IGMP, OSPF, and GRE traffic.

GeoIP Intelligence: Integrated live location lookups to identify City, Country, and ISP/Organization (e.g., AWS, Rostelecom, Korea Telecom) for every connection.

AI Guardian: Automated Gemini 2.0 Flash integration to explain suspicious behaviors in plain English directly within detection cards.

Universal Compatibility: Optimized builds for both Intel and Apple Silicon (M1/M2/M3/M4) Macs.

🛡️ Setup & Troubleshooting
For hardware setup (Npcap), compiler linker fixes, and driver permissions:
👉 DOCS/TROUBLESHOOTING.md

📦 Binary Downloads & Verifications
To verify your download, run shasum -a 256 [filename] (macOS) or Get-FileHash [filename] (Windows).

**macOS Distributions**: 

| Platform / Architecture | Filename | SHA-256 Checksum |
|-------------------------|----------|------------------|
| **macOS Universal** | `Vigilance_1.0.1_universal.dmg` | `pending` |
| **Apple Silicon Native** | `Vigilance_1.0.1_aarch64.dmg` | `pending` |
| **Intel Native** | `Vigilance_1.0.1_x64.dmg` | `pending` |
| **macOS Portable (Zip)** | `Vigilance-Portable-mac.zip` | `7397ab810f94605f1d3bba8bab777276f625c985b331f54740236cb710e9b8b9` |

## Windows Distributions
| Method | Filename | SHA-256 Checksum |
|--------|----------|------------------|
| **Windows Installer** | `Vigilance_1.0.1_x64_en-US.msi` | `3E42E342052ECE457BC98F8250716DB7F6AFDDC5F7BBEDBE1A62F262B9A582DD` |
| **Windows Installer** | `Vigilance_1.0.1_x64-setup.exe` | `4DF6A756A47C6DF78C9312530CD284470D97ED6E8AA0E87F1912FF1118597A71` |
| **Portable (Zip)** | `Vigilance-Portable-v1.0.1.zip` | `01C9620547136BE2551396A32F0418A8B18A4A76A0B410C040A369BC5FE1BBE1` |


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