# Vigilance-Desktop: Network Monitoring & Security Shield


<img width="2106" height="1184" alt="vigilance-app-record" src="https://github.com/user-attachments/assets/4269212a-c45e-437e-ab24-890f78f226a7" />


**Current Release: v3.1.0 Stable — The Guardian Clarity Update** — [Changelog](./CHANGELOG.md)

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

## 💎 v3.1.0 Key Highlights

**Gemini API Key in Settings**: Paste your Gemini API key directly in the app — no manual config.json editing. "Get a free API key →" opens Google AI Studio in your browser. Model updated to `gemini-2.5-flash`. Live notification banners alert you when the key is missing or quota is exceeded, with a one-click jump to Settings.

**Root Daemon Process Attribution**: Connections from root-owned processes (JumpCloud agent, MDM agents, system daemons) that were previously labeled "Guardian Kernel" are now identified by hostname. As soon as reverse DNS resolves `*.jumpcloud.com`, the connection is relabeled "JumpCloud Agent" — no restart needed. `sudo lsof` fallback on macOS for full PID visibility when passwordless sudo is configured.

**Stable Live View**: Process groups and individual connections no longer jump around as new packets arrive. First-seen order is tracked and enforced — data rates update live without reordering. Column header sorts still work on demand.

**Expanded LAN Intelligence**: OUI vendor table grew from 8 to 20+ vendors (Starlink, Google, Amazon, Cisco, D-Link, Arris, Eero, Huawei, Xiaomi, Motorola, Synology, QNAP, Dell, HP). Randomized MAC addresses (iOS/Android privacy mode) are now detected and labeled. IPv6 EUI-64 addresses yield MAC lookups. Hardware-aware OS detection prevents false "macOS" labels on Raspberry Pi hardware. LAN device classification is cached per IP — OS label no longer flips between packets.

**Copyright corrected**: © 2026 Daniel Andries across all bundle metadata.

🛡️ Setup & Troubleshooting
For hardware setup (Npcap), compiler linker fixes, and driver permissions:
👉 DOCS/TROUBLESHOOTING.md

📦 Binary Downloads & Verifications
To verify your download, run shasum -a 256 [filename] (macOS) or Get-FileHash [filename] (Windows).

**macOS Distributions**: 

| Platform / Architecture | Filename | SHA-256 Checksum |
|-------------------------|----------|------------------|
| **macOS Universal** | `Vigilance_3.1.0_universal.dmg` | 0a6ccf06cf651a5fafc38ed0ae08ac21f305f6229892f65be9324abb2786853a |
| **Apple Silicon Native** | `Vigilance_3.1.0_aarch64.dmg` | b526710152327cb01142524c086ec9d3fcb22cde575abd5e414819dd061dcb7b |
| **Intel Native** | `Vigilance_3.1.0_x64.dmg` | 0908164ecfb4811f13ddda063314e8be6b68b4ba91afd2b67a0c670d62831c47 |
| **macOS Portable (Zip)** | `Vigilance-3.1.0-Portable-Universal.zip` | ab6aaed486a64fcaa1e082607d667ae3163673b6b05f99c8394d493cc2c3763f |

## Windows Distributions
| Method | Filename | SHA-256 Checksum |
|--------|----------|------------------|
| **Windows Installer** | `Vigilance_3.1.0_x64_en-US.msi` | a4ab316fa5ca4254017b4e2f96465cc77e930ba5e0e8d2f57a974b69b83e9125 |
| **Windows Installer** | `Vigilance_3.1.0_x64-setup.exe` | 0908164ecfb4811f13ddda063314e8be6b68b4ba91afd2b67a0c670d62831c47 |
| **Portable (Zip)** | `Vigilance-Portable-v3.1.0.zip` | d18573cb6226346fcc5376e4e6b55911af751e254d9c540fb324aaaa34be7253 |


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
