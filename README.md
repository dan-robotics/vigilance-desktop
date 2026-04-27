<img width="2106" height="1184" alt="vigilance-app-record" src="https://github.com/user-attachments/assets/4269212a-c45e-437e-ab24-890f78f226a7" />

---

# Vigilance-Desktop: Network Monitoring & Security Shield


**Current Release: v3.2.0 Stable** — [View Changelog](./CHANGELOG.md)

Vigilance is a high-performance, native Rust network security monitor and "Guardian" firewall. It provides deep packet inspection (DPI), heuristic threat scoring, and automated hardware fingerprinting without the overhead of a browser-based UI.

## 🚀 Key Features
- **Pure Rust Engine:** Native UI via `egui`, completely eliminating WebView background noise and "Edge Helper" processes.
- **Deep Packet Inspection (DPI):** Extracts **SNI** from TLS handshakes and parses **DNS responses** on the fly for instant hostname attribution.
- **Supreme Fingerprinting:** Multi-vector LAN device identification using mDNS, DHCP, SSDP, and TCP SYN option patterns.
- **Guardian Core:** Advanced behavioral engine detecting beaconing (10s threshold/10% jitter), suspicious ports, and protocol mismatches.
- **Cross-Platform Firewall:** Robust blocklist management via `netsh` (Windows) and `pfctl` (macOS) with custom anchor support.

## 🏗️ Architecture
Vigilance-Desktop has transitioned from a Tauri hybrid to a **100% Native Rust stack**:
1. **Frontend (egui/eframe)**: A hardware-accelerated dashboard designed for high-density monitoring and zero-latency UI updates.
2. **Backend (Guardian Core)**: A kernel-level system probe that leverages `pnet` for raw packet capture and `tokio` for parallelized GeoIP/Hostname resolution.

## ⚙️ Requirements & Setup
- **OS:** Windows 10/11 or macOS 12+ (Monterey or newer).
- **Driver:** Npcap (Windows) or libpcap (macOS/Linux).
- **Privileges:** Administrator/Sudo required for raw packet capture and firewall management.

### Running on macOS (BPF Access)
To capture live packets without running the entire app as root, grant BPF access once per boot:
```bash
sudo chown $(whoami) /dev/bpf*
```

## 💎 v3.2.0 Technical Highlights

### SUPREME Fingerprinting
The OUI vendor table now covers 25+ major manufacturers (Starlink, Google, Amazon, Cisco, Eero, Synology, etc.).
- **Privacy Mode Detection:** Automatically identifies and labels randomized MAC addresses (iOS/Android privacy).
- **Hardware-Aware OS Logic:** Prevents false OS reporting by cross-referencing TTL/Window Scale with hardware manufacturer (e.g., distinguishing Linux on a Raspberry Pi vs. macOS).
- **mDNS & DHCP Backfill:** Instantly relabels "Guardian Kernel" connections to friendly names like "JumpCloud Agent" or "MDM Daemon" once hostnames resolve.

### Hybrid Guardian Engine
- **Local Heuristics:** Real-time scoring (0-100) based on reputation, heartbeats, and port misuse.
- **Gemini AI Integration:** Optional AI-powered threat analysis using `gemini-2.0-flash`. Keys are handled via local `config.json` and never embedded in the binary.
- **Local Fallback:** If AI is disabled, a built-in rule engine explains threats based on Org, Country, and Port metadata.

## 📦 Distributions & Verifications
*To verify a download, run `shasum -a 256 [filename]` (macOS) or `Get-FileHash [filename]` (Windows).*

### macOS (Universal / Silicon / Intel)
| Architecture | Filename |
| :--- | :--- |
| **Universal DMG** | `Vigilance_3.2.0_universal.dmg` |
| **Apple Silicon** | `Vigilance_3.2.0_aarch64.dmg` | 
| **Intel Native** | `Vigilance_3.2.0_x64.dmg` | 
| **Universal Portable** | `Vigilance-MacOS-Universal-Portable-v3.2.0.zip` |


### Windows (Installer / Portable)
| Architecture | Filename |
| :--- | :--- |
| **EXE Installer** | `vigilance_3.2.0_x64-setup.exe` |
| **MSI Installer** | `vigilance_3.2.0_x64_en-US.msi` | 
| **Portable ZIP**  | `Vigilance-Portable-v3.2.0.zip` | 

---

## 🛡️ Support
For driver setup, compiler fixes, and permission troubleshooting:  
👉 [DOCS/TROUBLESHOOTING.md](./DOCS/TROUBLESHOOTING.md)

## License
MIT License © 2026 Daniel Andries
