# Vigilance-Desktop: Network Monitoring & Security Shield


<img width="2106" height="1184" alt="vigilance-app-record" src="https://github.com/user-attachments/assets/4269212a-c45e-437e-ab24-890f78f226a7" />


**Current Release: v3.0.1 Stable — The Local Intelligence Update** — [Changelog](./CHANGELOG.md)

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

## 💎 v3.0.1 Key Highlights

**Local Network Intelligence**: Every device on your LAN is now fully classified in real-time — no external API call needed. IP, MAC OUI (vendor), TTL, TCP window size, and open port are combined to identify the device type, OS, and service (DNS server, SSH server, MySQL, etc.). LAN connections display in blue with a Network icon, clearly separate from internet traffic.

**Smart Multicast Scoring**: Multicast traffic is now scored in three tiers. Standard discovery (mDNS 224.0.0.251, SSDP, LLMNR, IPv6 equivalents) scores 0 — no noise. Routing protocol multicast on a desktop (OSPF, PIM, VRRP) scores 20 and is flagged for investigation — these only appear on routers, so seeing them on a workstation is meaningful. Unknown multicast groups score 10 for visibility.

**Reverse DNS (OS-native)**: A dedicated hostname resolution thread runs `getnameinfo` via the OS DNS resolver — no external API. LAN devices with registered hostnames (DHCP, mDNS) show their name instead of the raw IP. Public IPs with PTR records (AWS, Cloudflare CDN nodes, etc.) also resolve.

**MAC OUI Fingerprinting**: The source MAC address from each Ethernet frame is matched against a built-in OUI table covering Apple, Samsung, Intel, Raspberry Pi, TP-Link, Netgear, ASUS, Ubiquiti, and VMware virtual adapters.

**OS Fingerprinting (TTL + TCP Window)**: TTL=128 uniquely identifies Windows. TTL=255 identifies network equipment. TCP window size (64240 = Windows 10/11, 65535 = macOS/iOS) breaks ties on 64-TTL devices. Works identically on Windows and macOS captures.

**GeoIP Reliability**: 6-provider fallback chain (ipinfo.io → ipapi.co → ipwhois.app → api.ip.sb → geojs.io → ip-api.com) with rustls-tls for consistent cross-platform TLS. Persistent disk cache and session-level GEO_FAILED set prevent rate-limit spirals.

🛡️ Setup & Troubleshooting
For hardware setup (Npcap), compiler linker fixes, and driver permissions:
👉 DOCS/TROUBLESHOOTING.md

📦 Binary Downloads & Verifications
To verify your download, run shasum -a 256 [filename] (macOS) or Get-FileHash [filename] (Windows).

**macOS Distributions**: 

| Platform / Architecture | Filename | SHA-256 Checksum |
|-------------------------|----------|------------------|
| **macOS Universal** | `Vigilance_3.0.1_universal.dmg` | b454816ed4e179995cec344ccb52c05a49b20e7ea8d0e3730e319a20c45f4db4 |
| **Apple Silicon Native** | `Vigilance_3.0.1_aarch64.dmg` | 85e11418ac0f738676fd46a1d67d8804c720dc76b8a0eb2de8a9a08ac5d3823a |
| **Intel Native** | `Vigilance_3.0.1_x64.dmg` | 55191bdb7d5d2c3942d0355a00c48490275ab604cf709a8fd7947bca5cf622b6 |
| **macOS Portable (Zip)** | `Vigilance-Portable-mac-v3.0.1.zip` | 76f6547a729e41e47203963fd53f730fc30ad0fd372a8909f0a1d46cf5ec21d3 |

## Windows Distributions
| Method | Filename | SHA-256 Checksum |
|--------|----------|------------------|
| **Windows Installer** | `Vigilance_3.0.1_x64_en-US.msi` | 13088a0cbbcef0e1d56e244da9f5c5ee6b383631716dc66114a23e6b50e8c981 |
| **Windows Installer** | `Vigilance_3.0.1_x64-setup.exe` | d0c5ab3149c98660b15c4d47f61b4f13a412f9d41de622c301812c3c827d1726 |
| **Portable (Zip)** | `Vigilance-Portable-v3.0.1.zip` | 31b6ec36e9c0f7acb798f77fa54ad11289cfa3329eba8a834366ad17c4801e58 |


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
