## 📜 Changelog

### 🔧 v2.1.1 — GeoIP Reliability Update

#### GeoIP — 6-Provider Fallback Chain
- **5 additional geo providers**: ipinfo.io remains primary. If it fails or rate-limits, the app now automatically falls through ipapi.co → ipwhois.app → api.ip.sb → geojs.io → ip-api.com. All providers are free with no API key required. All except the last resort (ip-api.com) use HTTPS.
- **Cross-platform TLS fix**: Switched from implicit native-tls to `rustls-tls` (embedded Mozilla root certificate bundle). Eliminates silent TLS failures on Windows where the OS Schannel could reject connections that macOS accepts. Geo resolution now behaves identically on both platforms.

#### Version
- **v2.1.1** unified across `package.json`, `Cargo.toml`, `tauri.conf.json`, About dialog, and `README.txt`.

---

### 🚀 v2.1.0 — The AI Clarity Update (Stable)

#### AI — Per-Detection Analysis
- **"Ask AI" button on every detection card**: Both the Guardian (Heuristic Event Log) and Notifications tabs now have a dedicated **Ask AI** button on each detection card, placed next to the Block IP button. Clicking it sends that specific detection's IP, port, protocol, reason, score, and location to Gemini and writes the response directly into that card's AI note. Shows "Asking…" with a disabled state while in progress.
- **Global "Ask AI" tab button in header**: A purple **Ask AI** button in the top header bar analyzes the full context of whichever tab is active — all current connections (Live), all detections (Guardian / Notifications), or all blocked IPs (Firewall). Result appears as a dismissible banner below the header.
- **Local engine fallback**: Both the per-card and tab-level buttons fall back to the local `localExplain` engine if Cloud AI is disabled, so they always produce output.

#### GeoIP — Instant Push Channel
- **Dedicated `geo-resolved` Tauri event**: The backend now emits a `geo-resolved` event immediately when an IP resolves — independent of whether another packet from that IP arrives. Previously, geo info was only bundled into the next network packet from that IP; if traffic from a connection stopped before geo resolved, the frontend never received the location and it stayed blank permanently.
- **Frontend listener backfills all tabs**: The frontend listens for `geo-resolved` and immediately updates all matching connections in the Live table and all matching detection cards in Guardian and Notifications — country, city, ASN, org, and local AI note all update at once.

#### Windows — Adapter Auto-Selection Fix
- **Physical WiFi/LAN now selected by default on Windows**: The app was defaulting to the Hyper-V virtual adapter instead of the physical network card. Fixed both the backend candidate filter (virtual adapters with priority 0 are now fully excluded from auto-selection) and the frontend default picker (now searches for physical WiFi first, then physical Ethernet, explicitly skipping virtual adapters from Hyper-V, VMware, VirtualBox, and common VPN clients like Cisco, Juniper, and FortiClient).

#### Version
- **v2.1.0 Stable** unified across `package.json`, `Cargo.toml`, `tauri.conf.json`, About dialog, and `README.txt`.

---

### 🚀 v2.0.1 — The Network Clarity Update

#### IPv6 Support (Critical)
- **Full IPv6 Packet Capture**: The sniffer now dispatches on Ethernet EtherType (`0x0800` IPv4 / `0x86DD` IPv6) before parsing. Previously, IPv6 frames were silently misread as garbage IPv4 packets — causing streaming traffic from Apple CDN, Netflix, Cloudflare, and all QUIC/HTTP3 services to be entirely invisible or wrongly counted as upload. All modern CDNs default to IPv6, so this was the root cause of near-zero download readings.
- **TCP/UDP port extraction in IPv6**: Ports are now correctly extracted from TCP and UDP headers inside IPv6 frames, enabling process attribution and flow tracking on IPv6 connections.

#### Direction Detection Fix
- **Promiscuous mode filter**: BPF on macOS captures all frames on the LAN segment, including unicast traffic destined for other devices (Apple TV box, phones, etc.). Packets where neither source nor destination matches the Mac's own IP are now skipped — eliminating other devices' traffic from being counted as this machine's upload.
- **Correct direction logic**: Only packets involving this machine's IPs are counted. Inbound = `dst` matches local IP (Download). Outbound = `src` matches local IP (Upload).

#### GeoIP — Rebuilt
- **IPv6 IPs now resolved**: The GeoIP queue previously only accepted IPv4 addresses (`parse::<Ipv4Addr>()`). IPv6 addresses were silently skipped — meaning all connections to modern CDNs (Apple, Netflix, Google, Cloudflare) showed no ASN, org, or country. Fixed: both public IPv4 and public IPv6 addresses are now queued.
- **Concurrent lookups**: GeoIP resolution is now parallel — up to 8 IPs resolve simultaneously via `tokio::spawn`. Previous sequential processing (8 IPs × 5s timeout = 40s/batch) meant resolution always finished after the connection was gone.
- **ip-api.com fallback**: If ipinfo.io fails or returns empty data, falls back to ip-api.com automatically.
- **No more "Resolving…" ghost text**: Removed the `city: "Resolving..."` placeholder that was inserted into `GEO_CACHE` while lookup was in progress. Detection cards were building their AI note from this placeholder, producing "located in Resolving..." in every alert. Now nothing is written to the cache until real data arrives.
- **User-Agent header**: Added `User-Agent: Vigilance/1.0` to prevent anonymous-bot rate limiting.

#### AI Notes — Fixed
- Removed frontend `fetch('https://ipinfo.io/...')` from the webview — GeoIP is now 100% handled by the Rust backend. The webview fetch was failing silently (CORS/sandbox) and polluting `geoCacheRef` with stale state.
- Detection cards now regenerate `aiNote` immediately when backend GeoIP first arrives for an IP (backfill pass).
- Fixed Gemini model name: `gemini-3-flash-preview` → `gemini-2.0-flash`.

#### Memory Safety
- **`GEO_CACHE` capped at 2000 entries** — evicts 500 oldest when full. Previously unbounded.
- **`connection_history` capped at 5000 entries** — evicts oldest key at limit. Previously unbounded.

#### App & Distribution
- **macOS About dialog**: Clicking "About Vigilance" in the app menu shows name, version, copyright, and full MIT license text.
- **Version unified to 2.0.1** across `Cargo.toml`, `tauri.conf.json`, and `package.json`.
- **package.json name** corrected from `react-example` to `vigilance`.

---

### 🚀 v1.0.1 — The Intelligence Update

#### Protocol Intelligence
- **Full Protocol Decoding**: The backend no longer emits `OTHER` for non-TCP/UDP packets. Named decoding added for IGMP (2), IPIP (4), GRE (47), ESP (50), AH (51), OSPF (89), PIM (103), VRRP (112), SCTP (132). Unknown protocol numbers fall back to `PROTO-N` format.
- **Kernel Transparency**: System-level packets (ICMP, IGMP, GRE, OSPF, etc.) are grouped under "Guardian Kernel" in the UI with their protocol type visible in sub-rows as named badges.

#### GeoIP Intelligence
- **Live Location Lookups**: Every unique remote IP resolves asynchronously to City, Region, Country, and ISP/Organization via the `ipinfo.io` API. Results are cached per-session and applied to both the connection table and detection cards.
- **Country Display**: Group header rows show a compact country code (e.g. `KR`, `US`) next to each endpoint. Sub-rows and detection cards show the full location string on hover.

#### AI Guardian (Auto-Explanation)
- **Automatic Detection Analysis**: Every new detection (threat score ≥ 45) automatically triggers a Gemini 2.0 Flash request explaining what the IP likely belongs to and whether the traffic is worth investigating.
- **Local Fallback Engine** (`localExplain`): When cloud AI is disabled or unavailable (missing key, quota exceeded), a built-in rule-based engine generates an explanation from GeoIP org/country, port semantics, and heuristic reason — no API required.
- **Auto-Disable**: If the Gemini API key is missing or unreadable at startup, cloud AI is silently disabled and the local engine takes over immediately.

#### Heuristics Engine
- **Beaconing Threshold**: Tuned to 10 seconds minimum interval to balance sensitivity (catches active C2 heartbeats) without excessive false positives on normal keep-alive traffic.
- **Multicast Filter**: Entire `224.0.0.0/4` range (mDNS, SSDP, IGMP multicast) excluded from scoring — returns score 0 and label "Multicast (Normal)".
- **Deduplication**: Detection cards now have a 60-second cooldown per `IP:threatLabel` key, eliminating duplicate alerts for the same event from both Inbound and Outbound packet directions.

#### UI / Table Layout
- **Static-Width Table**: Replaced fluid `overflow-x-auto` table with a `table-fixed` + `<colgroup>` layout. Columns have declared widths — no more horizontal scrolling regardless of how many protocols or how long the location string is.
- **Protocol Badges**: Protocol column in group header rows now renders each protocol as an individual chip (`flex-wrap`) — badges stack vertically when a process uses many protocols (e.g. Guardian Kernel with ICMP/IGMP/GRE/OSPF), never pushing the table wider.
- **Sub-row Density**: Compact `px-4` padding, `shortGeo()` country-only location inline (full string on hover via `title`), AI text clamped to 2 lines, threat label truncated with tooltip.

#### Fixes & Reliability
- **Fix — GeoIP Backfill**: Detection cards retroactively update location and regenerate the local AI explanation when GeoIP resolves after the alert fires.
- **Fix — Windows Virtual Adapter Auto-Selection**: WAN Miniport, ISATAP, Teredo, 6to4, and Loopback adapters excluded from the interface priority filter.
- **Fix — Silent Capture Failures**: When the capture engine fails to open an adapter, the error is now surfaced in the UI. Previously failed silently.
- **Fix — TypeScript Protocol Cast**: Removed stale `as 'TCP' | 'UDP'` cast on `data.protocol` — protocols like ICMP, GRE, OSPF were being silently mis-typed.
- **Fix — Rust Compiler Warnings**: Resolved unused `mut` warning in `build.rs` using conditional compilation blocks.
- **Fix — TypeScript Binary Artifacts**: Added `exclude: ["src-tauri"]` to `tsconfig.json` — stops the compiler from scanning Rust build artifacts in `src-tauri/target/`.
- **Fix — npm tauri Script**: Added `"tauri": "tauri"` to `package.json` scripts so `npm run tauri dev` and `npm run tauri build` work correctly.
- **Perf — Interface Enumeration**: Reduced `datalink::interfaces()` calls from 4 to 1 per capture loop iteration.

### 🚀 v0.2.2 - Mock Data Removal & macOS Support

- **Mock Data Removed**: Removed all hardcoded placeholder connections (fake chrome.exe, svchost.exe, discord.exe, spotify.exe, and the Russian IP 45.182.18.5) that were showing on every launch. App now starts with an empty list and fills with real traffic only.
- **Hardcoded Alert Removed**: Removed static "IP 45.182.18.5 flagged as sinkhole" entry from the Guardian mitigations panel.
- **macOS Support**: Full macOS support — pnet/BPF packet capture, lsof port/PID resolution, pfctl firewall blocking.

#### macOS Downloads — v0.2.2

| File | Platform | SHA256 |
|---|---|---|
| `Vigilance_0.2.2_universal.dmg` | macOS Universal (Intel + Apple Silicon) | `45037de8da259a8d33b3a02176cf1dfb6f3302aeeb9b8daa847f7740a1e8133b` |
| `Vigilance_0.2.2_aarch64.dmg` | macOS Apple Silicon | `4341e9a39ad5a1198d3639d2e233dc8797b5f5be5546fbdaed0d5b01308e588f` |
| `Vigilance_0.2.2_x64.dmg` | macOS Intel | `8c195088a42fd86ee306ef79fe9a7cbfbf47a4285982c8bcdf01a209589e9589` |
| `Vigilance_0.2.2_universal.app.zip` | macOS Portable | `pending` |

---

### 🚀 v0.2.1 - Auto-Elevation & Firewall Reliability

- **Mock Data Removed**: Removed all hardcoded placeholder connections (fake chrome.exe, svchost.exe, discord.exe, spotify.exe, and the Russian IP 45.182.18.5) that were showing on every launch. App now starts with an empty list and fills with real traffic only.
- **Hardcoded Alert Removed**: Removed static "IP 45.182.18.5 flagged as sinkhole" entry from the Guardian mitigations panel.

#### macOS First-Time Setup

Raw packet capture requires BPF device access. Run once in Terminal:

```bash
sudo dseditgroup -o create access_bpf
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```

Log out and back in — the app runs normally without sudo after that.

To launch manually with sudo instead:

```bash
sudo /Applications/Vigilance.app/Contents/MacOS/vigilance
```

#### macOS Firewall Blocking

IP blocking uses `pfctl` and requires sudo. To allow passwordless pfctl, add to `/etc/sudoers`:

```
your_username ALL=(ALL) NOPASSWD: /sbin/pfctl
```

---



- **UAC Auto-Elevation**: Embedded a Windows application manifest (`requireAdministrator`) into the binary via `winres`. The app now requests admin privileges automatically on launch — users no longer need to manually right-click "Run as Administrator" for firewall rules to take effect.
- **Firewall Block Confirmed Working**: IP blocking via Windows Filtering Platform (`netsh advfirewall`) is fully functional when running with the correct privilege level. Rules appear in Windows Firewall within seconds of being applied.
- **HTML Title Fix**: Replaced the placeholder "My Google AI Studio App" browser tab title with "Vigilance | Guardian Core".
- **Portable Mode**: Added portable distribution support. When a `config/` folder exists next to `vigilance.exe` (or `--portable` flag is passed), the app reads config from `.\config\config.json` and writes logs to `.\logs\` instead of AppData. Distributed as `Vigilance-Portable-vX.X.X.zip`.

### 🚀 v0.2.0 - Production Hardening & Installer Polish

- **Silent Subprocess Execution**: All background system commands (`netstat`, `netsh`) now use the `CREATE_NO_WINDOW` Win32 flag — the CMD window that flickered every 3 seconds in installed builds is eliminated.
- **Installer Icon Fix**: Populated the `bundle.icon` array in `tauri.conf.json`; the MSI bundler no longer fails with "Couldn't find a .ico icon".
- **DevTools Disabled**: The right-click inspect menu and Ctrl+Shift+I developer panel are locked out in production builds.
- **AI Quota Visibility**: Deep Trace requests are counted and displayed in Settings. Gemini rate-limit / quota errors (HTTP 429) surface as a dismissible red banner instead of silently failing.
- **Version Alignment**: `tauri.conf.json`, `Cargo.toml`, and `package.json` all unified at `0.2.0`.

### 🚀 v0.1.2 - Unified Process View, Direction Fix & Security Hardening

- **Unified Process Grouping (Live + Audit)**: The Live mode activity feed now uses the same "Smart Folder" grouped view as Audit mode. Both modes show one collapsible row per application — click to expand and reveal individual sockets with their IP, port, protocol, live KB/s rates, AI analysis, and block controls.
- **Inbound Traffic Fix (Critical)**: Resolved a fundamental sniffer bug where all packets were incorrectly classified as `Outbound`. The Guardian Core now detects packet direction by comparing destination IP against the interface's own IP addresses — correctly identifying inbound streams (e.g. Spotify audio) and populating download metrics.
- **Port Assignment Fix**: For inbound packets, `remote_port` is now correctly sourced from the TCP/UDP source field (not destination), ensuring accurate process-to-socket mapping via `PORT_MAP`.
- **Flow Key Integrity**: The per-flow aggregation key now includes direction, preventing inbound and outbound flows to the same remote endpoint from collapsing into a single event with a corrupted direction field.
- **Heuristic Event Log Export**: Added native CSV export to both the Notifications tab and Guardian tab. Exports `Time, IP Address, Threat Reason, Risk Score` via the native Windows save dialog. Each export type has a consistent filename prefix: `vigilance_traffic_log_`, `vigilance_alerts_log_`, and `vigilance_heuristic_log_`, all suffixed with an ISO timestamp.
- **API Key Security Hardening**: Moved Gemini API key loading from Vite build-time injection (where it was baked into the JS bundle) to a runtime `get_api_key` Tauri command that reads `src-tauri/resources/config.json` on-demand. The key is never embedded in distributable assets.
- **Lazy AI Client**: `GoogleGenAI` is no longer initialized at module load — it is instantiated on first use, only when a user manually triggers a Deep Trace. Eliminates startup failures when `config.json` is absent.
- **GitHub-Safe Repository**: Fixed a critical `.gitignore` filename typo (`.gitimore` → `.gitignore`) that caused all exclusion rules to be silently ignored. Added `src-tauri/target/` and `src-tauri/resources/config.json` exclusions. A `config.example.json` template is provided for contributors.

### 🚀 v0.1.2 - Forensic Audit Update
- **Audit vs. Active Modes**: Introduced a global toggle to switch between real-time "Threat Hunting" (Active) and long-term "Data Accounting" (Audit).
- **Process Grouping**: Implemented a "Smart Folder" logic for the activity feed, grouping millions of individual socket connections under their parent process for a clean forensic view.
- **Freeze Control**: Added a hardware-level UI freeze to allow for manual packet inspection without losing session accounting.
- **Native CSV Export**: Re-architected data extraction to use a native Windows "Save As" dialog via Rust, ensuring 100% reliability for forensic logging.
- **Heuristic Whitelisting**: Improved the Guardian Engine to intelligently ignore OS broadcast signals (`255.255.255.255`), significantly reducing false positives.
- **Cost-Optimized AI**: Hard-coded a zero-background policy for Gemini AI. Credits are only used when a user manually requests a "Deep Trace" on a specific connection.
- **Architecture Fixes**: Updated the `sysinfo` integration to v0.30+ and resolved the JavaScript "Temporal Dead Zone" initialization bugs.