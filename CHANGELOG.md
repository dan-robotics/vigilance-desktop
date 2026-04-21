## 📜 Changelog

### 🔧 v1.0.1 — Windows Reliability Patch

- **Fix — GeoIP Backfill**: Detection cards now retroactively update location and
  regenerate the local AI explanation when GeoIP resolves after the alert fires.
  Affected both platforms but was more visible on Windows due to faster detections.

- **Fix — STATUS Column Overlap**: STATUS header was sized at 40px (w-10) — too
  narrow for label and padding. Widened to 80px, adjacent columns adjusted.

- **Fix — Windows Virtual Adapter Auto-Selection**: WAN Miniport, ISATAP, Teredo,
  6to4, and Loopback adapters were slipping past the priority filter and being
  selected over the real Wi-Fi or Ethernet interface. Exclusion list extended.

- **Fix — Silent Capture Failures Now Visible**: When the capture engine fails to
  open an adapter (permissions, wrong Npcap mode, bad interface), a red banner now
  appears in the UI with the exact error. Previously this failed silently with no
  indication to the user.

- **Perf — Interface Enumeration**: Reduced `datalink::interfaces()` calls from 4
  to 1 per capture loop iteration. Each call hits the Npcap NDIS driver on Windows.


### 🚀 v1.0.1
- **Heuristics Fixes: Corrected beaconing thresholds (10s) and scoring mismatches. 

- **Kernel Intelligence**: Transitioned from "Guardian Kernel" catch-all to specific protocol decoding (ICMP, IGMP, OSPF, etc.).

- **Intelligence**: Integrated async GeoIP lookups and automatic Gemini AI explanations for threats.

- **UI/UX**: Fixed table horizontal scrolling with a new static-width layout and stacking protocol badges.

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