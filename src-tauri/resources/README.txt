================================================================================
  VIGILANCE DESKTOP v2.1.1 - Network Monitoring & Security Shield
================================================================================

WHAT IS VIGILANCE?
------------------
Vigilance is a professional-grade, local-first network monitoring and security
suite for Windows and macOS. It provides real-time visibility into all network
traffic on your machine, grouped by application, with threat detection,
firewall control, and AI-powered security analysis.

FEATURES
--------
  - Real-time packet capture with process-level attribution (IPv4 + IPv6)
  - Live & Audit modes for threat hunting and forensic accounting
  - Guardian Heuristic Engine: beaconing detection, protocol mismatch analysis
  - AI Deep Trace via Gemini (optional, requires API key)
    - Per-detection "Ask AI" button on Guardian and Notifications tabs
    - Global "Ask AI" tab analysis — summarizes all active connections or alerts
  - Instant GeoIP push: country, city, ASN, and org appear as soon as resolved
  - One-click IP blocking via Windows Firewall (WFP) / macOS pfctl
  - CSV export for traffic logs, alerts, and heuristic events
  - Portable mode: runs from any folder, no install required

REQUIREMENTS
------------
  - Windows 10 / 11 (x64) OR macOS 12+ (Universal / Apple Silicon / Intel)
  - Npcap driver installed on Windows (free): https://npcap.com
  - Administrator / BPF privileges required for packet capture and firewall rules

MACOS SETUP (FIRST TIME)
--------------------------
  Raw packet capture requires BPF device access. Run once in Terminal:

    sudo dseditgroup -o create access_bpf
    sudo dseditgroup -o edit -a $(whoami) -t user access_bpf

  Log out and back in — Vigilance then runs without sudo.

  To allow passwordless firewall blocking via pfctl, add to /etc/sudoers:
    your_username ALL=(ALL) NOPASSWD: /sbin/pfctl

AI DEEP TRACE SETUP (OPTIONAL)
--------------------------------
  1. Get a free Gemini API key at: https://aistudio.google.com
  2. Edit config.json in the app resources folder and add your key:
       { "GEMINI_API_KEY": "your-key-here" }
  3. Restart Vigilance — the AI toggle will activate in Settings
  4. Use the "Ask AI" button in the header to analyze any tab,
     or click "Ask AI" on individual detection cards in Guardian / Notifications.

SUPPORT & DOCUMENTATION
------------------------
  GitHub:   https://github.com/dan-robotics/vigilance-desktop
  Issues:   https://github.com/dan-robotics/vigilance-desktop/issues
  Contact:  daniel.tehnical@gmail.com

LICENSE
-------
MIT License
Copyright (c) 2026 Daniel Andries

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

================================================================================
