Vigilance Desktop v0.2.1 - Portable Edition
================================================

REQUIREMENTS
------------
Npcap must be installed for packet capture to work.
Download free from: https://npcap.com

SETUP
-----
1. Edit config\config.json and add your Gemini API key (optional - only needed for AI Deep Trace).
2. Run vigilance.exe as Administrator (required for firewall rules and packet capture).

PORTABLE MODE
-------------
Vigilance detects portable mode automatically when the config\ folder exists next to the exe.
All settings are read from .\config\config.json
Logs are written to .\logs\

NOTES
-----
- Firewall block rules are written to Windows Firewall and persist at the OS level.
- No data is written to AppData or the registry in portable mode.

https://github.com/dan-robotics/vigilance-desktop
