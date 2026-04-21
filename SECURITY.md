# Security Policy

## Updates: 
Updated to reflect that while the app captures raw packets (requiring BPF/sudo), it now explicitly filters multicast and broadcast traffic to reduce noise and prevent false positives.

## Supported Versions
The latest released version of Vigilance Desktop is supported.
Older versions may not receive security updates.

## Reporting a Vulnerability
If you discover a security vulnerability, please report it responsibly.

Please DO NOT open a public GitHub issue.

Instead contact:
- Email: planer_crag5b@icloud.com
- Or GitHub private message to @dan-robotics

We aim to respond within 72 hours.

## Scope
This includes:
- The Vigilance desktop application
- Rust Guardian Core
- Installer and update mechanisms

## Exclusions
Fingerprinting, rate‑limiting, or network blocks caused by third‑party firewalls are not considered vulnerabilities.