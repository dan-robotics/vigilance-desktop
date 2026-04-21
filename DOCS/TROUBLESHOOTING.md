# Vigilance: Troubleshooting & Environment Setup

If you encounter issues running the Vigilance Guardian Core, refer to the solutions below.

## 1. Linker Error: `cannot open input file 'Packet.lib'`
This is the most common error during the build phase. Rust needs the Npcap SDK to link the network sniffer.

1.  Download the **Npcap SDK** from [npcap.com](https://npcap.com/#download) (ZIP file).
2.  Create a folder named `lib` in the **root** of this project (`Vigilance-App/lib`).
3.  Copy `Lib/x64/Packet.lib` and `Lib/x64/wpcap.lib` from the SDK ZIP into your new `lib` folder.
4.  Restart your terminal and run `npx tauri dev` again.

## 2. Runtime Error: `No active network interface found`
If the app panics on startup or shows "Simulation Mode" when it should be active:

1.  **Driver Check**: Ensure **Npcap** is installed on your Windows machine (the driver, not just the SDK).
2.  **Permissions**: Run your terminal (VS Code, CMD, or PowerShell) as **Administrator**. Local packet capture requires raw socket access.
3.  **Interface Selection**: I have updated the code to fall back to any available interface, but ensure your Ethernet or Wi-Fi adapter is marked as "Up" in Windows Network Settings.

## 3. Frontend Error: `Failed to resolve import`
If Vite fails to find `@tauri-apps/api/event`:

1.  Run `npm install` in the project root.
2.  If it persists, delete `node_modules` and run `npm install` again to ensure the v2 libraries are properly linked.

## 4. Application Icons
To regenerate the professional green shield branding:

1.  Ensure `src-tauri/icons/icon.svg` exists.
2.  Run:
    ```bash
    npx tauri icon ./src-tauri/icons/icon.svg
    ```

## 5. Firewall Issues (netsh)
If blocking an IP fails:
- Ensure no other security software (Third-party firewalls) is overriding Windows Firewall.
- The app uses `netsh advfirewall` which requires administrative context.

---

## macOS Setup

### 6. BPF Permission Error (macOS)
Raw packet capture requires access to `/dev/bpf*`. Without it the app starts in Simulation Mode.

**Option A — Grant access for the current session (run once per boot):**
```bash
sudo chown $(whoami) /dev/bpf*
npm run tauri dev
```

**Option B — Persistent group membership (survives reboots):**
```bash
sudo dseditgroup -o create access_bpf
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```
Log out and back in. The app runs without sudo after that.

**Option C — Run the binary directly as root:**
```bash
sudo /Applications/Vigilance.app/Contents/MacOS/vigilance
```

### 7. pfctl Firewall Blocking Requires sudo (macOS)
The `block_ip` command uses `pfctl` under the hood. To allow passwordless blocking, add a sudoers entry:

```bash
sudo visudo -f /private/etc/sudoers.d/vigilance
```

Add this line (replace `your_username`):
```
your_username ALL=(ALL) NOPASSWD: /sbin/pfctl
```

### 8. lsof Not Resolving Process Names (macOS)
The process resolver polls `lsof` every 3 seconds. If all connections show "Guardian Kernel" instead of real process names:

1. Ensure the app has **Full Disk Access** in **System Settings → Privacy & Security → Full Disk Access**.
2. Verify `lsof` is available: `which lsof` should return `/usr/sbin/lsof`.
3. On Apple Silicon, confirm Rosetta is not interfering if running an Intel build.

### 9. Building for macOS (All Targets)

```bash
# Apple Silicon
npm run tauri build -- --target aarch64-apple-darwin

# Intel
rustup target add x86_64-apple-darwin
npm run tauri build -- --target x86_64-apple-darwin

# Universal (both in one .dmg)
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run tauri build -- --target universal-apple-darwin

# Portable zip (run after any build)
cd src-tauri/target/release/bundle/macos && zip -r ~/Desktop/Vigilance-Portable-mac.zip Vigilance.app
```

Build output: `src-tauri/target/release/bundle/macos/Vigilance.app` and `src-tauri/target/release/bundle/dmg/`.
