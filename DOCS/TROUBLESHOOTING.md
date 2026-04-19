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
