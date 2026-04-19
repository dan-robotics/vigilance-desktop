# Vigilance Portable Build Script
# Usage: .\build-portable.ps1
# Output: Vigilance-Portable.zip

$version = "0.2.1"
$exeSource = "src-tauri\target\release\vigilance.exe"
$outDir = "Vigilance-Portable"
$zipName = "Vigilance-Portable-v$version.zip"

if (-not (Test-Path $exeSource)) {
    Write-Error "vigilance.exe not found. Run 'npx tauri build' first."
    exit 1
}

# Clean previous output
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
if (Test-Path $zipName) { Remove-Item -Force $zipName }

# Build folder structure
New-Item -ItemType Directory -Path "$outDir\config" | Out-Null
New-Item -ItemType Directory -Path "$outDir\logs"   | Out-Null

# Copy exe
Copy-Item $exeSource "$outDir\vigilance.exe"

# Create config template
@'
{
  "GEMINI_API_KEY": "your-gemini-api-key-here"
}
'@ | Set-Content "$outDir\config\config.json"

# Create README.txt
@"
Vigilance Desktop v$version - Portable Edition
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
"@ | Set-Content "$outDir\README.txt"

# Zip it
Compress-Archive -Path "$outDir\*" -DestinationPath $zipName

Write-Host ""
Write-Host "Built: $zipName" -ForegroundColor Green
Write-Host "Contents:"
Get-ChildItem $outDir -Recurse | ForEach-Object { Write-Host "  $($_.FullName.Replace((Resolve-Path $outDir).Path, ''))" }
