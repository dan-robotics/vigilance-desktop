# Vigilance Portable Build Script
# Usage: .\build-portable.ps1
# Output: Vigilance-Portable.zip

$version = "1.0.1"
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

# Copy exe and README
Copy-Item $exeSource "$outDir\vigilance.exe"
Copy-Item "src-tauri\resources\README.txt" "$outDir\README.txt"

# Create config template
@'
{
  "GEMINI_API_KEY": "your-gemini-api-key-here"
}
'@ | Set-Content "$outDir\config\config.json"

# Zip it
Compress-Archive -Path "$outDir\*" -DestinationPath $zipName

Write-Host ""
Write-Host "Built: $zipName" -ForegroundColor Green
Write-Host "Contents:"
Get-ChildItem $outDir -Recurse | ForEach-Object { Write-Host "  $($_.FullName.Replace((Resolve-Path $outDir).Path, ''))" }
