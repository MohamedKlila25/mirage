# Open the Mirage SOC Console (advanced live dashboard) in your browser.
# Run from the repo root in a PowerShell terminal:  .\console.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
powershell -ExecutionPolicy Bypass -File scripts\mongo.ps1 | Out-Host
$env:PYTHONPATH = $PSScriptRoot
Write-Host "Mirage SOC Console  ->  http://127.0.0.1:8600   (Ctrl+C to stop)" -ForegroundColor Cyan
Start-Process "http://127.0.0.1:8600"
& "$PSScriptRoot\.venv312\Scripts\python.exe" -m dashboard.server
