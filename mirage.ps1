# Run Mirage commands. Examples (from the repo root, PowerShell):
#   .\mirage.ps1 status
#   .\mirage.ps1 setup                       # agent designs the decoy environment (first time)
#   .\mirage.ps1 attack --policy agent --seed 2
#   .\mirage.ps1 compare --seed 1
#   .\mirage.ps1 reset
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
powershell -ExecutionPolicy Bypass -File scripts\mongo.ps1 | Out-Host
$env:PYTHONPATH = $PSScriptRoot
& "$PSScriptRoot\.venv312\Scripts\python.exe" -u -m local.run @args
