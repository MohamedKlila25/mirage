# Open the Mirage analyst dashboard in your browser.
# Run from the repo root in a PowerShell terminal:  .\dashboard.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
powershell -ExecutionPolicy Bypass -File scripts\mongo.ps1 | Out-Host   # make sure MongoDB is up
$env:PYTHONPATH = $PSScriptRoot
Write-Host "Dashboard will open at http://localhost:8501  (Ctrl+C to stop)" -ForegroundColor Cyan
& "$PSScriptRoot\.venv312\Scripts\python.exe" -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
