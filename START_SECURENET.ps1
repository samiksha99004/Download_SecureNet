# Start SecureNet: FastAPI backend (port 8000) + Vite dev server (port 5173), then open the browser.
# If another program already uses one of those ports, the next free port is used instead (8001.., 5174..)
# and both servers are told about it, so SecureNet never clashes with other local apps/websites.
# Each server runs in its own window; close those windows to stop SecureNet.
# Run as Administrator for live packet capture (needs Npcap) and Protection-mode firewall blocking.
# First time on a PC: run SETUP.bat.

param([switch]$NoBrowser)   # -NoBrowser: start the servers without opening the dashboard
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\securenet-env.ps1')

function Fail($text) { Write-Host "`n$text" -ForegroundColor Red; exit 1 }

if (-not (Test-Path (Join-Path $BackendDir '.env'))) {
    Fail 'backend\.env is missing - run SETUP.bat first (it creates the file and tells you what to fill in).'
}
if (-not (Test-SecureNetVenv)) { Fail 'The Python environment is missing or was copied from another PC - run SETUP.bat first.' }
$nodeDir = Find-SecureNetNode
if (-not $nodeDir) { Fail 'Node.js 22+ was not found - run SETUP.bat first.' }
if (-not (Test-SecureNetFrontendDeps)) { Fail 'Frontend packages are not installed - run SETUP.bat first.' }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Note: not running as Administrator - live capture / blocking will be unavailable.' -ForegroundColor Yellow
}

# Child windows inherit this environment (Node on PATH, caches off C:)
Use-SecureNetCaches
$env:Path = "$nodeDir;$env:Path"

# ── Ports (reuse the last ones, skip ports that belong to other programs) ──
$saved = Read-SecureNetPorts
$prefBackend = if ($saved -and $saved.backend) { [int]$saved.backend } else { 8000 }
$prefFrontend = if ($saved -and $saved.frontend) { [int]$saved.frontend } else { 5173 }
$be = Select-SecureNetPort $prefBackend 8099 ${function:Test-SecureNetBackend}
if (-not $be) { Fail 'No free port found for the SecureNet backend (8000-8099).' }
$fe = Select-SecureNetPort $prefFrontend 5199 ${function:Test-SecureNetDashboard}
if (-not $fe) { Fail 'No free port found for the SecureNet dashboard (5173-5199).' }
$apiUrl = "http://127.0.0.1:$($be.Port)"
$uiUrl = "http://localhost:$($fe.Port)"
Save-SecureNetPorts $be.Port $fe.Port

# Tell both servers which ports are in use (environment variables win over the .env files)
$env:PORT = "$($be.Port)"
$env:CORS_ORIGINS = "http://localhost:$($fe.Port),http://127.0.0.1:$($fe.Port)"
$env:DASHBOARD_URL = $uiUrl
$env:VITE_API_BASE_URL = "http://localhost:$($be.Port)/api"
$env:VITE_WS_URL = "ws://localhost:$($be.Port)/ws/live"

if ($be.Running) {
    Write-Host "Backend already running on port $($be.Port)."
} else {
    Write-Host "Starting backend on $apiUrl ..." -ForegroundColor Cyan
    Start-Process cmd.exe -WorkingDirectory $BackendDir -ArgumentList '/k', `
        "title SecureNet Backend & venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port $($be.Port) --ws-max-size 65536 --no-server-header"
}
if ($fe.Running) {
    Write-Host "Dashboard already running on port $($fe.Port)."
} else {
    Write-Host "Starting dashboard on $uiUrl ..." -ForegroundColor Cyan
    Start-Process cmd.exe -WorkingDirectory $FrontendDir -ArgumentList '/k', `
        "title SecureNet Frontend & npm run dev -- --port $($fe.Port) --strictPort"
}

Write-Host 'Waiting for SecureNet to come up...'
$deadline = (Get-Date).AddSeconds(90)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        Invoke-WebRequest "$apiUrl/health" -UseBasicParsing -TimeoutSec 3 | Out-Null
        Invoke-WebRequest $uiUrl -UseBasicParsing -TimeoutSec 3 | Out-Null
        $ready = $true; break
    } catch { Start-Sleep -Milliseconds 700 }
}
if (-not $ready) {
    Fail 'SecureNet did not start within 90 seconds - check the "SecureNet Backend" and "SecureNet Frontend" windows for the error.'
}
if (-not $NoBrowser) { Start-Process $uiUrl }
Write-Host "SecureNet is running at $uiUrl. Keep the two server windows open; close them to stop SecureNet." -ForegroundColor Green
