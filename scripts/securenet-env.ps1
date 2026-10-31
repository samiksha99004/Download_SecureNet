# Shared helpers for SETUP.ps1 / START_SECURENET.ps1 / backend\setup.ps1 (dot-source this file).
# Works on any Windows PC: tools and caches go to <project>\.local so nothing is scattered over C:
# and nothing is written to other drives. Only on the original development PC, which already keeps
# them in F:\tools / F:\dev-cache (owner's rule), are those folders reused. On another PC an F:
# drive may be a USB stick or DVD drive, so its mere existence is not enough.

$Script:RepoRoot = Split-Path -Parent $PSScriptRoot
$Script:BackendDir = Join-Path $RepoRoot 'backend'
$Script:FrontendDir = Join-Path $RepoRoot 'frontend'

function Get-SecureNetDirs {
    if ($env:SECURENET_TOOLS_DIR) {
        $tools = $env:SECURENET_TOOLS_DIR; $cache = Join-Path $tools 'cache'
    } elseif ((Test-Path 'F:\tools\node\node.exe') -or (Test-Path 'F:\dev-cache\pip')) {
        $tools = 'F:\tools'; $cache = 'F:\dev-cache'
    } else {
        $tools = Join-Path $RepoRoot '.local\tools'; $cache = Join-Path $RepoRoot '.local\cache'
    }
    [pscustomobject]@{ Tools = $tools; Cache = $cache; Node = (Join-Path $tools 'node') }
}

function Use-SecureNetCaches {
    $d = Get-SecureNetDirs
    foreach ($sub in 'pip', 'npm', 'tmp') { New-Item -ItemType Directory -Force (Join-Path $d.Cache $sub) | Out-Null }
    $env:PIP_CACHE_DIR = Join-Path $d.Cache 'pip'
    $env:npm_config_cache = Join-Path $d.Cache 'npm'
    $env:npm_config_update_notifier = 'false'
    $env:npm_config_fund = 'false'
    $env:TEMP = Join-Path $d.Cache 'tmp'; $env:TMP = $env:TEMP
}

# Node.js >= 20.19 (Vite 8). Returns the folder containing node.exe, or $null.
function Find-SecureNetNode {
    $ErrorActionPreference = 'Continue'   # native tools may write to stderr
    $candidates = @((Get-SecureNetDirs).Node)
    $onPath = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += (Split-Path -Parent $onPath.Source) }
    foreach ($dir in $candidates) {
        $exe = Join-Path $dir 'node.exe'
        if (-not (Test-Path $exe)) { continue }
        $v = (& $exe --version) -replace '^v', ''
        $ver = [version]($v -split '-')[0]
        if ($ver -ge [version]'22.12' -or ($ver.Major -eq 20 -and $ver -ge [version]'20.19')) { return $dir }
    }
    return $null
}

# Python 3.11-3.14 for creating the venv. Returns @(exe, args...) or $null.
function Find-SecureNetPython {
    $ErrorActionPreference = 'Continue'   # native tools may write to stderr
    foreach ($v in '3.13', '3.12', '3.14', '3.11') {
        $py = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($py) {
            & $py.Source "-$v" -c "import sys" 2>$null
            if ($LASTEXITCODE -eq 0) { return @($py.Source, "-$v") }
        }
    }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python -and $python.Source -notlike '*WindowsApps*') {
        & $python.Source -c "import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] <= (3,14) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { return @($python.Source) }
    }
    return $null
}

function Test-SecureNetVenv {
    $ErrorActionPreference = 'Continue'   # native tools may write to stderr
    $exe = Join-Path $BackendDir 'venv\Scripts\python.exe'
    if (-not (Test-Path $exe)) { return $false }
    & $exe -c "import fastapi, sqlalchemy, asyncpg, uvicorn" 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Test-SecureNetFrontendDeps {
    return (Test-Path (Join-Path $FrontendDir 'node_modules\.bin\vite.cmd'))
}

# ── Ports: 8000 (backend) / 5173 (dashboard), unless another program already uses them ──
# The ports SecureNet last used are kept in backend\data\ports.json, so the Windows start-up entry
# (backend\scripts\autostart.py) starts the backend on the same port the dashboard talks to.
$Script:PortsFile = Join-Path $BackendDir 'data\ports.json'

function Test-PortInUse([int]$port) {
    [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

function Test-SecureNetBackend([int]$port) {
    try {
        $r = Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 15
        return ($null -ne $r.ids -and $null -ne $r.detector)
    } catch { return $false }
}

function Test-SecureNetDashboard([int]$port) {
    try {
        return ((Invoke-WebRequest "http://localhost:$port" -UseBasicParsing -TimeoutSec 10).Content -match '<title>SecureNet')
    } catch { return $false }
}

# First port from $preferred..$last that is free (Running = $false) or already SecureNet (Running = $true).
function Select-SecureNetPort([int]$preferred, [int]$last, [scriptblock]$isSecureNet) {
    for ($p = $preferred; $p -le $last; $p++) {
        if (-not (Test-PortInUse $p)) { return [pscustomobject]@{ Port = $p; Running = $false } }
        if (& $isSecureNet $p) { return [pscustomobject]@{ Port = $p; Running = $true } }
        Write-Host "Port $p is used by another program - trying the next one." -ForegroundColor Yellow
    }
    return $null
}

function Read-SecureNetPorts {
    try { return (Get-Content $PortsFile -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
}

function Save-SecureNetPorts([int]$backend, [int]$frontend) {
    New-Item -ItemType Directory -Force (Split-Path $PortsFile) | Out-Null
    [IO.File]::WriteAllText($PortsFile, (@{ backend = $backend; frontend = $frontend } | ConvertTo-Json))
}
