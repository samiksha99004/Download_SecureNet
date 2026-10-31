# SecureNet one-time setup for a new (or moved) Windows PC.
#   - Python venv + backend packages (rebuilt if it was copied from another PC)
#   - Node.js (downloaded if missing) + frontend packages
#   - backend\.env: created from the example on first run (with a random JWT secret)
#   - checks the cloud database connection, creates/updates its tables, checks email delivery
# Safe to run again at any time. Use -WithML to also install scikit-learn / XGBoost.

param([switch]$WithML)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\securenet-env.ps1')

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "`n$text" -ForegroundColor Red; exit 1 }

$dirs = Get-SecureNetDirs
Use-SecureNetCaches
Write-Host "Tools: $($dirs.Tools)   Caches: $($dirs.Cache)" -ForegroundColor DarkGray

# ── 1. backend\.env (database address, sign-in secret, email settings — never committed) ──
Step 'Checking backend\.env'
$envFile = Join-Path $BackendDir '.env'
function New-SecureNetSecret {
    $bytes = New-Object byte[] 48
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}
if (-not (Test-Path $envFile)) {
    $text = (Get-Content (Join-Path $BackendDir '.env.example') -Raw) -replace '(?m)^JWT_SECRET=.*$', "JWT_SECRET=$(New-SecureNetSecret)"
    [IO.File]::WriteAllText($envFile, $text)
    Fail ("Created backend\.env from backend\.env.example (with a new random JWT_SECRET).`n" +
          "Open backend\.env in Notepad and fill in:`n" +
          "  DATABASE_URL   your own free Neon PostgreSQL database (https://neon.tech), starting postgresql+asyncpg://`n" +
          "  EMAIL_ENABLED=true, SMTP_USER, SMTP_PASSWORD   a Gmail address and its App Password (sign-in codes are emailed)`n" +
          "  ADMIN_EMAILS   your own email address (that account becomes the SecureNet admin)`n" +
          "Then run SETUP again. README.md (step 3) explains each value.")
}
$envText = Get-Content $envFile -Raw
if ($envText -match '(?m)^JWT_SECRET=(replace-with.*)?\s*$') {
    [IO.File]::WriteAllText($envFile, ($envText -replace '(?m)^JWT_SECRET=.*$', "JWT_SECRET=$(New-SecureNetSecret)"))
    Write-Host 'Generated a random JWT_SECRET in backend\.env.'
}
Write-Host 'backend\.env found.'

# ── 2. Python virtual environment ──
Step 'Python environment'
if (-not (Test-SecureNetVenv)) {
    $python = Find-SecureNetPython
    if (-not $python) {
        Fail ("Python 3.11-3.14 was not found.`nInstall Python 3.13 from https://www.python.org/downloads/ " +
              "(tick 'Add python.exe to PATH'), then run SETUP again.")
    }
    $venv = Join-Path $BackendDir 'venv'
    if (Test-Path $venv) {
        Write-Host 'Existing venv does not work on this PC (it was copied from another computer) - rebuilding it.' -ForegroundColor Yellow
        Remove-Item -Recurse -Force $venv
    }
    Write-Host "Creating venv with $($python -join ' ')"
    $pyExe = $python[0]; $pyArgs = @($python | Select-Object -Skip 1)
    & $pyExe @pyArgs -m venv $venv
    if ($LASTEXITCODE -ne 0) { Fail 'Could not create the Python virtual environment.' }
}
$venvPy = Join-Path $BackendDir 'venv\Scripts\python.exe'
& $venvPy -m pip install --disable-pip-version-check -q --upgrade pip
& $venvPy -m pip install --disable-pip-version-check -q -r (Join-Path $BackendDir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { Fail 'Installing backend packages failed (see the messages above).' }
if ($WithML) {
    & $venvPy -m pip install --disable-pip-version-check -q -r (Join-Path $BackendDir 'requirements-ml.txt')
    if ($LASTEXITCODE -ne 0) { Fail 'Installing ML packages failed.' }
}
Write-Host 'Backend packages installed.'

# ── 3. Node.js ──
Step 'Node.js'
$nodeDir = Find-SecureNetNode
if (-not $nodeDir) {
    Write-Host "Node.js 22+ not found - downloading Node.js 24 LTS to $($dirs.Node)"
    $base = 'https://nodejs.org/dist/latest-v24.x'
    $sums = (Invoke-WebRequest "$base/SHASUMS256.txt" -UseBasicParsing).Content -split "`n"
    $line = $sums | Where-Object { $_ -match 'node-v[\d.]+-win-x64\.zip$' } | Select-Object -First 1
    if (-not $line) { Fail 'Could not find the Node.js download. Install Node.js 24 LTS from https://nodejs.org and run SETUP again.' }
    $hash, $zipName = ($line.Trim() -split '\s+')
    $zip = Join-Path $env:TEMP $zipName
    Invoke-WebRequest "$base/$zipName" -OutFile $zip -UseBasicParsing
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $hash.ToLower()) { Fail 'Node.js download is corrupt (checksum mismatch).' }
    $unpack = Join-Path $env:TEMP 'node-unpack'
    if (Test-Path $unpack) { Remove-Item -Recurse -Force $unpack }
    Expand-Archive $zip $unpack
    if (Test-Path $dirs.Node) { Remove-Item -Recurse -Force $dirs.Node }
    New-Item -ItemType Directory -Force (Split-Path $dirs.Node) | Out-Null
    Move-Item (Get-ChildItem $unpack -Directory | Select-Object -First 1).FullName $dirs.Node
    Remove-Item -Force $zip; Remove-Item -Recurse -Force $unpack
    $nodeDir = Find-SecureNetNode
    if (-not $nodeDir) { Fail 'Node.js installation failed.' }
}
$env:Path = "$nodeDir;$env:Path"
Write-Host "Using Node.js $(& (Join-Path $nodeDir 'node.exe') --version) from $nodeDir"

# ── 4. Frontend packages ──
Step 'Frontend packages'
Push-Location $FrontendDir
try {
    & (Join-Path $nodeDir 'npm.cmd') install --no-audit --no-fund --loglevel=error
    if ($LASTEXITCODE -ne 0) { Fail 'npm install failed (see the messages above).' }
} finally { Pop-Location }
Write-Host 'Frontend packages installed.'

# ── 5. Configuration, cloud database and email ──
Step 'Checking configuration, cloud database (creating/updating its tables) and email'
Push-Location $BackendDir
try {
    & $venvPy (Join-Path $BackendDir 'scripts\check_setup.py')
    if ($LASTEXITCODE -ne 0) { Fail 'Configuration / database check failed (see the message above).' }
} finally { Pop-Location }

# ── 6. Live capture driver ──
if (Test-Path (Join-Path $env:SystemRoot 'System32\Npcap')) {
    Write-Host 'Npcap: installed (live capture available when started as Administrator).'
} else {
    Write-Host 'Npcap: NOT installed - live traffic capture needs it: https://npcap.com (then run START as Administrator).' -ForegroundColor Yellow
}

Write-Host "`nSetup complete. Start SecureNet with START_SECURENET.bat" -ForegroundColor Green
