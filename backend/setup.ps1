# Kept for compatibility - the full setup (Python venv, Node.js, frontend packages,
# .env / cloud database / email checks) lives in the project root: SETUP.bat / SETUP.ps1.
#   .\setup.ps1            same as SETUP.ps1
#   .\setup.ps1 -WithML    also install scikit-learn / XGBoost for the models
param([switch]$WithML)
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'SETUP.ps1') -WithML:$WithML
exit $LASTEXITCODE
