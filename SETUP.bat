@echo off
rem SecureNet one-time setup for this PC (double-click). Safe to run again.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SETUP.ps1" %*
echo.
pause
