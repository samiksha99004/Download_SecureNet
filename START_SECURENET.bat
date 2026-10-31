@echo off
rem SecureNet launcher - double-click to start the backend (:8000) and the dashboard (:5173).
rem Right-click > "Run as administrator" for live packet capture (needs Npcap) and Protection-mode blocking.
rem First time on a PC: run SETUP.bat.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0START_SECURENET.ps1"
if errorlevel 1 pause
timeout /t 5 >nul
