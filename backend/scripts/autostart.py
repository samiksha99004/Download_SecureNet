"""Started by Windows when the user signs in — only while the IDS is ON.

The "SecureNet Monitor" shortcut in the Startup folder (created when a user
turns the IDS on, removed when they turn it off) runs this with the venv's
pythonw.exe, so there is no window. It starts the SecureNet backend in the
background; the backend sees that the IDS was on, turns it back on and shows
one desktop notification. Output goes to backend/logs/autostart.log.
Does nothing when a SecureNet backend is already running.
Uses the ports START_SECURENET last chose (backend/data/ports.json), so the
dashboard finds the backend even when 8000/5173 belong to other programs.
"""

import json
import os
import socket
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
MAX_LOG_BYTES = 5 * 1024 * 1024

os.chdir(BACKEND)
sys.path.insert(0, str(BACKEND))

logs = BACKEND / "logs"
logs.mkdir(exist_ok=True)
log_path = logs / "autostart.log"
if log_path.exists() and log_path.stat().st_size > MAX_LOG_BYTES:
    log_path.replace(logs / "autostart.old.log")
# pythonw has no console: everything (including the app's logger) goes to the file
sys.stdout = sys.stderr = open(log_path, "a", encoding="utf-8", buffering=1)

try:
    saved = json.loads((BACKEND / "data" / "ports.json").read_text(encoding="utf-8-sig"))
except (OSError, ValueError):
    saved = {}
PORT = int(saved.get("backend") or 8000)
DASHBOARD_PORT = int(saved.get("frontend") or 5173)
# same settings the launcher passes (environment variables win over backend/.env)
os.environ["PORT"] = str(PORT)
os.environ["CORS_ORIGINS"] = f"http://localhost:{DASHBOARD_PORT},http://127.0.0.1:{DASHBOARD_PORT}"
os.environ["DASHBOARD_URL"] = f"http://localhost:{DASHBOARD_PORT}"
# Serve the built dashboard from this headless backend too. Otherwise, when the app opens and
# REUSES this already-running backend, http://localhost:8000/ returns the API JSON instead of the
# dashboard. (The Electron launcher sets this itself; the boot-monitor backend must too.)
_frontend_dist = BACKEND.parent / "frontend" / "dist"
if (_frontend_dist / "index.html").is_file():
    os.environ["FRONTEND_DIST"] = str(_frontend_dist)


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


if port_in_use(PORT):
    print(f"Port {PORT} is already in use (SecureNet is running, or another program took the port) - nothing to do.")
    sys.exit(0)

import uvicorn  # noqa: E402

print("Starting SecureNet backend at Windows sign-in (the IDS was on).")
uvicorn.run("app.main:app", host="127.0.0.1", port=PORT, log_level="warning",
            ws_max_size=65536, server_header=False)
