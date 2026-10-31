"""
SecureNet — keep the IDS on across a shutdown / restart

* Turning the IDS ON (dashboard) saves {"enabled": true, ...} to
  IDS_STATE_FILE and adds "SecureNet Monitor" to the user's Windows Startup
  folder. Turning it OFF saves false and removes the start-up entry.
  Stopping the server at shutdown changes neither, so the saved state is
  what the user last chose.
* When the backend starts (after sign-in to Windows via the start-up entry,
  or from START_SECURENET.bat) and the saved state is ON, the IDS is turned
  back on and ONE desktop notification says so. No email is sent for this.

The start-up entry runs backend/scripts/autostart.py with the venv's
pythonw.exe (no window). Nothing needs administrator rights.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from app.core.config import BACKEND_DIR, settings
from app.utils.desktop import notify_desktop
from app.utils.logger import logger
from app.utils.timeutil import to_iso_z, utcnow

SHORTCUT_NAME = "SecureNet Monitor.lnk"
RESUME_ATTEMPTS = 20          # right after start-up the network/database may not be ready yet
RESUME_RETRY_SECONDS = 15
_CREATE_NO_WINDOW = 0x08000000

ON_TITLE = "SecureNet"
ON_MESSAGE = "SecureNet is on and is monitoring."
FAILED_TITLE = "SecureNet could not start monitoring"


# ── saved state ──────────────────────────────────────────────────────────────

def load_state() -> dict:
    try:
        return json.loads(settings.ids_state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(enabled: bool, started_by: Optional[dict] = None) -> None:
    path = settings.ids_state_file
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"enabled": enabled, "startedBy": started_by if enabled else None,
                               "changedAt": to_iso_z(utcnow())}, indent=2), encoding="utf-8")
    tmp.replace(path)


# ── Windows start-up entry ───────────────────────────────────────────────────

def startup_dir() -> Path:
    if settings.IDS_STARTUP_DIR:
        return settings.resolve_path(settings.IDS_STARTUP_DIR)
    return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def shortcut_path() -> Path:
    return startup_dir() / SHORTCUT_NAME


_SHORTCUT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:SN_LNK)
$s.TargetPath = $env:SN_TARGET
$s.Arguments = $env:SN_ARGS
$s.WorkingDirectory = $env:SN_DIR
$s.Description = 'SecureNet: turns the IDS back on after the computer restarts'
$s.Save()
"""


def _create_shortcut_sync() -> None:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    target = pythonw if pythonw.is_file() else Path(sys.executable)
    link = shortcut_path()
    link.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SN_LNK": str(link), "SN_TARGET": str(target),
           "SN_ARGS": f'"{BACKEND_DIR / "scripts" / "autostart.py"}"', "SN_DIR": str(BACKEND_DIR)}
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _SHORTCUT_SCRIPT],
        capture_output=True, text=True, timeout=30, env=env, creationflags=_CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.strip()[:300] or "could not create the start-up shortcut")


def _remember_sync(enabled: bool, started_by: Optional[dict]) -> None:
    save_state(enabled, started_by)
    if sys.platform != "win32":
        return
    if enabled:
        _create_shortcut_sync()
    else:
        shortcut_path().unlink(missing_ok=True)


async def remember_ids_state(enabled: bool, started_by: Optional[dict] = None) -> None:
    """Called when a user turns the IDS ON/OFF. Problems are logged, never raised."""
    if not settings.IDS_AUTOSTART:
        return
    try:
        await asyncio.to_thread(_remember_sync, enabled, started_by)
        logger.info(f"IDS {'ON' if enabled else 'OFF'} remembered for the next computer start")
    except Exception as exc:
        logger.warning(f"Could not remember the IDS state for the next start: {exc}")


# ── turn the IDS back on when the backend starts ─────────────────────────────

async def resume_after_restart() -> bool:
    """Turn the IDS on when the backend starts — always when IDS_ON_AT_STARTUP is set (the
    owner wants live monitoring as soon as SecureNet opens), otherwise only if it was ON when
    SecureNet last stopped — and show one desktop notification. A user turning the IDS OFF
    while this is still retrying wins. Returns True when the IDS was turned on."""
    if not settings.IDS_AUTOSTART:
        return False
    from app.ml.ids_service import get_ids_service   # late import: avoids a cycle at startup
    from app.ml.network_monitor import CaptureUnavailable

    ids = get_ids_service()
    started = to_iso_z(utcnow())
    for attempt in range(1, RESUME_ATTEMPTS + 1):
        state = await asyncio.to_thread(load_state)
        switched_off_now = state.get("enabled") is False and str(state.get("changedAt", "")) > started
        wanted = (settings.IDS_ON_AT_STARTUP and not switched_off_now) or state.get("enabled") is True
        if not wanted or ids.enabled:   # not wanted, or a user already turned it on
            return False
        try:
            await ids.start("monitor")
        except CaptureUnavailable as exc:
            logger.error(f"IDS could not be turned on at start-up: {exc}")
            await notify_desktop(FAILED_TITLE, "SecureNet can't watch the network on this computer right now. "
                                               "Open SecureNet for details.")
            return False
        except Exception as exc:  # network / database not ready yet right after start-up
            logger.warning(f"Turning the IDS on failed (attempt {attempt}/{RESUME_ATTEMPTS}): {exc}")
            await asyncio.sleep(RESUME_RETRY_SECONDS)
            continue
        ids.started_by = state.get("startedBy") if state.get("enabled") else None
        if not state.get("enabled"):
            await remember_ids_state(True, None)   # also comes back after a computer restart
        logger.info("IDS turned on at start-up" + (" (it was on before)" if state.get("enabled") else ""))
        await notify_desktop(ON_TITLE, ON_MESSAGE)
        return True

    await notify_desktop(FAILED_TITLE, "SecureNet could not reach its database to start monitoring. "
                                       "Open SecureNet and turn the IDS on.")
    return False
