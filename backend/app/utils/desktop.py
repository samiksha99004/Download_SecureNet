"""
SecureNet Backend — Desktop (Windows) notifications

A Windows toast shown by the backend itself, so it works even when no browser
is open (e.g. right after the computer starts). Nothing is installed: the
"SecureNet" app id is registered under HKCU and PowerShell shows the toast
through the built-in Windows notification API. Never emailed, never raises.
"""

import asyncio
import html
import os
import subprocess
import sys
from pathlib import Path

from app.core.config import settings
from app.utils.logger import logger

APP_ID = "SecureNet.IDS"
# Clicking a toast activates this custom URL protocol, which opens SecureNet.
LAUNCH_PROTOCOL = "securenet"
LAUNCH_ARG = "securenet:open"
_CREATE_NO_WINDOW = 0x08000000

_TOAST_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($env:SN_TOAST_XML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:SN_TOAST_APP).Show(
    [Windows.UI.Notifications.ToastNotification]::new($xml))
"""


def _register_app_id() -> None:
    """Let Windows show toasts as "SecureNet" (per-user registry key, no admin needed)."""
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\AppUserModelId\{APP_ID}") as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, settings.APP_NAME)


def _register_launch_protocol() -> None:
    """Register the `securenet:` URL protocol so CLICKING a toast opens the app.

    The toast carries `activationType="protocol" launch="securenet:open"`. When the user clicks
    it, Windows runs the handler below (per-user, no admin). The handler is a tiny .vbs that opens
    the SecureNet desktop app via its shortcut if present, otherwise the dashboard the backend
    already serves (works even when the window is closed / headless)."""
    import winreg

    here = Path(__file__).resolve()
    project_root = here.parents[4] if len(here.parents) > 4 else here.parent  # ...\Intrusion_Detection-System
    backend_dir = here.parents[2]
    port = getattr(settings, "PORT", 8000) or 8000
    url = f"http://localhost:{port}/"
    shortcut = project_root / "SecureNet IDS.lnk"

    data_dir = backend_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    opener = data_dir / "securenet_open.vbs"
    # Launch the app window if the shortcut exists; otherwise open the dashboard URL.
    vbs = (
        'Set sh = CreateObject("WScript.Shell")\r\n'
        'Set fso = CreateObject("Scripting.FileSystemObject")\r\n'
        f'lnk = "{shortcut}"\r\n'
        'If fso.FileExists(lnk) Then\r\n'
        '  sh.Run """" & lnk & """", 1, False\r\n'
        'Else\r\n'
        f'  sh.Run "{url}", 1, False\r\n'
        'End If\r\n'
    )
    try:
        if not opener.exists() or opener.read_text(encoding="utf-8") != vbs:
            opener.write_text(vbs, encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Could not write toast opener script: {exc}")
        return

    command = f'wscript.exe "{opener}" "%1"'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{LAUNCH_PROTOCOL}") as key:
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, "URL:SecureNet Protocol")
        winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          rf"Software\Classes\{LAUNCH_PROTOCOL}\shell\open\command") as key:
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, command)


def _show_sync(title: str, message: str) -> bool:
    _register_app_id()
    try:
        _register_launch_protocol()   # so clicking the toast opens the app (never fatal)
    except Exception as exc:
        logger.warning(f"Could not register toast click handler: {exc}")
    # activationType="protocol" + launch -> clicking the toast opens SecureNet via the securenet: handler
    xml = (f'<toast activationType="protocol" launch="{LAUNCH_ARG}">'
           '<visual><binding template="ToastGeneric">'
           f"<text>{html.escape(title)}</text><text>{html.escape(message)}</text>"
           '</binding></visual>'
           '<actions><action content="Open SecureNet" activationType="protocol" '
           f'arguments="{LAUNCH_ARG}"/></actions>'
           "</toast>")
    # Text goes through environment variables, never into the script itself
    env = {**os.environ, "SN_TOAST_XML": xml, "SN_TOAST_APP": APP_ID}
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _TOAST_SCRIPT],
        capture_output=True, text=True, timeout=30, env=env, creationflags=_CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        logger.warning(f"Desktop notification failed: {result.stderr.strip()[:300]}")
        return False
    return True


async def notify_desktop(title: str, message: str) -> bool:
    """Show a Windows desktop notification. Returns False (and logs) when it can't."""
    if not settings.DESKTOP_NOTIFICATIONS or sys.platform != "win32":
        return False
    try:
        shown = await asyncio.to_thread(_show_sync, title, message)
    except Exception as exc:  # a notice must never break the IDS
        logger.warning(f"Desktop notification failed: {exc}")
        return False
    if shown:
        logger.info(f"Desktop notification shown: {title} - {message}")
    return shown
