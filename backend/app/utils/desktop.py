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

from app.core.config import settings
from app.utils.logger import logger

APP_ID = "SecureNet.IDS"
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


def _show_sync(title: str, message: str) -> bool:
    _register_app_id()
    xml = ('<toast><visual><binding template="ToastGeneric">'
           f"<text>{html.escape(title)}</text><text>{html.escape(message)}</text>"
           "</binding></visual></toast>")
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
