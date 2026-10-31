"""
SecureNet backend package.

Windows guard: Python 3.12+ asks WMI (the Windows Management service) for basic system facts in
the `platform` module, which numpy, xgboost, scapy and pip all use. When WMI is stuck — it happens
(seen on this PC on 2026-10-11) — every one of those imports freezes and SecureNet never starts.
`platform` already has a fallback (registry / `ver`) for when WMI fails, so we make the WMI query
fail at once and Python uses that fallback. Nothing else changes.
"""

import platform as _platform
import sys as _sys

__version__ = "1.0.0"

if _sys.platform == "win32" and hasattr(_platform, "_wmi_query"):
    def _skip_wmi(*_args, **_kwargs):
        raise OSError("SecureNet does not use WMI (it can hang)")

    _platform._wmi_query = _skip_wmi
