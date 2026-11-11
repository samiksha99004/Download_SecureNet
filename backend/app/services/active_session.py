"""
SecureNet — single active session

Only ONE account may be signed in at a time. When someone signs in, a fresh random
session id becomes "current" and is embedded in their access/refresh tokens; every
request checks the token's session id against the current one. A new sign-in (or a
sign-out) changes the current id, so any previously issued token stops working at
once and that browser is signed out automatically.

The current id is kept in a small file next to the IDS state so it survives a backend
restart. Enforcement can be turned off (tests) via settings.SINGLE_SESSION_ENFORCED.
"""

from __future__ import annotations

import uuid
from typing import Optional

from app.core.config import settings
from app.utils.logger import logger


def _file():
    return settings.ids_state_file.with_name("active-session.txt")


def current_sid() -> Optional[str]:
    try:
        value = _file().read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def _write(sid: str) -> None:
    try:
        path = _file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sid, encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Could not persist active session: {exc}")


def start(user_id: str) -> str:
    """Begin a new single session for `user_id`; returns the session id to put in the tokens.
    Any token from a previous session immediately stops working."""
    sid = uuid.uuid4().hex
    _write(sid)
    logger.info(f"Active session started for user {user_id} (sid {sid[:8]}…)")
    return sid


def invalidate() -> None:
    """End the current session (sign-out): set a fresh id nobody holds, so every existing
    token is now invalid."""
    _write(uuid.uuid4().hex)


def is_valid(sid: Optional[str]) -> bool:
    """Is this token's session id the current one? When enforcement is off (tests) everything
    passes. When no session has been recorded yet, accept (don't lock out a fresh backend)."""
    if not getattr(settings, "SINGLE_SESSION_ENFORCED", True):
        return True
    current = current_sid()
    if current is None:
        return True
    return bool(sid) and sid == current
