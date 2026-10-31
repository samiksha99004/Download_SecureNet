"""
SecureNet Backend — Time helpers

The database stores naive UTC timestamps (TIMESTAMP WITHOUT TIME ZONE).
Everything that touches the DB must therefore use naive UTC datetimes, and
everything sent to the browser must carry an explicit "Z" so JavaScript does
not misread it as local time.
"""

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    """Current time as a naive UTC datetime (DB-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_naive_utc(value: datetime) -> datetime:
    """Convert any datetime to naive UTC (aware values are converted first)."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 string (with or without 'Z'/offset) into naive UTC.

    Raises ValueError for malformed input; returns None for empty input.
    """
    if not value:
        return None
    return to_naive_utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))


def to_iso_z(value: datetime) -> str:
    """Serialize a datetime as ISO-8601 UTC with a trailing 'Z'."""
    return to_naive_utc(value).isoformat(timespec="milliseconds") + "Z"
