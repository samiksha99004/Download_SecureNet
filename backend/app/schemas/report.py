"""
SecureNet Backend — Report Schemas
"""

from typing import Optional

from app.schemas.base import CamelModel, UtcDatetime


class ReportWindow(CamelModel):
    """One 6-hour window (local time) that had detected attacks — a box on the Reports page.
    A window's report appears only AFTER the window has ended; windows with no attack are skipped."""
    key: str                     # window start "YYYY-MM-DDTHH" (local), the download id
    date: str                    # local date "YYYY-MM-DD"
    range_label: str             # e.g. "12:00 am - 6:00 am"
    total: int
    high: int
    medium: int
    low: int
    top_attack: Optional[str] = None
    sources: int
    first_seen: UtcDatetime
    last_seen: UtcDatetime
