"""
SecureNet Backend — Report Schemas
"""

from typing import Optional

from app.schemas.base import CamelModel, UtcDatetime


class DailyReport(CamelModel):
    """One day (local time) that had detected attacks — shown as a box on the Reports page."""
    date: str                    # YYYY-MM-DD, local calendar day
    total: int
    high: int
    medium: int
    low: int
    top_attack: Optional[str] = None
    sources: int
    first_seen: UtcDatetime
    last_seen: UtcDatetime
