"""
SecureNet Backend — Reports Routes

Daily reports: one per local day that had attacks, built on the fly from the
stored security events and downloaded as .txt / .csv / .pdf. (The old
"generate / list / delete saved report files" endpoints were removed — they
wrote files to the server's disk and the dashboard no longer used them.)
"""

import asyncio
from collections import defaultdict
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.db.base import AsyncSessionLocal, get_db
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.report import DailyReport
from app.services import exporters, incident_report
from app.services.cache import cached

router = APIRouter(prefix="/reports", tags=["Reports"])

MAX_REPORT_EVENTS = 50_000


# ── Daily reports: one per local day that had attacks (built on the fly) ──────

TZ_OFFSET = Query(0, alias="tzOffset", ge=-840, le=840,
                  description="Minutes east of UTC of the viewer's time zone (India = 330)")
DAILY_FORMATS = {"txt": "text/plain; charset=utf-8", "pdf": "application/pdf"}


@router.get("/daily", response_model=list[DailyReport])
async def list_daily_reports(
    tz_offset: int = TZ_OFFSET,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Days with detected attacks, newest first (empty when nothing has happened; cached until events change)."""
    return await cached(f"events:daily:{tz_offset}", lambda: _daily_reports(tz_offset), ttl=300)


async def cached_daily_local() -> list[DailyReport]:
    """The daily reports in this computer's time zone (what its browser asks for), prepared ahead."""
    offset = incident_report.server_offset_minutes()
    return await cached(f"events:daily:{offset}", lambda: _daily_reports(offset), ttl=300)


async def _daily_reports(tz_offset: int) -> list[DailyReport]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(SecurityEvent.timestamp, SecurityEvent.severity, SecurityEvent.attack_type, SecurityEvent.source_ip,
                   SecurityEvent.attack_guesses)
            .order_by(SecurityEvent.timestamp)
        )).all()
    days: dict[date, list] = defaultdict(list)
    for row in rows:
        days[incident_report.to_local(row.timestamp, tz_offset).date()].append(row)

    reports = []
    for day, items in sorted(days.items(), reverse=True):
        severities = [r.severity.value for r in items]
        attacks = [incident_report._guess_name(r) for r in items]   # the model's best guess
        reports.append(DailyReport(
            date=day.isoformat(),
            total=len(items),
            high=severities.count("high"),
            medium=severities.count("medium"),
            low=severities.count("low"),
            top_attack=max(set(attacks), key=attacks.count),
            sources=len({r.source_ip for r in items}),
            first_seen=items[0].timestamp,
            last_seen=items[-1].timestamp,
        ))
    return reports


@router.get("/daily/{day}/download")
async def download_daily_report(
    day: date,
    format: str = Query("txt", pattern="^(txt|pdf)$"),
    tz_offset: int = TZ_OFFSET,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """That day's report (local time) as .txt or .pdf."""
    start, end = incident_report.local_day_bounds_utc(day, tz_offset)
    events = (await db.execute(
        select(SecurityEvent).where(SecurityEvent.timestamp >= start, SecurityEvent.timestamp < end)
        .order_by(SecurityEvent.timestamp).limit(MAX_REPORT_EVENTS)
    )).scalars().all()
    if not events:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No attacks were detected on this day.")

    label = day.strftime("%d %b %Y")
    title = f"Daily report - {label}"
    if format == "txt":
        text = await asyncio.to_thread(incident_report.render_text, events, title, tz_offset,
                                       f"{label} 00:00 - 23:59")
        content = text.encode("utf-8")
    else:
        content = await asyncio.to_thread(exporters.to_pdf, events, title,
                                          f"{label} · {len(events)} alert(s) · times in UTC")
    filename = incident_report.report_filename("daily-report", day.isoformat(), format)
    return Response(content=content, media_type=DAILY_FORMATS[format],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
