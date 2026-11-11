"""
SecureNet Backend — Reports Routes

6-hour-window reports: the day is split into four local windows (12am-6am,
6am-12pm, 12pm-6pm, 6pm-12am). A window gets ONE report, built on the fly from
the stored security events, ONLY if:
  * at least one attack happened in it, AND
  * the window has already ended (no report for the window in progress).
Each report lists every attack with its date/time. Downloaded as .txt / .pdf.
"""

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.db.base import AsyncSessionLocal, get_db
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.report import ReportWindow
from app.services import exporters, incident_report
from app.services.cache import cached
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/reports", tags=["Reports"])

MAX_REPORT_EVENTS = 50_000
WINDOW_HOURS = 6

TZ_OFFSET = Query(0, alias="tzOffset", ge=-840, le=840,
                  description="Minutes east of UTC of the viewer's time zone (India = 330)")
REPORT_FORMATS = {"txt": "text/plain; charset=utf-8", "pdf": "application/pdf"}

# Label for each 6-hour window of the local day (slot = local hour // 6).
_RANGE_LABELS = {
    0: "12:00 am - 6:00 am",
    1: "6:00 am - 12:00 pm",
    2: "12:00 pm - 6:00 pm",
    3: "6:00 pm - 12:00 am",
}


def _window_start_local(local_dt: datetime) -> datetime:
    """Start of the 6-hour window (local time) that `local_dt` falls in."""
    slot = local_dt.hour // WINDOW_HOURS
    return local_dt.replace(hour=slot * WINDOW_HOURS, minute=0, second=0, microsecond=0)


@router.get("/windows", response_model=list[ReportWindow])
async def list_window_reports(
    tz_offset: int = TZ_OFFSET,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Finished 6-hour windows that had attacks, newest first. A window in progress is not listed
    (its report is made only once the 6 hours are over); windows with no attack are skipped."""
    owner_id = current_user.id
    return await cached(f"events:windows:{owner_id}:{tz_offset}",
                        lambda: _window_reports(owner_id, tz_offset), ttl=120)


async def _window_reports(owner_id, tz_offset: int) -> list[ReportWindow]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(SecurityEvent.timestamp, SecurityEvent.severity, SecurityEvent.attack_type,
                   SecurityEvent.source_ip, SecurityEvent.attack_guesses)
            .where(SecurityEvent.owner_id == owner_id)
            .order_by(SecurityEvent.timestamp)
        )).all()
    now_local = incident_report.to_local(utcnow(), tz_offset)
    windows: dict[datetime, list] = defaultdict(list)
    for row in rows:
        windows[_window_start_local(incident_report.to_local(row.timestamp, tz_offset))].append(row)

    reports = []
    for start, items in sorted(windows.items(), reverse=True):
        if start + timedelta(hours=WINDOW_HOURS) > now_local:
            continue   # window not finished yet -> no report until the 6 hours are over
        slot = start.hour // WINDOW_HOURS
        severities = [r.severity.value for r in items]
        attacks = [incident_report._guess_name(r) for r in items]
        reports.append(ReportWindow(
            key=start.strftime("%Y-%m-%dT%H"),
            date=start.date().isoformat(),
            range_label=_RANGE_LABELS[slot],
            total=len(items),
            high=severities.count("high"),
            medium=severities.count("medium"),
            low=severities.count("low"),
            top_attack=incident_report.pretty_label(max(set(attacks), key=attacks.count)),
            sources=len({r.source_ip for r in items}),
            first_seen=items[0].timestamp,
            last_seen=items[-1].timestamp,
        ))
    return reports


@router.get("/windows/{key}/download")
async def download_window_report(
    key: str,
    format: str = Query("txt", pattern="^(txt|pdf)$"),
    tz_offset: int = TZ_OFFSET,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """That 6-hour window's report (local time) as .txt or .pdf."""
    try:
        start_local = datetime.strptime(key, "%Y-%m-%dT%H")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report id")
    start_utc = start_local - timedelta(minutes=tz_offset)
    end_utc = start_utc + timedelta(hours=WINDOW_HOURS)
    events = (await db.execute(
        select(SecurityEvent).where(SecurityEvent.timestamp >= start_utc, SecurityEvent.timestamp < end_utc,
                                    SecurityEvent.owner_id == current_user.id)
        .order_by(SecurityEvent.timestamp).limit(MAX_REPORT_EVENTS)
    )).scalars().all()
    if not events:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No attacks were detected in this window.")

    slot = start_local.hour // WINDOW_HOURS
    day_label = start_local.strftime("%d %b %Y")
    range_label = _RANGE_LABELS[slot]
    title = f"Report - {day_label}, {range_label}"
    period = f"{day_label}, {range_label}"
    if format == "txt":
        text = await asyncio.to_thread(incident_report.render_text, events, title, tz_offset, period)
        content = text.encode("utf-8")
    else:
        content = await asyncio.to_thread(exporters.to_pdf, events, title,
                                          f"{period} · {len(events)} attack(s)")
    filename = incident_report.report_filename("report", key.replace(":", ""), format)
    return Response(content=content, media_type=REPORT_FORMATS[format],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
