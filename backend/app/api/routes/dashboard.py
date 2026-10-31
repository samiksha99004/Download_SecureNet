"""
SecureNet Backend — Dashboard Routes

KPIs, protocol distribution, top sources and host status.
Stored incident history is always shown (whether or not the IDS is running);
live-only figures (active flows) come from the running IDS.
"""

import platform
import time
from datetime import timedelta
from typing import List

import psutil
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.api.routes.events import convert_event_to_response
from app.core.config import settings
from app.db.base import AsyncSessionLocal
from app.ml.ids_service import get_ids_service
from app.models.security_event import ActionTaken, EventState, Protocol, SecurityEvent, SeverityLevel
from app.models.user import User
from app.services.cache import cached
from app.schemas.security import (
    AttackTypeCount,
    DashboardSummary,
    HostStatus,
    ProtocolDistribution,
    SeverityBreakdown,
    TopSource,
)
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

# Network throughput is derived from two psutil samples.
_net_sample: dict = {"time": None, "bytes": None}


async def _load_summary() -> DashboardSummary:
    """Three queries (all counts in one); own session so it can also run in the background."""
    one_hour_ago = utcnow() - timedelta(hours=1)
    recent_hour = SecurityEvent.timestamp >= one_hour_ago
    active = SecurityEvent.state == EventState.ACTIVE
    async with AsyncSessionLocal() as db:
        row = (await db.execute(
            select(
                func.count().filter(recent_hour),
                func.count().filter(SecurityEvent.severity == SeverityLevel.HIGH, active),
                func.count().filter(SecurityEvent.action_taken == ActionTaken.BLOCKED),
                func.avg(SecurityEvent.anomaly_score).filter(recent_hour),
                func.count().filter(SecurityEvent.severity == SeverityLevel.LOW, active),
                func.count().filter(SecurityEvent.severity == SeverityLevel.MEDIUM, active),
            ).select_from(SecurityEvent)
        )).one()
        attack_rows = (await db.execute(
            select(SecurityEvent.attack_type, func.count())
            .where(SecurityEvent.attack_type.isnot(None))
            .group_by(SecurityEvent.attack_type)
            .order_by(desc(func.count()))
            .limit(10)
        )).all()
        recent = (await db.execute(
            select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(10)
        )).scalars().all()
    return DashboardSummary(
        active_flows=0,
        anomalies_last_hour=row[0] or 0,
        high_severity_count=row[1] or 0,
        blocked_count=row[2] or 0,
        average_anomaly_score=round(float(row[3] or 0), 4),
        severity_breakdown=SeverityBreakdown(low=row[4] or 0, medium=row[5] or 0, high=row[1] or 0),
        attack_type_distribution=[AttackTypeCount(attack_type=r[0], count=r[1]) for r in attack_rows],
        recent_events=[convert_event_to_response(e) for e in recent],
    )


async def cached_summary() -> DashboardSummary:
    # "last hour" moves with the clock: refreshed in the background every 30 s
    return await cached("events:dashboard-summary", _load_summary, ttl=30)


async def _load_protocols() -> ProtocolDistribution:
    async with AsyncSessionLocal() as db:
        rows = await db.execute(select(SecurityEvent.protocol, func.count()).group_by(SecurityEvent.protocol))
        counts = {row[0]: row[1] for row in rows}
    tcp, udp = counts.get(Protocol.TCP, 0), counts.get(Protocol.UDP, 0)
    icmp, other = counts.get(Protocol.ICMP, 0), counts.get(Protocol.OTHER, 0)
    return ProtocolDistribution(tcp=tcp, udp=udp, icmp=icmp, other=other, total_flows=tcp + udp + icmp + other)


async def cached_protocols() -> ProtocolDistribution:
    return await cached("events:protocols", _load_protocols, ttl=300)


async def _load_top_sources(limit: int) -> List[TopSource]:
    from sqlalchemy import case

    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(
                SecurityEvent.source_ip,
                func.count().label("event_count"),
                func.sum(case((SecurityEvent.state == EventState.ACTIVE, 1), else_=0)),
                func.sum(case((SecurityEvent.severity == SeverityLevel.HIGH, 1), else_=0)),
                func.max(SecurityEvent.timestamp),
            )
            .group_by(SecurityEvent.source_ip)
            .order_by(desc("event_count"))
            .limit(limit)
        )).all()
    return [
        TopSource(
            source_ip=row[0],
            flow_count=row[1],
            anomaly_count=row[2] or 0,
            high_severity_count=row[3] or 0,
            last_seen=row[4],
        )
        for row in rows
    ]


async def cached_top_sources(limit: int = 5) -> List[TopSource]:
    return await cached(f"events:top-sources:{limit}", lambda: _load_top_sources(limit), ttl=300)


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(current_user: User = Depends(get_current_user)):
    """KPIs and recent events.

    * activeFlows          – flows currently being tracked by the live IDS
    * anomaliesLastHour    – events stored in the last hour
    * highSeverityCount    – unresolved (active) high-severity events
    * blockedCount         – events whose source IP was blocked
    * averageAnomalyScore  – mean score of events in the last hour

    Served from memory; reloaded when events change (see services/cache.py).
    """
    summary = await cached_summary()
    return summary.model_copy(update={"active_flows": get_ids_service().get_status()["active_flows"]})


@router.get("/host-status", response_model=HostStatus)
async def get_host_status(current_user: User = Depends(get_current_user)):
    """Current host resource usage (non-blocking psutil calls)."""
    try:
        now = time.monotonic()
        net = psutil.net_io_counters()
        total_bytes = net.bytes_sent + net.bytes_recv
        rate = None
        if _net_sample["time"] is not None and now > _net_sample["time"]:
            rate = max(0.0, (total_bytes - _net_sample["bytes"]) / (now - _net_sample["time"]))
        _net_sample.update(time=now, bytes=total_bytes)

        return HostStatus(
            hostname=platform.node(),
            os=f"{platform.system()} {platform.release()}",
            cpu_percent=round(psutil.cpu_percent(interval=None), 2),
            memory_percent=round(psutil.virtual_memory().percent, 2),
            network_interface=settings.CAPTURE_INTERFACE or "default",
            network_bytes_per_sec=round(rate, 1) if rate is not None else None,
            uptime=int(time.time() - psutil.boot_time()),
            last_updated=utcnow(),
        )
    except Exception:
        return HostStatus()


@router.get("/protocol-distribution", response_model=ProtocolDistribution)
async def get_protocol_distribution(current_user: User = Depends(get_current_user)):
    """Protocol distribution of stored security events (served from memory)."""
    return await cached_protocols()


@router.get("/top-sources", response_model=List[TopSource])
async def get_top_sources(
    limit: int = Query(5, ge=1, le=50),
    current_user: User = Depends(get_current_user),
):
    """Source IPs with the most security events (served from memory)."""
    return await cached_top_sources(limit)
