"""
Shared filtering / sorting for security-event queries (history, export, reports).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import and_, or_

from app.models.security_event import DetectionMode, EventState, Protocol, SecurityEvent, SeverityLevel
from app.utils.timeutil import parse_iso_utc

# Frontend (camelCase) sort keys → columns. Anything else is rejected.
SORT_COLUMNS = {
    "timestamp": SecurityEvent.timestamp,
    "sourceIp": SecurityEvent.source_ip,
    "destinationIp": SecurityEvent.destination_ip,
    "anomalyScore": SecurityEvent.anomaly_score,
    "severity": SecurityEvent.severity,
    "attackType": SecurityEvent.attack_type,
    "mode": SecurityEvent.mode,
    "state": SecurityEvent.state,
    "actionTaken": SecurityEvent.action_taken,
    "protocol": SecurityEvent.protocol,
}


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_date(value: Optional[str], name: str) -> Optional[datetime]:
    try:
        return parse_iso_utc(value)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid '{name}' date — use ISO 8601 (e.g. 2026-09-24T00:00:00Z)")


def _enum(enum_cls, value: Optional[str], name: str):
    if not value:
        return None
    try:
        return enum_cls(value)
    except ValueError:
        allowed = ", ".join(e.value for e in enum_cls)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid {name} '{value}'. Allowed: {allowed}")


@dataclass
class EventFilters:
    search: Optional[str] = None
    severity: Optional[str] = None
    state: Optional[str] = None
    mode: Optional[str] = None
    attack_type: Optional[str] = None
    protocol: Optional[str] = None
    from_date: Optional[str] = None
    to_date: Optional[str] = None

    def conditions(self) -> List:
        conds = []
        if self.search:
            pattern = f"%{_escape_like(self.search.strip())}%"
            conds.append(or_(
                SecurityEvent.source_ip.ilike(pattern, escape="\\"),
                SecurityEvent.destination_ip.ilike(pattern, escape="\\"),
                SecurityEvent.attack_type.ilike(pattern, escape="\\"),
            ))
        if (sev := _enum(SeverityLevel, self.severity, "severity")) is not None:
            conds.append(SecurityEvent.severity == sev)
        if (st := _enum(EventState, self.state, "state")) is not None:
            conds.append(SecurityEvent.state == st)
        if (md := _enum(DetectionMode, self.mode, "mode")) is not None:
            conds.append(SecurityEvent.mode == md)
        if (pr := _enum(Protocol, self.protocol, "protocol")) is not None:
            conds.append(SecurityEvent.protocol == pr)
        if self.attack_type:
            if self.attack_type.lower() in ("normal", "none", "unknown"):
                conds.append(SecurityEvent.attack_type.is_(None))
            else:
                conds.append(SecurityEvent.attack_type == self.attack_type)
        if (start := _parse_date(self.from_date, "from")) is not None:
            conds.append(SecurityEvent.timestamp >= start)
        if (end := _parse_date(self.to_date, "to")) is not None:
            conds.append(SecurityEvent.timestamp <= end)
        return conds


def sort_clause(sort_by: str, sort_order: str):
    column = SORT_COLUMNS.get(sort_by)
    if column is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Cannot sort by '{sort_by}'. Allowed: {', '.join(SORT_COLUMNS)}")
    return column.desc() if sort_order == "desc" else column.asc()


def combine(conditions: Iterable):
    conditions = list(conditions)
    return and_(*conditions) if conditions else None
