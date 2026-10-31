"""
SecureNet Backend — Security Event Schemas
"""

from typing import Optional, List, Union

from pydantic import field_validator

from app.models.security_event import SeverityLevel, EventState, DetectionMode, ActionTaken, Protocol
from app.schemas.base import CamelModel, IdStr, UtcDatetime


# ── Contributing Feature ──────────────────────────────────────────────────────

class ContributingFeature(CamelModel):
    """Feature that contributed to the detection decision"""
    name: str
    value: Union[float, str]
    contribution: float


class AttackGuess(CamelModel):
    """One of the model's guesses of which attack the abnormal traffic might be"""
    label: str
    probability: float


# ── Security Event ────────────────────────────────────────────────────────────

class SecurityEventResponse(CamelModel):
    """Security event data returned to frontend"""
    id: IdStr
    timestamp: UtcDatetime
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: Protocol
    anomaly_score: float
    severity: SeverityLevel
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
    mode: DetectionMode
    state: EventState
    action_taken: ActionTaken
    detection_reason: Optional[str] = None
    contributing_features: List[ContributingFeature] = []
    attack_guesses: List[AttackGuess] = []
    flow_duration_ms: Optional[int] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    packets_sent: Optional[int] = None
    packets_received: Optional[int] = None

    @field_validator("contributing_features", mode="before")
    @classmethod
    def _none_to_list(cls, value):
        return value or []

    @field_validator("attack_guesses", mode="before")
    @classmethod
    def _clean_guesses(cls, value):
        from app.services.verdict import clean_guesses
        return clean_guesses(value)


# ── Dashboard Summary ─────────────────────────────────────────────────────────

class AttackTypeCount(CamelModel):
    """Attack type distribution entry"""
    attack_type: str
    count: int


class SeverityBreakdown(CamelModel):
    """Event count by severity"""
    low: int = 0
    medium: int = 0
    high: int = 0


class DashboardSummary(CamelModel):
    """Dashboard KPI data"""
    active_flows: int
    anomalies_last_hour: int
    high_severity_count: int
    blocked_count: int
    average_anomaly_score: float
    severity_breakdown: SeverityBreakdown
    attack_type_distribution: List[AttackTypeCount]
    recent_events: List[SecurityEventResponse]


# ── Host Status ───────────────────────────────────────────────────────────────

class HostStatus(CamelModel):
    """System resource status"""
    hostname: Optional[str] = None
    os: Optional[str] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    network_interface: Optional[str] = None
    network_bytes_per_sec: Optional[float] = None
    uptime: Optional[int] = None  # seconds
    last_updated: Optional[UtcDatetime] = None


# ── Protocol Distribution ─────────────────────────────────────────────────────

class ProtocolDistribution(CamelModel):
    """Network protocol statistics (from stored security events)"""
    tcp: int
    udp: int
    icmp: int
    other: int
    total_flows: int


# ── Top Sources ───────────────────────────────────────────────────────────────

class TopSource(CamelModel):
    """Top event source statistics"""
    source_ip: str
    flow_count: int
    anomaly_count: int
    high_severity_count: int
    last_seen: UtcDatetime
