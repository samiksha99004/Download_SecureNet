"""
SecureNet Backend — Security Event Models
"""

from app.utils.timeutil import utcnow
from sqlalchemy import Column, String, DateTime, Float, Integer, Enum as SQLEnum, ForeignKey, Text, JSON
from sqlalchemy import Uuid as UUID
from sqlalchemy.orm import relationship
import uuid
import enum

from app.db.base import Base


class SeverityLevel(str, enum.Enum):
    """Event severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EventState(str, enum.Enum):
    """Security event lifecycle states"""
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class DetectionMode(str, enum.Enum):
    """Detection system operating mode"""
    MONITOR = "monitor"
    PROTECT = "protect"


class ActionTaken(str, enum.Enum):
    """Actions taken in response to an event"""
    LOGGED = "logged"
    ALERTED = "alerted"
    BLOCKED = "blocked"
    TERMINATED = "terminated"
    NONE = "none"


class Protocol(str, enum.Enum):
    """Network protocols"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "other"


class SecurityEvent(Base):
    """
    Security event detected by the IDS pipeline.
    Represents a single network flow that was flagged as anomalous.
    """
    __tablename__ = "security_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, nullable=False, default=utcnow, index=True)
    
    # Network information
    source_ip = Column(String(45), nullable=False, index=True)  # IPv4/IPv6
    source_port = Column(Integer, nullable=False)
    destination_ip = Column(String(45), nullable=False, index=True)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(SQLEnum(Protocol), nullable=False, index=True)
    
    # Detection results
    anomaly_score = Column(Float, nullable=False, index=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    attack_type = Column(String(100), nullable=True, index=True)  # null if normal
    confidence = Column(Float, nullable=True)  # Stage 2 classification confidence
    
    # Response
    mode = Column(SQLEnum(DetectionMode), nullable=False, index=True)
    state = Column(SQLEnum(EventState), nullable=False, default=EventState.ACTIVE, index=True)
    action_taken = Column(SQLEnum(ActionTaken), nullable=False, default=ActionTaken.LOGGED)
    
    # Additional context
    detection_reason = Column(Text, nullable=True)
    contributing_features = Column(JSON, nullable=True)  # Use JSON instead of JSONB for SQLite compatibility
    # the model's guesses of which attack it might be: [{"label", "probability"}], best first
    attack_guesses = Column(JSON, nullable=True)
    
    # Flow statistics (optional)
    flow_duration_ms = Column(Integer, nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    bytes_received = Column(Integer, nullable=True)
    packets_sent = Column(Integer, nullable=True)
    packets_received = Column(Integer, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    def __repr__(self):
        return f"<SecurityEvent {self.id} {self.source_ip} -> {self.destination_ip}>"


class EventFeature(Base):
    """
    Stores the full 78-feature vector for a security event.
    Separated from SecurityEvent for performance and normalization.
    """
    __tablename__ = "event_features"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    feature_vector = Column(JSON, nullable=False)  # Use JSON instead of JSONB for SQLite compatibility
    created_at = Column(DateTime, nullable=False, default=utcnow)
    
    def __repr__(self):
        return f"<EventFeature for {self.event_id}>"
