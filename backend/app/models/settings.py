"""
SecureNet Backend — Settings Models
"""

from app.utils.timeutil import utcnow
from sqlalchemy import Column, String, DateTime, Boolean, Float, Integer, Enum as SQLEnum, ForeignKey, Text, JSON
from sqlalchemy import Uuid as UUID
import uuid
import enum

from app.db.base import Base


class DetectionSensitivity(str, enum.Enum):
    """Detection sensitivity presets"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CUSTOM = "custom"


class ProtectionMode(str, enum.Enum):
    """Protection operating mode"""
    MONITOR = "monitor"
    PROTECT = "protect"


class WhitelistEntryType(str, enum.Enum):
    """Whitelist entry types"""
    IP = "ip"
    CIDR = "cidr"
    PORT = "port"
    PROTOCOL = "protocol"


class DetectionSettings(Base):
    """Detection configuration - single row table"""
    __tablename__ = "detection_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    enabled = Column(Boolean, nullable=False, default=True)
    sensitivity = Column(SQLEnum(DetectionSensitivity), nullable=False, default=DetectionSensitivity.MEDIUM)
    anomaly_threshold = Column(Float, nullable=False, default=0.5)
    min_flows_for_analysis = Column(Integer, nullable=False, default=10)
    analysis_interval_ms = Column(Integer, nullable=False, default=5000)
    stage2_enabled = Column(Boolean, nullable=False, default=True)
    stage2_confidence_threshold = Column(Float, nullable=False, default=0.7)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


class ProtectionSettings(Base):
    """Protection configuration - single row table"""
    __tablename__ = "protection_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mode = Column(SQLEnum(ProtectionMode), nullable=False, default=ProtectionMode.MONITOR)
    auto_block = Column(Boolean, nullable=False, default=False)
    auto_block_severities = Column(JSON, nullable=False, default=lambda: ["high"])  # Use JSON instead of ARRAY for SQLite
    block_duration_seconds = Column(Integer, nullable=False, default=3600)
    max_blocked_ips = Column(Integer, nullable=False, default=1000)
    notify_on_block = Column(Boolean, nullable=False, default=True)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


class NotificationSettings(Base):
    """Notification configuration - single row table"""
    __tablename__ = "notification_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_enabled = Column(Boolean, nullable=False, default=True)
    email_address = Column(String(255), nullable=True)
    alert_on_high = Column(Boolean, nullable=False, default=True)
    alert_on_medium = Column(Boolean, nullable=False, default=True)
    alert_on_low = Column(Boolean, nullable=False, default=True)
    alert_on_block = Column(Boolean, nullable=False, default=True)
    digest_enabled = Column(Boolean, nullable=False, default=False)
    digest_interval_hours = Column(Integer, nullable=False, default=24)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


class SystemSettings(Base):
    """System configuration - single row table"""
    __tablename__ = "system_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    log_retention_days = Column(Integer, nullable=False, default=90)
    max_stored_events = Column(Integer, nullable=False, default=100000)
    timezone = Column(String(50), nullable=False, default="UTC")
    date_format = Column(String(50), nullable=False, default="YYYY-MM-DD HH:mm:ss")
    debug_mode = Column(Boolean, nullable=False, default=False)
    # "Contact us" details shown on the Support page (set by the admin)
    contact_website = Column(String(255), nullable=True)
    contact_phone = Column(String(40), nullable=True)
    contact_email = Column(String(255), nullable=True)
    contact_address = Column(String(500), nullable=True)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


class WhitelistEntry(Base):
    """IP/CIDR/Port whitelist entries"""
    __tablename__ = "whitelist_entries"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(SQLEnum(WhitelistEntryType), nullable=False, index=True)
    value = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    def __repr__(self):
        return f"<WhitelistEntry {self.type}:{self.value}>"
