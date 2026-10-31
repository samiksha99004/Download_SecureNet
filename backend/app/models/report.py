"""
SecureNet Backend — Report Model
"""

from app.utils.timeutil import utcnow
from sqlalchemy import Column, String, DateTime, Integer, Enum as SQLEnum, ForeignKey, Text, JSON
from sqlalchemy import Uuid as UUID
import uuid
import enum

from app.db.base import Base


class ReportStatus(str, enum.Enum):
    """Report generation status"""
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class ReportFormat(str, enum.Enum):
    """Report output format"""
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"


class Report(Base):
    """Generated security report"""
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Date range
    date_range_start = Column(DateTime, nullable=False, index=True)
    date_range_end = Column(DateTime, nullable=False, index=True)
    
    # Generation metadata
    generated_at = Column(DateTime, nullable=False, default=utcnow)
    status = Column(SQLEnum(ReportStatus), nullable=False, default=ReportStatus.PENDING, index=True)
    format = Column(SQLEnum(ReportFormat), nullable=False)
    size_bytes = Column(Integer, nullable=True)
    download_url = Column(String(512), nullable=True)
    
    # Filters applied to report
    filters = Column(JSON, nullable=False)  # Use JSON instead of JSONB for SQLite compatibility
    
    # Creator
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Report {self.name} ({self.status})>"
