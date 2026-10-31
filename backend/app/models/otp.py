"""
SecureNet Backend — OTP Model
"""

from datetime import timedelta
from app.utils.timeutil import utcnow
from sqlalchemy import Column, String, DateTime, Integer, Boolean
from sqlalchemy import Uuid as UUID
import uuid

from app.db.base import Base
from app.core.config import settings


class OTP(Base):
    """One-Time Password for email verification"""
    __tablename__ = "otps"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, index=True)
    otp_code = Column(String(10), nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    is_used = Column(Boolean, nullable=False, default=False)
    
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.expires_at:
            self.expires_at = utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    
    def is_expired(self) -> bool:
        """Check if OTP has expired"""
        return utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if OTP is valid for use"""
        return (
            not self.is_used
            and not self.is_expired()
            and self.attempts < settings.OTP_MAX_ATTEMPTS
        )
    
    def __repr__(self):
        return f"<OTP {self.email}>"
