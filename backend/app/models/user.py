"""
SecureNet Backend — User Model
"""

from app.utils.timeutil import utcnow
from sqlalchemy import Boolean, true, Column, String, DateTime, Enum as SQLEnum
from sqlalchemy import Uuid as UUID
from sqlalchemy.types import TypeDecorator
import uuid
import enum

from app.db.base import Base


class IntStoredAsString(TypeDecorator):
    """Integer value kept in the legacy VARCHAR column.

    `users.failed_login_attempts` was created as VARCHAR by the initial
    migration. This keeps the Python side an int without needing a schema
    migration on existing databases.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else str(int(value))

    def process_result_value(self, value, dialect):
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0


class AuthProvider(str, enum.Enum):
    """Authentication provider types"""
    LOCAL = "local"
    GOOGLE = "google"


class AccountStatus(str, enum.Enum):
    """User account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class UserRole(str, enum.Enum):
    """User roles for authorization"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base):
    """User account model"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=True)  # NULL until set after OTP verification
    phone_number = Column(String(20), nullable=True)    # E.164-style digits, optional "+"
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.VIEWER)
    account_status = Column(SQLEnum(AccountStatus), nullable=False, default=AccountStatus.PENDING_VERIFICATION)
    auth_provider = Column(SQLEnum(AuthProvider), nullable=False, default=AuthProvider.LOCAL)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    last_login_at = Column(DateTime, nullable=True)
    
    # Optional profile fields
    avatar_url = Column(String(512), nullable=True)

    # Attack alert emails for this user (codes are always emailed)
    email_alerts = Column(Boolean, nullable=False, default=True, server_default=true())
    
    # Security
    failed_login_attempts = Column(IntStoredAsString, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<User {self.email}>"
