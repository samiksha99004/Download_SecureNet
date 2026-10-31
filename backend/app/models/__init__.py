"""
Database models for SecureNet
"""

from app.models.user import User, UserRole, AccountStatus, AuthProvider
from app.models.security_event import (
    SecurityEvent,
    EventFeature,
    SeverityLevel,
    EventState,
    DetectionMode,
    ActionTaken,
    Protocol
)
from app.models.settings import (
    DetectionSettings,
    ProtectionSettings,
    NotificationSettings,
    SystemSettings,
    WhitelistEntry,
    WhitelistEntryType,
    ProtectionMode,
    DetectionSensitivity
)
from app.models.otp import OTP
from app.models.report import Report, ReportStatus, ReportFormat
from app.models.support import SupportMessage

__all__ = [
    "SupportMessage",
    # User
    "User",
    "UserRole",
    "AccountStatus",
    "AuthProvider",
    # Security Events
    "SecurityEvent",
    "EventFeature",
    "SeverityLevel",
    "EventState",
    "DetectionMode",
    "ActionTaken",
    "Protocol",
    # Settings
    "DetectionSettings",
    "ProtectionSettings",
    "NotificationSettings",
    "SystemSettings",
    "WhitelistEntry",
    "WhitelistEntryType",
    "ProtectionMode",
    "DetectionSensitivity",
    # OTP
    "OTP",
    # Reports
    "Report",
    "ReportStatus",
    "ReportFormat",
]
