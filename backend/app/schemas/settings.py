"""
SecureNet Backend — Settings Schemas
"""

import ipaddress
from typing import Optional, List

from pydantic import EmailStr, Field, field_validator, model_validator

from app.models.settings import DetectionSensitivity, ProtectionMode, WhitelistEntryType
from app.schemas.base import CamelModel, IdStr, UtcDatetime

_VALID_SEVERITIES = {"low", "medium", "high"}


# ── Detection Settings ────────────────────────────────────────────────────────

class DetectionSettingsResponse(CamelModel):
    """Detection configuration"""
    enabled: bool
    sensitivity: DetectionSensitivity
    anomaly_threshold: float
    min_flows_for_analysis: int
    analysis_interval_ms: int
    stage2_enabled: bool
    stage2_confidence_threshold: float


class DetectionSettingsUpdate(CamelModel):
    """Update detection settings"""
    enabled: Optional[bool] = None
    sensitivity: Optional[DetectionSensitivity] = None
    anomaly_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    min_flows_for_analysis: Optional[int] = Field(None, ge=1)
    analysis_interval_ms: Optional[int] = Field(None, ge=100)
    stage2_enabled: Optional[bool] = None
    stage2_confidence_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)


# ── Protection Settings ───────────────────────────────────────────────────────

class ProtectionSettingsResponse(CamelModel):
    """Protection configuration"""
    mode: ProtectionMode
    auto_block: bool
    auto_block_severities: List[str]
    block_duration_seconds: int
    max_blocked_ips: int
    notify_on_block: bool


class ProtectionSettingsUpdate(CamelModel):
    """Update protection settings"""
    mode: Optional[ProtectionMode] = None
    auto_block: Optional[bool] = None
    auto_block_severities: Optional[List[str]] = None
    block_duration_seconds: Optional[int] = Field(None, ge=1)
    max_blocked_ips: Optional[int] = Field(None, ge=1)
    notify_on_block: Optional[bool] = None

    @field_validator("auto_block_severities")
    @classmethod
    def _check_severities(cls, value):
        if value is None:
            return value
        bad = [v for v in value if v not in _VALID_SEVERITIES]
        if bad:
            raise ValueError(f"Unknown severities: {', '.join(bad)}")
        return value


# ── Advanced Protection (one on/off switch over the protection settings) ───────

class AdvancedProtectionResponse(CamelModel):
    """Advanced Protection: ON = detect AND auto-block attackers; OFF = detection only."""
    enabled: bool


class AdvancedProtectionUpdate(CamelModel):
    """Turn Advanced Protection on or off. (Only `enabled=false` is accepted here —
    turning it ON needs the emailed-code flow below.)"""
    enabled: bool


class AdvancedProtectionChallenge(CamelModel):
    """Returned when an admin asks to turn Advanced Protection ON: a code was emailed."""
    confirm_token: str
    sent_to: str
    message: str


class AdvancedProtectionConfirm(CamelModel):
    """Confirm turning Advanced Protection ON with the emailed code."""
    token: str = Field(..., min_length=10)
    otp: str = Field(..., min_length=4, max_length=10)


# ── Notification Settings ─────────────────────────────────────────────────────

class NotificationSettingsResponse(CamelModel):
    """Notification configuration"""
    email_enabled: bool
    email_address: Optional[str] = None
    alert_on_high: bool
    alert_on_medium: bool
    alert_on_low: bool
    alert_on_block: bool
    digest_enabled: bool
    digest_interval_hours: int


class NotificationSettingsUpdate(CamelModel):
    """Update notification settings"""
    email_enabled: Optional[bool] = None
    email_address: Optional[EmailStr] = None
    alert_on_high: Optional[bool] = None
    alert_on_medium: Optional[bool] = None
    alert_on_low: Optional[bool] = None
    alert_on_block: Optional[bool] = None
    digest_enabled: Optional[bool] = None
    digest_interval_hours: Optional[int] = Field(None, ge=1)

    @field_validator("email_address", mode="before")
    @classmethod
    def _empty_to_none(cls, value):
        return value or None


# ── System Settings ───────────────────────────────────────────────────────────

class SystemSettingsResponse(CamelModel):
    """System configuration"""
    log_retention_days: int
    max_stored_events: int
    timezone: str
    date_format: str
    debug_mode: bool
    contact_website: Optional[str] = None
    contact_phone: Optional[str] = None
    contact_email: Optional[str] = None
    contact_address: Optional[str] = None


class SystemSettingsUpdate(CamelModel):
    """Update system settings"""
    log_retention_days: Optional[int] = Field(None, ge=1)
    max_stored_events: Optional[int] = Field(None, ge=100)
    timezone: Optional[str] = Field(None, min_length=1, max_length=50)
    date_format: Optional[str] = Field(None, min_length=1, max_length=50)
    debug_mode: Optional[bool] = None
    contact_website: Optional[str] = Field(None, max_length=255)
    contact_phone: Optional[str] = Field(None, max_length=40)
    contact_email: Optional[EmailStr] = None
    contact_address: Optional[str] = Field(None, max_length=500)

    @field_validator("contact_website", "contact_phone", "contact_email", "contact_address", mode="before")
    @classmethod
    def _blank_to_none(cls, value):
        if isinstance(value, str):
            value = value.strip()
        return value or None

    @field_validator("contact_website")
    @classmethod
    def _website(cls, value: Optional[str]) -> Optional[str]:
        if value and not value.lower().startswith(("http://", "https://")):
            value = "https://" + value
        if value and ("." not in value or " " in value):
            raise ValueError("Enter a website address such as www.example.com")
        return value

    @field_validator("contact_phone")
    @classmethod
    def _phone(cls, value: Optional[str]) -> Optional[str]:
        if value and not all(ch.isdigit() or ch in "+-() " for ch in value):
            raise ValueError("Phone number may contain digits, spaces, +, - and brackets only")
        if value and sum(ch.isdigit() for ch in value) < 6:
            raise ValueError("Enter a complete phone number")
        return value


class ContactInfo(CamelModel):
    """'Contact us' details for the Support page (empty fields are not shown)."""
    website: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None


# ── All Settings ──────────────────────────────────────────────────────────────

class AllSettingsResponse(CamelModel):
    """Combined settings response"""
    detection: DetectionSettingsResponse
    protection: ProtectionSettingsResponse
    notifications: NotificationSettingsResponse
    system: SystemSettingsResponse


# ── Whitelist Entry ───────────────────────────────────────────────────────────

class WhitelistEntryResponse(CamelModel):
    """Whitelist entry"""
    id: IdStr
    type: WhitelistEntryType
    value: str
    description: Optional[str] = None
    created_at: UtcDatetime
    created_by: Optional[IdStr] = None
    active: bool


class CreateWhitelistEntryRequest(CamelModel):
    """Create whitelist entry (value is validated against its type)"""
    type: WhitelistEntryType
    value: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)

    @model_validator(mode="after")
    def _validate_value(self):
        value = self.value.strip()
        try:
            if self.type == WhitelistEntryType.IP:
                value = str(ipaddress.ip_address(value))
            elif self.type == WhitelistEntryType.CIDR:
                value = str(ipaddress.ip_network(value, strict=False))
            elif self.type == WhitelistEntryType.PORT:
                port = int(value)
                if not 0 <= port <= 65535:
                    raise ValueError
                value = str(port)
            elif self.type == WhitelistEntryType.PROTOCOL:
                value = value.upper()
                if value not in {"TCP", "UDP", "ICMP"}:
                    raise ValueError
        except ValueError:
            raise ValueError(f"'{self.value}' is not a valid {self.type.value} value")
        self.value = value
        return self


class SupportMessageRequest(CamelModel):
    """'Send us a message' from the Support page (sent to the admin's email)."""
    subject: str = Field(..., min_length=3, max_length=150)
    message: str = Field(..., min_length=10, max_length=5000)

    @field_validator("subject", "message", mode="before")
    @classmethod
    def _strip(cls, value):
        return value.strip() if isinstance(value, str) else value
