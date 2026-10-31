"""
SecureNet Backend — Notification Routes

  GET  /api/notifications            recent alerts for the notification bell
  GET  /api/notifications/status     email delivery status + recipients
  POST /api/notifications/test-email send a sample alert email to yourself
"""

import time
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.db.base import AsyncSessionLocal, get_db
from app.ml.ids_service import alert_payload
from app.models.security_event import SecurityEvent
from app.models.settings import NotificationSettings
from app.models.user import User, UserRole
from app.schemas.base import CamelModel
from app.schemas.common import MessageResponse
from app.services.cache import cached
from app.services.notifier import AlertInfo, get_notifier, get_recipients, render_alert_email
from app.utils.email import EmailDeliveryError, email_delivery_status, send_email
from app.utils.timeutil import to_iso_z, utcnow

router = APIRouter(prefix="/notifications", tags=["Notifications"])

TEST_EMAIL_COOLDOWN_SECONDS = 30
_last_test_email: Dict[str, float] = {}


class NotificationItem(CamelModel):
    event_id: str
    timestamp: str
    severity: str
    verdict: str = "abnormal"
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
    possible_attack: str = "Unknown"     # the model's best guess, e.g. "DDoS (97%)"
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    anomaly_score: float
    action_taken: str
    message: str


class NotificationStatus(CamelModel):
    email_delivery: str            # enabled | disabled | misconfigured
    email_alerts_enabled: bool     # Settings → Notifications → email alerts
    recipient_count: int
    recipients: List[str] = []     # admins only
    batch_seconds: int
    interval_seconds: int = 300      # at most one attack email this often
    emails_sent: int
    last_error: Optional[str] = None


async def _load_feed(limit: int) -> List[NotificationItem]:
    async with AsyncSessionLocal() as db:
        events = (await db.execute(
            select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)
        )).scalars().all()
    return [NotificationItem.model_validate(alert_payload(e)) for e in events]


async def cached_feed(limit: int = 30) -> List[NotificationItem]:
    return await cached(f"events:feed:{limit}", lambda: _load_feed(limit), ttl=300)


@router.get("", response_model=List[NotificationItem])
async def list_notifications(
    limit: int = Query(30, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Most recent security alerts (newest first; served from memory)."""
    return await cached_feed(limit)


async def _load_recipients() -> tuple[bool, List[str]]:
    async with AsyncSessionLocal() as db:
        prefs = (await db.execute(select(NotificationSettings).limit(1))).scalars().first()
        return bool(prefs and prefs.email_enabled), await get_recipients(db, prefs)


async def cached_recipients() -> tuple[bool, List[str]]:
    return await cached("settings:recipients", _load_recipients, ttl=30)


@router.get("/status", response_model=NotificationStatus)
async def notification_status(current_user: User = Depends(get_current_user)):
    # "settings:" prefix: dropped when settings change; accounts changing drop it too (forget_user)
    email_on, recipients = await cached_recipients()
    notifier = get_notifier()
    return NotificationStatus(
        email_delivery=email_delivery_status(),
        email_alerts_enabled=email_on,
        recipient_count=len(recipients),
        recipients=recipients if current_user.role == UserRole.ADMIN else [],
        batch_seconds=settings.ALERT_EMAIL_BATCH_SECONDS,
        interval_seconds=settings.ALERT_EMAIL_INTERVAL_SECONDS,
        emails_sent=notifier.emails_sent,
        last_error=notifier.last_error,
    )


@router.post("/test-email", response_model=MessageResponse)
async def send_test_email(current_user: User = Depends(get_current_user)):
    """Send a sample alert email to the signed-in user's registered address."""
    delivery = email_delivery_status()
    if delivery != "enabled":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Email delivery is turned off on the server. In backend/.env set EMAIL_ENABLED=true and "
                "SMTP_USER / SMTP_PASSWORD (for Gmail use an App Password), then restart the backend."
                if delivery == "disabled"
                else "SMTP_USER / SMTP_PASSWORD are not configured in backend/.env."
            ),
        )
    now = time.time()
    if now - _last_test_email.get(current_user.email, 0) < TEST_EMAIL_COOLDOWN_SECONDS:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Please wait a few seconds before sending another test email.")
    _last_test_email[current_user.email] = now

    sample = AlertInfo(
        event_id="test", timestamp=to_iso_z(utcnow()), severity="high", attack_type="Test alert (sample)",
        source_ip="203.0.113.10", source_port=51515, destination_ip="192.168.1.10", destination_port=22,
        protocol="TCP", anomaly_score=0.91, action="alerted",
        reason="This is a test message from SecureNet — email alerting is working.",
    )
    text, body = render_alert_email([sample], "test")
    try:
        await send_email([current_user.email], f"[{settings.APP_NAME}] Test alert email", text, body)
    except EmailDeliveryError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Email could not be sent: {exc}")
    return MessageResponse(message=f"Test email sent to {current_user.email}")
