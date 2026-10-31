"""
SecureNet Backend — Support Routes

- "Contact us" details for the Support page and the "Visit our website" link
  on the sign-in pages (public). The admin edits them in Settings → System;
  until an email is set, the admin's own email is shown.
- "Send us a message": a signed-in user's message is emailed to the contact
  email (Reply-To = the user, so the admin answers them directly), the user
  gets a copy, and the message is stored (record + limits that survive a
  restart; plus a per-network-address limit).
"""

import html
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.api.routes.settings_routes import get_or_create
from app.core.config import settings
from app.db.base import AsyncSessionLocal, get_db
from app.models.settings import SystemSettings
from app.models.support import SupportMessage
from app.models.user import User
from app.schemas.common import MessageResponse
from app.schemas.settings import ContactInfo, SupportMessageRequest
from app.services.cache import cached
from app.utils import ratelimit
from app.utils.email import EmailDeliveryError, send_email
from app.utils.logger import logger
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/support", tags=["Support"])

# Anti-spam: at most one message per minute and 10 per day per user (counted
# from the stored messages, so a restart does not reset it)
MESSAGE_COOLDOWN_SECONDS = 60
MESSAGES_PER_DAY = 10


def _admin_email() -> Optional[str]:
    return sorted(settings.admin_emails)[0] if settings.admin_emails else None


@router.get("/contact", response_model=ContactInfo)
async def get_contact():
    return await cached_contact()


async def _load_contact() -> ContactInfo:
    async with AsyncSessionLocal() as db:
        row = await get_or_create(db, SystemSettings)
    return ContactInfo(
        website=row.contact_website,
        phone=row.contact_phone,
        email=row.contact_email or _admin_email(),
        address=row.contact_address,
    )


async def cached_contact() -> ContactInfo:
    return await cached("settings:contact", _load_contact, ttl=300)


async def _check_rate(db: AsyncSession, user: User) -> None:
    now = utcnow()
    last = (await db.execute(
        select(func.max(SupportMessage.created_at)).where(SupportMessage.user_id == user.id)
    )).scalar()
    if last is not None and (now - last).total_seconds() < MESSAGE_COOLDOWN_SECONDS:
        wait = int(MESSAGE_COOLDOWN_SECONDS - (now - last).total_seconds()) + 1
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"Please wait {wait} seconds before sending another message.")
    today = (await db.execute(
        select(func.count()).select_from(SupportMessage)
        .where(SupportMessage.user_id == user.id, SupportMessage.created_at >= now - timedelta(days=1))
    )).scalar() or 0
    if today >= MESSAGES_PER_DAY:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="You have sent the maximum number of messages for today. Please try again tomorrow.")


def _render(user: User, subject: str, message: str, for_admin: bool) -> tuple[str, str]:
    who = f"{user.full_name} <{user.email}>"
    phone = user.phone_number or "-"
    intro = ("A SecureNet user sent a message from the Support page. Reply to this email to answer them."
             if for_admin else
             "Thank you for contacting SecureNet. This is a copy of your message; the team will reply to this email address.")
    text = (f"{intro}\n\nFrom: {who}\nPhone: {phone}\nSubject: {subject}\n\n{message}\n")
    esc = html.escape
    body = f"""<html><body style="margin:0;background:#fbeee4;font-family:Arial,Helvetica,sans-serif">
  <div style="max-width:640px;margin:0 auto;padding:24px">
    <div style="color:#c2562f;font-size:20px;font-weight:bold;margin-bottom:8px">SecureNet</div>
    <div style="background:#fffaf6;border:1px solid #efd6c6;border-radius:8px;padding:20px;color:#3d2b22">
      <p style="margin:0 0 16px;color:#5a4035">{esc(intro)}</p>
      <table style="font-size:14px;margin-bottom:16px">
        <tr><td style="color:#7d6154;padding:2px 12px 2px 0">From</td><td>{esc(who)}</td></tr>
        <tr><td style="color:#7d6154;padding:2px 12px 2px 0">Phone</td><td>{esc(phone)}</td></tr>
        <tr><td style="color:#7d6154;padding:2px 12px 2px 0">Subject</td><td><b>{esc(subject)}</b></td></tr>
      </table>
      <div style="white-space:pre-wrap;font-size:14px;line-height:1.5;border-top:1px solid #efd6c6;padding-top:12px">{esc(message)}</div>
    </div>
  </div></body></html>"""
    return text, body


@router.post("/message", response_model=MessageResponse)
async def send_support_message(
    request: SupportMessageRequest,
    http: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    row = await get_or_create(db, SystemSettings)
    to = row.contact_email or _admin_email()
    if not to:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Messages can't be sent yet. Please try again later.")
    ratelimit.enforce("support", http)
    await _check_rate(db, current_user)

    subject = " ".join(request.subject.split())  # no line breaks in the header
    text, body = _render(current_user, subject, request.message, for_admin=True)
    try:
        await send_email([to], f"[SecureNet Support] {subject}", text, body, reply_to=current_user.email)
    except EmailDeliveryError as exc:
        logger.error(f"Support message from {current_user.email} failed: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Your message could not be sent right now. Please try again in a few minutes.")
    db.add(SupportMessage(user_id=current_user.id, sender_email=current_user.email, recipient=to,
                          subject=subject, message=request.message))
    await db.commit()
    ratelimit.record("support", http)
    logger.info(f"Support message sent from {current_user.email} to {to}")

    # Copy for the user (best effort — the message itself was delivered)
    copy_text, copy_body = _render(current_user, subject, request.message, for_admin=False)
    try:
        await send_email([current_user.email], f"[SecureNet Support] Copy of your message: {subject}",
                         copy_text, copy_body, reply_to=to)
    except EmailDeliveryError as exc:
        logger.warning(f"Support message copy to {current_user.email} failed: {exc}")

    return MessageResponse(message="Your message has been sent. We will reply to you by email.")
