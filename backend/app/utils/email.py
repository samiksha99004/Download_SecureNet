"""
SecureNet Backend — Email Utilities

SMTP runs in a worker thread so it never blocks the asyncio event loop.
Emails are only ever really sent: when delivery is turned off or not
configured, callers get EmailDeliveryError — nothing is faked or printed.
"""

import asyncio
import html as html_mod
import smtplib
from dataclasses import dataclass
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable, List, Optional, Sequence

from app.core.config import settings
from app.utils.logger import logger

_PLACEHOLDER_MARKERS = ("your-", "your_", "example", "placeholder", "changeme", "change-me", "xxxx")


def _looks_placeholder(value: str) -> bool:
    value = value.strip().lower()
    return not value or any(marker in value for marker in _PLACEHOLDER_MARKERS)


class EmailDeliveryError(RuntimeError):
    """Raised when an email could not be delivered."""


def email_delivery_status() -> str:
    """'enabled' | 'disabled' (EMAIL_ENABLED=false) | 'misconfigured' (no SMTP credentials)."""
    if not settings.EMAIL_ENABLED:
        return "disabled"
    if _looks_placeholder(settings.SMTP_USER) or "@" not in settings.SMTP_USER             or _looks_placeholder(settings.SMTP_PASSWORD):
        return "misconfigured"
    return "enabled"


@dataclass(frozen=True)
class Attachment:
    """A file attached to an email (e.g. the incident report)."""
    filename: str
    content: bytes
    mime_subtype: str = "octet-stream"   # "plain" for .txt, "pdf", "csv", ...


def _build(to_email: str, subject: str, text: str, html: str,
           attachments: Sequence[Attachment] = (), reply_to: Optional[str] = None) -> MIMEMultipart:
    body = MIMEMultipart("alternative")
    body.attach(MIMEText(text, "plain", "utf-8"))
    body.attach(MIMEText(html, "html", "utf-8"))
    if attachments:
        message = MIMEMultipart("mixed")
        message.attach(body)
        for item in attachments:
            if item.mime_subtype == "plain":
                part = MIMEText(item.content.decode("utf-8"), "plain", "utf-8")
            else:
                part = MIMEApplication(item.content, _subtype=item.mime_subtype)
            part.add_header("Content-Disposition", "attachment", filename=item.filename)
            message.attach(part)
    else:
        message = body
    message["Subject"] = subject
    message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    message["To"] = to_email
    if reply_to:
        message["Reply-To"] = reply_to
    return message


def _send_many_sync(recipients: List[str], subject: str, text: str, html: str,
                    attachments: Sequence[Attachment] = (), reply_to: Optional[str] = None) -> List[str]:
    """Send one message per recipient over a single SMTP session. Returns failed addresses."""
    failed: List[str] = []
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        for rcpt in recipients:
            try:
                message = _build(rcpt, subject, text, html, attachments, reply_to)
                server.sendmail(settings.SMTP_FROM_EMAIL, [rcpt], message.as_string())
            except smtplib.SMTPException as exc:
                logger.error(f"Email to {rcpt} failed: {exc}")
                failed.append(rcpt)
    return failed


async def send_email(recipients: Iterable[str], subject: str, text: str, html: str,
                     attachments: Optional[Sequence[Attachment]] = None, reply_to: Optional[str] = None) -> None:
    """Send an email to each recipient. Raises EmailDeliveryError on failure
    (including when email delivery is turned off or not configured)."""
    rcpts = sorted({r.strip().lower() for r in recipients if r and r.strip()})
    if not rcpts:
        return
    status = email_delivery_status()
    if status == "disabled":
        raise EmailDeliveryError("Email delivery is turned off (EMAIL_ENABLED=false in backend/.env)")
    if status == "misconfigured":
        raise EmailDeliveryError("SMTP_USER / SMTP_PASSWORD in backend/.env are not set to a real account")
    try:
        failed = await asyncio.to_thread(_send_many_sync, rcpts, subject, text, html, tuple(attachments or ()), reply_to)
    except Exception as exc:
        raise EmailDeliveryError(str(exc)) from exc
    if failed:
        raise EmailDeliveryError(f"Delivery failed for: {', '.join(failed)}")
    logger.info(f"Email sent to {len(rcpts)} recipient(s): {subject}")


def render_code_email(code: str, heading: str, next_step: str) -> tuple[str, str]:
    """(text, html) of a verification-code email.

    Layout like the big services' code emails: a grey "Code requested" panel
    with every digit in its own box - nothing else to click; the user copies
    the digits by hand (Gmail may also add its own "Copy code" chip to
    verification-code emails like this). Table-based with inline styles only,
    so Gmail / Outlook / phone mail apps show it the same way.
    """
    app = html_mod.escape(settings.APP_NAME)
    minutes = settings.OTP_EXPIRE_MINUTES
    text = (
        f"Your {settings.APP_NAME} verification code is: {code}\n\n"
        f"{next_step}\n"
        f"This code expires in {minutes} minutes and works only once.\n"
        "If you didn't request this code, you can ignore this email."
    )
    # One contiguous code string (not per-digit boxes): this is what lets Gmail / Apple Mail /
    # iOS recognise it as a verification code and show their OWN one-tap "Copy code" button, and
    # it is trivially select-and-copy everywhere else. (Email has no JavaScript, so a custom
    # clickable copy button cannot work — the native mail-app chip is the real "copy button".)
    font = ("-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,"
            "Helvetica,Arial,sans-serif")
    mono = "ui-monospace,SFMono-Regular,'SF Mono',Consolas,'Liberation Mono',Menlo,monospace"
    body = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f4f6f9;font-family:{font};color:#0f172a;-webkit-font-smoothing:antialiased">
<div style="display:none;max-height:0;overflow:hidden">Your {app} verification code is {code}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9">
  <tr><td align="center" style="padding:32px 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border:1px solid #e5e9f0;border-radius:16px">
      <tr><td style="padding:32px 36px 8px">
        <div style="font-size:17px;font-weight:700;color:#0ea5a4;letter-spacing:.2px">&#128737; {app}</div>
      </td></tr>
      <tr><td style="padding:12px 36px 4px">
        <div style="font-size:22px;font-weight:700;letter-spacing:-.2px;color:#0f172a">{html_mod.escape(heading)} verification code</div>
        <div style="font-size:14px;line-height:1.55;color:#64748b;padding-top:8px">{html_mod.escape(next_step)}</div>
      </td></tr>
      <tr><td style="padding:22px 36px 6px">
        <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:12px;padding:22px 16px;text-align:center">
          <div style="font-size:12px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:#94a3b8;padding-bottom:12px">Your code</div>
          <div style="font-family:{mono};font-size:36px;font-weight:700;letter-spacing:12px;color:#0f172a;padding-left:12px">{html_mod.escape(code)}</div>
        </div>
      </td></tr>
      <tr><td style="padding:16px 36px 4px">
        <div style="font-size:13.5px;line-height:1.6;color:#475569">
          Expires in <b style="color:#0f172a">{minutes} minutes</b> &middot; works only once.
        </div>
      </td></tr>
      <tr><td style="padding:14px 36px 28px">
        <div style="font-size:12.5px;line-height:1.6;color:#94a3b8;border-top:1px solid #eef2f7;padding-top:16px">
          If you didn't request this code you can ignore this email &mdash; never share it with anyone.<br>
          Sent by {app} &middot; Behavioural Intrusion Detection System
        </div>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""
    return text, body


async def _send_code(email: str, code: str, purpose: str, next_step: str) -> None:
    """Email a code. Subject "[SecureNet] <purpose> verification code" (like GitHub's), which
    also helps mail apps recognise it as a code email."""
    text, body = render_code_email(code, purpose, next_step)
    await send_email([email], f"[{settings.APP_NAME}] {purpose} verification code", text, body)


async def send_otp_email(email: str, otp_code: str) -> None:
    """Registration code. Raises EmailDeliveryError if it cannot be sent."""
    await _send_code(email, otp_code, "Sign-up",
                     f"Enter it on the {settings.APP_NAME} sign-up page, then create your password.")


async def send_password_reset_email(email: str, otp_code: str) -> None:
    """Forgot-password code. Raises EmailDeliveryError if it cannot be sent."""
    await _send_code(email, otp_code, "Password reset",
                     f"Enter it on the {settings.APP_NAME} forgot-password page, then choose a new password.")


async def send_login_code_email(email: str, otp_code: str) -> None:
    """Sign-in code (second step after the password). Raises EmailDeliveryError."""
    await _send_code(email, otp_code, "Sign-in",
                     f"Your password was just entered on the {settings.APP_NAME} sign-in page. Enter this code to "
                     "finish signing in. If this was not you, change your password right away - someone knows it.")


async def send_password_change_email(email: str, otp_code: str) -> None:
    """Code confirming a signed-in user's password change. Raises EmailDeliveryError."""
    await _send_code(email, otp_code, "Password change",
                     f"Someone signed in to your {settings.APP_NAME} account asked to change its password. Enter "
                     "this code on the Account page to confirm. If this was not you, ignore this email, keep your "
                     f"password and tell the {settings.APP_NAME} admin.")


async def send_profile_change_email(email: str, otp_code: str, summary: str) -> None:
    """Code confirming a change of the user's own details. Raises EmailDeliveryError."""
    await _send_code(email, otp_code, "Profile change",
                     f"You asked to change your {summary}. Enter this code on the {settings.APP_NAME} Account page "
                     "to confirm. If this was not you, ignore this email and nothing will change.")
