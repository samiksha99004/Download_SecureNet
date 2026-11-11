"""
SecureNet — Alert e-mail notifier

Every stored security event is handed to `notifier.enqueue(event)` by the IDS.
The notifier:
  * emails when the network goes from NORMAL to ABNORMAL (after ALERT_EMAIL_BATCH_SECONDS,
    so the start of a burst lands in one email), then — while it stays abnormal — at most
    ONE summary email every ALERT_EMAIL_INTERVAL_SECONDS (5 min). After 5 quiet minutes the
    network counts as normal again, and the next alert starts a new episode (email at once).
    In-app pop-ups and desktop alerts are not throttled — they show every alert;
  * filters by Settings → Notifications (high / medium / blocked);
  * sends FROM the admin's Gmail (SMTP_USER) TO every active SecureNet user (and the
    optional extra address from Settings). The admin is the sender, not a user, and
    never receives attack emails;
  * sends a periodic digest when "digest" is enabled.

In-app / desktop pop-ups are handled by the frontend from the WebSocket
`alert` messages; this module is only about email.
"""

from __future__ import annotations

import asyncio
from collections import Counter
import html
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import List, Optional, Sequence

from sqlalchemy import func, select

from app.core.config import settings
from app.db.base import AsyncSessionLocal
from app.models.security_event import ActionTaken, SecurityEvent, SeverityLevel
from app.models.settings import NotificationSettings
from app.models.user import AccountStatus, User, UserRole
from app.services.incident_report import render_text, report_filename, server_offset_minutes, to_local, tz_label
from app.utils.email import Attachment, EmailDeliveryError, send_email
from app.utils.logger import logger
from app.services.verdict import ABNORMAL, guesses_text, possible_attack, pretty_label
from app.utils.timeutil import parse_iso_utc, to_iso_z, utcnow

SEVERITY_COLORS = {"high": "#dc2626", "medium": "#d97706", "low": "#059669"}


@dataclass
class AlertInfo:
    """Snapshot of a security event (safe to keep after the DB session closes)."""
    event_id: str
    timestamp: str
    severity: str
    attack_type: Optional[str]
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    anomaly_score: float
    action: str
    reason: Optional[str]
    confidence: Optional[float] = None
    guesses: Optional[list] = None
    owner_id: Optional[str] = None

    @classmethod
    def from_event(cls, e: SecurityEvent) -> "AlertInfo":
        return cls(
            event_id=str(e.id),
            owner_id=str(e.owner_id) if e.owner_id else None,
            timestamp=to_iso_z(e.timestamp),
            severity=e.severity.value,
            attack_type=e.attack_type,
            source_ip=e.source_ip,
            source_port=e.source_port,
            destination_ip=e.destination_ip,
            destination_port=e.destination_port,
            protocol=e.protocol.value,
            anomaly_score=float(e.anomaly_score),
            action=e.action_taken.value,
            reason=e.detection_reason,
            confidence=e.confidence,
            guesses=e.attack_guesses,
        )

    @property
    def title(self) -> str:
        return ABNORMAL

    @property
    def guess(self) -> str:
        """The model's best guess of which attack it might be."""
        return possible_attack(self.attack_type, self.confidence, self.guesses)


def wanted(alert: AlertInfo, prefs: NotificationSettings) -> bool:
    """Does this alert match the notification preferences?"""
    return (
        (alert.severity == SeverityLevel.HIGH.value and prefs.alert_on_high)
        or (alert.severity == SeverityLevel.MEDIUM.value and prefs.alert_on_medium)
        or (alert.severity == SeverityLevel.LOW.value and prefs.alert_on_low)
        or (alert.action == ActionTaken.BLOCKED.value and prefs.alert_on_block)
    )


async def get_recipients(db, prefs: Optional[NotificationSettings], owner_id: Optional[str] = None) -> List[str]:
    """Who gets attack emails, plus the optional extra address from Settings.

    Per-account model: when `owner_id` is given (the account that owns the events, i.e. the user
    who was logged in when they were detected), the alert goes ONLY to that account — so each user
    gets their own attacks. Without an owner (e.g. a shared status view or events with no owner) it
    falls back to every active account with email alerts on."""
    if owner_id is not None:
        try:
            owner_uuid = uuid.UUID(str(owner_id))      # the User.id column is a UUID
        except (TypeError, ValueError):
            owner_uuid = None
        row = (await db.execute(
            select(User.email, User.email_alerts).where(
                User.id == owner_uuid, User.account_status == AccountStatus.ACTIVE)
        )).first() if owner_uuid else None
        recipients = {row[0].strip().lower()} if (row and row[0] and row[1]) else set()
    else:
        users = (await db.execute(
            select(User.email, User.email_alerts).where(User.account_status == AccountStatus.ACTIVE)
        )).all()
        recipients = {email.strip().lower() for email, wants in users if email and wants}
    if prefs is not None and prefs.email_address:
        recipients.add(prefs.email_address.strip().lower())
    return sorted(recipients)


# ── Email rendering ──────────────────────────────────────────────────────────

def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def most_severe(alerts: Sequence[AlertInfo]) -> AlertInfo:
    return max(alerts, key=lambda a: (SEVERITY_RANK.get(a.severity, 0), a.timestamp))


def local_time(iso: str) -> str:
    """Alert time in the backend machine's local time zone, e.g. 25 Sep 2026, 16:29:11 (UTC+05:30)."""
    offset = server_offset_minutes()
    return f"{to_local(parse_iso_utc(iso), offset):%d %b %Y, %H:%M:%S} ({tz_label(offset)})"


def _clock(iso: str) -> str:
    offset = server_offset_minutes()
    return f"{to_local(parse_iso_utc(iso), offset):%H:%M}"


def _day(iso: str) -> str:
    offset = server_offset_minutes()
    return f"{to_local(parse_iso_utc(iso), offset):%d %b %Y}"


def likely_attack(alerts: Sequence[AlertInfo]) -> tuple[str, int]:
    """The attack the model guessed most often in these alerts, and in how many."""
    names = []
    for a in alerts:
        guess = a.guess
        names.append(guess.split(" (")[0] if guess else "Unknown")
    name, count = Counter(names).most_common(1)[0]
    return name, count


def summarize_alerts(alerts: Sequence[AlertInfo]) -> dict:
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    severities = Counter(a.severity for a in ordered)
    sources = Counter(a.source_ip for a in ordered)
    name, count = likely_attack(ordered)
    offset = server_offset_minutes()
    first, last = ordered[0].timestamp, ordered[-1].timestamp
    when = _clock(first) if _clock(first) == _clock(last) else f"{_clock(first)} – {_clock(last)}"
    top_source, _ = sources.most_common(1)[0]
    others = len(sources) - 1
    return {
        "total": len(ordered),
        "high": severities.get("high", 0), "medium": severities.get("medium", 0), "low": severities.get("low", 0),
        "attack": name, "attack_count": count,
        "when": f"{when} on {_day(last)} ({tz_label(offset)})",
        "first_clock": _clock(first),
        "source": top_source + (f" and {others} other{'s' if others != 1 else ''}" if others else ""),
        "worst": max(ordered, key=lambda a: SEVERITY_RANK.get(a.severity, 0)).severity,
    }


# what each kind of email says first
EMAIL_KINDS = {
    "new": ("Abnormal Network Found",
            "SecureNet detected abnormal activity on your network. Below is the live traffic "
            "breakdown — every class SecureNet saw and its share of recent traffic."),
    "continuing": ("Abnormal Network Found",
                   "SecureNet is still seeing abnormal activity on your network. Below is the live "
                   "traffic breakdown of the last few minutes."),
    "digest": ("Security summary", "A summary of the traffic SecureNet recently flagged as possibly abnormal."),
    "test": ("Test alert", "This is a test. Email alerts from SecureNet are working."),
}


def _is_benign(label: str) -> bool:
    return (label or "").lower() in ("benign", "normal")


def breakdown_lines(breakdown: Optional[Sequence[dict]]) -> list[str]:
    """Plain-text rows of the dashboard's live breakdown: every class with its %, biggest first."""
    rows: list[str] = []
    for r in (breakdown or []):
        raw = str(r.get("label", "?"))
        label = pretty_label(raw)            # display name only
        pct = float(r.get("pct", 0.0))
        tag = "" if _is_benign(raw) else "  (attack)"
        rows.append(f"  {label:<28} {pct:5.1f}%{tag}")
    return rows


def render_alert_email(alerts: Sequence[AlertInfo], kind: str = "new",
                       breakdown: Optional[Sequence[dict]] = None,
                       abnormal_pct: Optional[float] = None) -> tuple[str, str]:
    """(text, html) of an alert email. Headline: ABNORMAL NETWORK FOUND. The body lists the live
    dashboard breakdown — every traffic class and its share, even 0.1% — instead of a single
    (often wrong) attack guess. Every per-flow detail is still in the attached incident report."""
    info = summarize_alerts(alerts)
    title, intro = EMAIL_KINDS.get(kind, EMAIL_KINDS["new"])
    app = _esc(settings.APP_NAME)
    interval_min = max(1, settings.ALERT_EMAIL_INTERVAL_SECONDS // 60)
    link = f"{settings.DASHBOARD_URL}/history"
    pct_line = f"Attacks were {abnormal_pct:.1f}% of recent traffic." if abnormal_pct is not None else ""
    b_lines = breakdown_lines(breakdown)

    text = "\n".join([
        f"{settings.APP_NAME}: ABNORMAL NETWORK FOUND",
        "",
        intro,
        pct_line,
        "",
        "LIVE TRAFFIC BREAKDOWN (same as the dashboard — every class, even 0.1%):",
        *(b_lines or ["  (breakdown not available)"]),
        "",
        f"When      : {info['when']}",
        f"Involving : {info['source']}",
        "",
        "The percentages above are the model's per-flow guesses; on normal internet traffic some",
        "are false positives. Treat each as a lead to verify, not a confirmed attack.",
        "",
        "The full per-flow report is attached - open or print it for every detail.",
        f"See it in SecureNet: {link}",
        "",
        f"You get at most one alert email every {interval_min} minutes. Alerts on your screen are not affected.",
    ])

    def brow(r: dict) -> str:
        raw = str(r.get("label", "?"))
        label = pretty_label(raw)            # display name only
        pct = float(r.get("pct", 0.0))
        benign = _is_benign(raw)
        color = "#059669" if benign else "#dc2626"
        bar = max(2, min(100, round(pct)))
        return (
            '<tr>'
            f'<td style="padding:4px 10px 4px 0;font-size:14px;color:#1f2328;white-space:nowrap">'
            f'{_esc(label)}{"" if benign else " <span style=\'color:#dc2626;font-size:11px\'>attack</span>"}</td>'
            f'<td style="padding:4px 0;width:100%">'
            f'<div style="background:#eef1f6;border-radius:6px;height:10px"><div style="background:{color};'
            f'height:10px;border-radius:6px;width:{bar}%"></div></div></td>'
            f'<td style="padding:4px 0 4px 10px;font-size:14px;font-weight:bold;color:{color};text-align:right;'
            f'white-space:nowrap">{pct:.1f}%</td></tr>'
        )

    brows = "".join(brow(r) for r in (breakdown or [])) or (
        '<tr><td style="font-size:14px;color:#8c959f">Breakdown not available.</td></tr>')

    def irow(label: str, value: str) -> str:
        return (f'<tr><td style="padding:4px 16px 4px 0;color:#59636e;font-size:13px;white-space:nowrap">'
                f'{_esc(label)}</td><td style="padding:4px 0;font-size:13px;color:#1f2328">{value}</td></tr>')

    body = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#ffffff;font-family:Arial,Helvetica,sans-serif;color:#1f2328">
<div style="display:none;max-height:0;overflow:hidden">Abnormal network found{(" — attacks " + format(abnormal_pct, ".0f") + "% of recent traffic") if abnormal_pct is not None else ""}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff">
  <tr><td align="center" style="padding:24px 12px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px">
      <tr><td style="font-size:20px;font-weight:bold;color:#c2562f;padding:0 0 8px">&#128737; {app}</td></tr>
      <tr><td style="background:#fdeceb;border-left:5px solid #dc2626;border-radius:12px;padding:16px 20px">
        <div style="font-size:24px;font-weight:bold;color:#b91c1c;letter-spacing:0.01em">ABNORMAL NETWORK FOUND</div>
        {f'<div style="font-size:15px;color:#7f1d1d;padding-top:4px">{_esc(pct_line)}</div>' if pct_line else ''}
      </td></tr>
      <tr><td style="font-size:14px;line-height:1.5;color:#3d444d;padding:16px 2px 12px">{_esc(intro)}</td></tr>
      <tr><td style="padding:0 0 6px;font-size:12px;font-weight:bold;letter-spacing:0.05em;color:#59636e">
        LIVE TRAFFIC BREAKDOWN (same as the dashboard)</td></tr>
      <tr><td style="padding:0 0 8px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">{brows}</table></td></tr>
      <tr><td style="padding:10px 0 0"><table role="presentation" cellpadding="0" cellspacing="0">
        {irow("When", _esc(info["when"]))}{irow("Involving", _esc(info["source"]))}</table></td></tr>
      <tr><td style="font-size:13px;line-height:1.5;padding:14px 2px 0;color:#8c959f">
        The percentages are the model's per-flow guesses; on normal internet traffic some are false
        positives. Treat each as a lead to verify, not a confirmed attack.</td></tr>
      <tr><td style="font-size:14px;line-height:1.5;padding:14px 2px 0;color:#3d444d">
        The full per-flow report is attached &mdash; open or print it for every detail.</td></tr>
      <tr><td style="font-size:12px;line-height:1.5;color:#8c959f;padding:24px 2px 0;border-top:1px solid #e6e9ee">
        You get at most one alert email every {interval_min} minutes; alerts on your screen are not affected.
        To stop these emails: SecureNet &rarr; Settings &rarr; Preferences &rarr; Attack Alert Emails.<br>
        Sent by {app} &ndash; Behavioural Intrusion Detection System</td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""
    return text, body


def alert_subject(alerts: Sequence[AlertInfo], kind: str = "new",
                  abnormal_pct: Optional[float] = None) -> str:
    pct = f" - attacks {abnormal_pct:.0f}% of recent traffic" if abnormal_pct is not None else ""
    return f"[{settings.APP_NAME}] Abnormal network found{pct}"


# ── Notifier service ─────────────────────────────────────────────────────────

async def fetch_events(db, alerts: Sequence[AlertInfo]) -> List[SecurityEvent]:
    ids = [uuid.UUID(a.event_id) for a in alerts]
    events = (await db.execute(select(SecurityEvent).where(SecurityEvent.id.in_(ids)))).scalars().all()
    return sorted(events, key=lambda e: e.timestamp)


def report_attachment(events: Sequence[SecurityEvent], breakdown: Optional[Sequence[dict]] = None,
                      abnormal_pct: Optional[float] = None) -> Attachment:
    """Incident report (.txt) for the attacks in one alert email, with the live breakdown on top."""
    offset = server_offset_minutes()
    stamp = to_local(utcnow(), offset).strftime("%Y%m%d-%H%M%S")
    title = f"Abnormal network found - {len(events)} flagged flow(s)"
    content = render_text(events, title, offset, breakdown=breakdown, abnormal_pct=abnormal_pct)
    return Attachment(report_filename("incident-report", stamp, "txt"), content.encode("utf-8"), "plain")


class AlertNotifier:
    def __init__(self) -> None:
        self._pending: List[AlertInfo] = []
        self._wakeup = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._last_digest = time.time()
        self._last_alert_at: Optional[float] = None    # when the latest alert arrived (monotonic)
        self._last_email_at: Optional[float] = None    # when the latest alert email went out
        self._new_episode = False                      # network went from normal to abnormal
        self.emails_sent = 0
        self.last_error: Optional[str] = None

    def enqueue(self, event: SecurityEvent) -> None:
        """Queue a stored security event for the next alert email."""
        now = time.monotonic()
        quiet = self._last_alert_at is None or now - self._last_alert_at > settings.ALERT_EMAIL_INTERVAL_SECONDS
        if quiet:                       # normal → abnormal: this alert starts a new episode
            self._new_episode = True
        self._last_alert_at = now
        self._pending.append(AlertInfo.from_event(event))
        self._wakeup.set()

    def seconds_until_next_email(self) -> float:
        """How long the queued alerts wait: a short batch window for a new episode,
        otherwise until 5 minutes after the previous alert email."""
        interval = settings.ALERT_EMAIL_INTERVAL_SECONDS
        if self._new_episode or self._last_email_at is None:
            since = None if self._last_email_at is None else time.monotonic() - self._last_email_at
            if since is not None and since < interval:      # a new episode right after an email: still 5 min apart
                return interval - since
            return float(settings.ALERT_EMAIL_BATCH_SECONDS)
        return max(0.0, interval - (time.monotonic() - self._last_email_at))

    async def start(self) -> None:
        if self._task is None:
            self._wakeup = asyncio.Event()
            self._task = asyncio.create_task(self._run(), name="alert-notifier")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        # alerts queued right before shutdown: send them unless that would break the 5-minute
        # spacing (they stay in History and the daily report either way)
        if self._pending and self.seconds_until_next_email() <= settings.ALERT_EMAIL_BATCH_SECONDS:
            await self.flush()

    async def _run(self) -> None:
        while True:
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
            self._wakeup.clear()
            if self._pending:
                # new episode: wait the batch window; still abnormal: wait until 5 min after the last email.
                # Alerts arriving meanwhile join the same email.
                await asyncio.sleep(self.seconds_until_next_email())
                self._wakeup.clear()
            try:
                await self.flush()
                await self._maybe_send_digest()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never let the notifier die
                self.last_error = str(exc)
                logger.error(f"Alert notifier error: {exc}", exc_info=True)

    async def flush(self) -> int:
        """Send pending alerts now. Returns the number of alerts emailed."""
        pending, self._pending = self._pending, []
        if not pending:
            return 0
        kind = "new" if self._new_episode else "continuing"
        self._new_episode = False
        async with AsyncSessionLocal() as db:
            prefs = (await db.execute(select(NotificationSettings).limit(1))).scalars().first()
            if prefs is None or not prefs.email_enabled:
                return 0
            alerts = [a for a in pending if wanted(a, prefs)]
            if not alerts:
                return 0
            # Per-account: the email goes to the account that owns these events (whoever was logged
            # in when they were detected). One user is logged in at a time, so all share one owner.
            owner_id = next((a.owner_id for a in alerts if a.owner_id), None)
            recipients = await get_recipients(db, prefs, owner_id)
            if not recipients:
                return 0
            events = await fetch_events(db, alerts)

        # Live dashboard breakdown (every class + %, even 0.1%) — the email leads with this, not a
        # single (often wrong) attack guess.
        breakdown: List[dict] = []
        abnormal_pct: Optional[float] = None
        try:
            from app.ml.ids_service import get_ids_service   # lazy: avoid import cycle
            summary = get_ids_service().verdict_summary()
            breakdown = list(summary.get("recent") or [])
            abnormal_pct = summary.get("recent_abnormal_pct")
        except Exception as exc:
            logger.warning(f"Could not read live breakdown for alert email: {exc}")

        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        report = await asyncio.to_thread(report_attachment, events, breakdown, abnormal_pct)
        subject = alert_subject(alerts, kind, abnormal_pct)
        text, body = render_alert_email(alerts, kind, breakdown, abnormal_pct)
        mails = [(recipients, subject, text, body)]
        self._last_email_at = time.monotonic()
        for rcpts, subj, text, body in mails:
            try:
                await send_email(rcpts, subj, text, body, attachments=[report])
                self.emails_sent += 1
                self.last_error = None
            except EmailDeliveryError as exc:
                self.last_error = str(exc)
                logger.error(f"Alert email failed: {exc}")
        return len(alerts)

    async def _maybe_send_digest(self) -> None:
        async with AsyncSessionLocal() as db:
            prefs = (await db.execute(select(NotificationSettings).limit(1))).scalars().first()
            if prefs is None or not prefs.email_enabled or not prefs.digest_enabled:
                return
            interval = max(1, prefs.digest_interval_hours) * 3600
            if time.time() - self._last_digest < interval:
                return
            self._last_digest = time.time()
            since = utcnow() - timedelta(seconds=interval)
            # Only the currently signed-in account (the active owner) gets mail. Its digest summarises
            # ONLY its own events. If nobody is signed in, no digest is sent.
            try:
                from app.ml.ids_service import get_ids_service   # lazy: avoid import cycle
                owner_id = get_ids_service().active_owner_id
            except Exception:
                owner_id = None
            digests = []   # (email, alerts, total)
            if owner_id:
                row = (await db.execute(
                    select(User.id, User.email).where(
                        User.id == uuid.UUID(str(owner_id)), User.account_status == AccountStatus.ACTIVE,
                        User.email_alerts.is_(True))
                )).first()
                if row and row[1]:
                    events = (await db.execute(
                        select(SecurityEvent).where(SecurityEvent.owner_id == row[0], SecurityEvent.timestamp >= since)
                        .order_by(SecurityEvent.timestamp.desc()).limit(settings.ALERT_EMAIL_MAX_EVENTS)
                    )).scalars().all()
                    if events:
                        total = (await db.execute(
                            select(func.count()).select_from(SecurityEvent)
                            .where(SecurityEvent.owner_id == row[0], SecurityEvent.timestamp >= since)
                        )).scalar() or 0
                        digests.append((row[1].strip().lower(), [AlertInfo.from_event(e) for e in events], total))
        hours = prefs.digest_interval_hours
        for email, alerts, total in digests:
            text, body = render_alert_email(alerts, "digest")
            try:
                await send_email([email], f"[{settings.APP_NAME}] Security digest — {total} event(s) in {hours}h",
                                 text, body)
                self.emails_sent += 1
            except EmailDeliveryError as exc:
                self.last_error = str(exc)
                logger.error(f"Digest email failed: {exc}")


notifier = AlertNotifier()


def get_notifier() -> AlertNotifier:
    return notifier
