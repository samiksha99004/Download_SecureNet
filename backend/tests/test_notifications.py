"""Notification system tests: alert emails, recipients, feed, test email."""

import pytest

from app.db.base import AsyncSessionLocal
from app.models.security_event import (
    ActionTaken, DetectionMode, EventState, Protocol, SecurityEvent, SeverityLevel,
)
from app.models.settings import NotificationSettings
from app.services.notifier import AlertNotifier
from app.utils.timeutil import utcnow
from tests.conftest import register


async def make_event(severity=SeverityLevel.HIGH, action=ActionTaken.ALERTED, attack="DDoS") -> SecurityEvent:
    async with AsyncSessionLocal() as db:
        event = SecurityEvent(
            timestamp=utcnow(), source_ip="203.0.113.7", source_port=50000,
            destination_ip="192.168.1.5", destination_port=80, protocol=Protocol.TCP,
            anomaly_score=0.9, severity=severity, attack_type=attack, confidence=0.95,
            mode=DetectionMode.PROTECT, state=EventState.ACTIVE, action_taken=action,
            detection_reason="unit test",
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)
        return event


async def set_prefs(**values):
    async with AsyncSessionLocal() as db:
        prefs = NotificationSettings(**values)
        db.add(prefs)
        await db.commit()


@pytest.fixture
def sent(monkeypatch):
    """Capture outgoing emails instead of using SMTP."""
    mails = []

    async def fake_send(recipients, subject, text, html, attachments=None):
        mails.append({"to": sorted(recipients), "subject": subject, "text": text, "html": html,
                      "attachments": list(attachments or [])})

    monkeypatch.setattr("app.services.notifier.send_email", fake_send)
    return mails


async def test_alerts_are_batched_to_all_registered_users(client, captured_otps, sent):
    """Alerts go from the admin's Gmail to every SecureNet user; the admin gets none."""
    await register(client, captured_otps, email="admin@example.com", name="Owner Admin")       # first = admin
    await register(client, captured_otps, email="analyst@example.com", name="Asha Rao", phone="+919000000001")
    await set_prefs(email_enabled=True, email_address="soc@example.com",
                    alert_on_high=True, alert_on_medium=False, alert_on_low=False, alert_on_block=True)

    notifier = AlertNotifier()
    notifier.enqueue(await make_event(SeverityLevel.HIGH, attack="DDoS"))
    notifier.enqueue(await make_event(SeverityLevel.MEDIUM, attack="Bot"))          # filtered out
    notifier.enqueue(await make_event(SeverityLevel.LOW, ActionTaken.BLOCKED, "SSH-Bruteforce"))  # blocked -> kept
    assert await notifier.flush() == 2

    # one email: every non-admin registered user + the extra address — never the admin
    assert len(sent) == 1
    [mail] = sent
    assert mail["to"] == ["analyst@example.com", "soc@example.com"]
    assert all("admin@example.com" not in m["to"] for m in sent)
    assert mail["subject"].startswith("[SecureNet] Abnormal traffic detected - most likely ")
    assert "(2 alerts)" in mail["subject"]
    assert not mail["subject"].startswith("[SecureNet Admin]")
    assert "2 alerts" in mail["html"] and "Bot" not in mail["text"]
    assert "full report is attached" in mail["text"]
    assert "+919000000001" not in mail["text"]          # users don't see other users' details

    [report] = mail["attachments"]
    assert report.filename.startswith("SecureNet-incident-report-") and report.filename.endswith(".txt")
    body = report.content.decode("utf-8")
    assert "Abnormal traffic : 2 incident(s)" in body and "DDoS" in body and "SSH-Bruteforce" in body and "Bot" not in body


async def test_admin_never_gets_attack_emails(client, captured_otps, sent):
    """Only an admin registered (or the extra address is the admin's): nobody to email."""
    await register(client, captured_otps, email="admin@example.com")
    await set_prefs(email_enabled=True, email_address="ADMIN@example.com",
                    alert_on_high=True, alert_on_medium=True, alert_on_low=True)
    notifier = AlertNotifier()
    notifier.enqueue(await make_event(SeverityLevel.HIGH, attack="DDoS"))
    assert await notifier.flush() == 0
    assert sent == []


async def test_every_attack_is_emailed_by_default(client, captured_otps, sent):
    await register(client, captured_otps, email="admin@example.com")       # first = admin (no attack mails)
    await register(client, captured_otps, email="user@example.com")
    await set_prefs()  # defaults: email on, high + medium + low
    notifier = AlertNotifier()
    for severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW):
        notifier.enqueue(await make_event(severity, attack=f"Attack-{severity.value}"))
    assert await notifier.flush() == 3
    assert "Abnormal traffic : 3 incident(s)" in sent[0]["attachments"][0].content.decode("utf-8")


async def test_no_email_when_alerts_disabled(client, captured_otps, sent):
    await register(client, captured_otps)
    await set_prefs(email_enabled=False)
    notifier = AlertNotifier()
    notifier.enqueue(await make_event())
    assert await notifier.flush() == 0
    assert sent == []


async def test_html_is_escaped(client, captured_otps, sent):
    await register(client, captured_otps)                                   # admin
    await register(client, captured_otps, email="user@example.com")
    await set_prefs(email_enabled=True, alert_on_high=True)
    notifier = AlertNotifier()
    notifier.enqueue(await make_event(attack="<script>x</script>"))
    await notifier.flush()
    assert "<script>" not in sent[0]["html"] and "&lt;script&gt;" in sent[0]["html"]


async def test_ids_alert_is_queued_for_email(monkeypatch):
    from app.ml.detector import Detection
    from app.ml.ids_service import IDSService
    from tests.test_ids import FakeDetector, make_flow

    queued = []
    monkeypatch.setattr("app.ml.ids_service.get_notifier",
                        lambda: type("N", (), {"enqueue": staticmethod(queued.append)})())
    ids = IDSService()
    ids.detector = FakeDetector(Detection(0.95, True, "DDoS", 0.99))
    event = await ids.process_flow(make_flow())
    assert queued == [event]


async def test_notification_feed_and_status(client, admin):
    _, headers = admin
    await make_event(attack="DDoS")
    r = await client.get("/api/notifications?limit=5", headers=headers)
    assert r.status_code == 200
    item = r.json()[0]
    assert item["attackType"] == "DDoS" and item["timestamp"].endswith("Z") and "DDoS" in item["message"]

    await set_prefs(email_enabled=True, email_address="extra@example.com")
    r = await client.get("/api/notifications/status", headers=headers)
    status = r.json()
    assert status["emailDelivery"] == "disabled"          # EMAIL_ENABLED=false in tests
    assert status["emailAlertsEnabled"] is True
    assert status["recipients"] == ["extra@example.com"]          # never the admin


async def test_test_email_endpoint(client, admin, monkeypatch):
    _, headers = admin
    r = await client.post("/api/notifications/test-email", headers=headers)
    assert r.status_code == 400 and "EMAIL_ENABLED" in r.json()["message"]

    sent = []

    async def fake_send(recipients, subject, text, html):
        sent.append(list(recipients))

    monkeypatch.setattr("app.api.routes.notifications.email_delivery_status", lambda: "enabled")
    monkeypatch.setattr("app.api.routes.notifications.send_email", fake_send)
    r = await client.post("/api/notifications/test-email", headers=headers)
    assert r.status_code == 200, r.text
    assert sent == [["admin@example.com"]]
    r = await client.post("/api/notifications/test-email", headers=headers)
    assert r.status_code == 429  # cooldown


# ── email only on normal -> abnormal, then at most every 5 minutes ─────────

class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


async def test_attack_emails_are_spaced_five_minutes_apart(client, captured_otps, sent, monkeypatch):
    from app.core.config import settings
    from app.services import notifier as module

    clock = Clock()
    monkeypatch.setattr(module.time, "monotonic", clock)
    await register(client, captured_otps, email="admin@example.com")
    await register(client, captured_otps, email="user@example.com")
    await set_prefs()
    notifier = AlertNotifier()
    interval = settings.ALERT_EMAIL_INTERVAL_SECONDS
    assert interval == 300

    # normal -> abnormal: emailed after the short batch window
    notifier.enqueue(await make_event(SeverityLevel.HIGH, attack="DDoS"))
    assert notifier.seconds_until_next_email() == settings.ALERT_EMAIL_BATCH_SECONDS
    assert await notifier.flush() == 1
    assert sent[-1]["subject"].startswith("[SecureNet] Abnormal traffic detected")

    # still abnormal a few seconds later: many alerts wait for ONE email 5 min after the last
    for _ in range(20):
        clock.t += 3
        notifier.enqueue(await make_event(SeverityLevel.HIGH, attack="DDoS"))
    assert notifier.seconds_until_next_email() == pytest.approx(interval - 60)
    clock.t = 1000.0 + interval
    assert notifier.seconds_until_next_email() == 0
    assert await notifier.flush() == 20
    assert len(sent) == 2 and "Abnormal traffic continues - 20 alerts" in sent[-1]["subject"]
    assert "still detecting abnormal traffic" in sent[-1]["text"]

    # 5 quiet minutes = normal again; the next alert is a new episode
    clock.t += interval + 1
    notifier.enqueue(await make_event(SeverityLevel.MEDIUM, attack="Bot"))
    assert notifier.seconds_until_next_email() == settings.ALERT_EMAIL_BATCH_SECONDS
    assert await notifier.flush() == 1
    assert "Abnormal traffic detected" in sent[-1]["subject"]


async def test_alert_email_is_short_and_carries_the_printable_report(client, captured_otps, sent):
    await register(client, captured_otps, email="admin@example.com")
    await register(client, captured_otps, email="user@example.com")
    await set_prefs()
    notifier = AlertNotifier()
    for i in range(30):
        notifier.enqueue(await make_event(SeverityLevel.HIGH if i % 3 else SeverityLevel.MEDIUM,
                                          attack="DDoS" if i < 25 else "Bot"))
    assert await notifier.flush() == 30
    [mail] = sent
    text = mail["text"]
    assert "Most likely attack : DDoS (in 25 of 30 alerts)" in text
    assert "30 alerts (20 high · 10 medium)" in text
    assert "Open SecureNet" in mail["html"] and "full report is attached" in mail["html"]
    assert len(text.splitlines()) < 20                     # a summary, not a dump of 30 alerts
    assert "203.0.113.7:50000" not in text                  # per-alert details live in the report
    [report] = mail["attachments"]
    body = report.content.decode("utf-8")
    assert "Abnormal traffic : 30 incident(s)" in body and body.count("Event ID") == 30
    assert "203.0.113.7:50000" in body


async def test_shutdown_does_not_break_the_five_minutes(client, captured_otps, sent):
    await register(client, captured_otps, email="admin@example.com")
    await register(client, captured_otps, email="user@example.com")
    await set_prefs()
    notifier = AlertNotifier()
    notifier.enqueue(await make_event(SeverityLevel.HIGH, attack="DDoS"))
    await notifier.flush()
    notifier.enqueue(await make_event(SeverityLevel.HIGH, attack="DDoS"))
    await notifier.stop()                                   # a minute later the computer shuts down
    assert len(sent) == 1
