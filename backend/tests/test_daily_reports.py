"""Daily reports (Reports page): empty until attacks happen, one box per local day, downloads."""

from datetime import datetime

from app.db.base import AsyncSessionLocal
from app.models.security_event import (
    ActionTaken, DetectionMode, EventState, Protocol, SecurityEvent, SeverityLevel,
)


async def add_event(ts: datetime, severity=SeverityLevel.HIGH, attack="DDoS", src="203.0.113.9"):
    async with AsyncSessionLocal() as db:
        db.add(SecurityEvent(
            timestamp=ts, source_ip=src, source_port=40000, destination_ip="192.168.1.10",
            destination_port=443, protocol=Protocol.TCP, anomaly_score=0.91, severity=severity,
            attack_type=attack, confidence=0.9, mode=DetectionMode.MONITOR, state=EventState.ACTIVE,
            action_taken=ActionTaken.ALERTED, detection_reason="unit test",
            contributing_features=[{"name": "Flow Bytes/s", "value": 4.2, "contribution": 4.2}],
        ))
        await db.commit()


async def test_no_attacks_means_no_reports(client, admin):
    _, headers = admin
    r = await client.get("/api/reports/daily?tzOffset=330", headers=headers)
    assert r.status_code == 200 and r.json() == []


async def test_daily_reports_group_by_local_day(client, admin):
    _, headers = admin
    # 19:00 UTC on the 24th is 00:30 on the 25th in India (UTC+05:30)
    await add_event(datetime(2026, 9, 24, 19, 0), SeverityLevel.HIGH, "DDoS", "203.0.113.9")
    await add_event(datetime(2026, 9, 25, 8, 0), SeverityLevel.MEDIUM, "DDoS", "198.51.100.4")
    await add_event(datetime(2026, 9, 24, 10, 0), SeverityLevel.LOW, "PortScan", "203.0.113.9")

    r = await client.get("/api/reports/daily?tzOffset=330", headers=headers)
    days = r.json()
    assert [d["date"] for d in days] == ["2026-09-25", "2026-09-24"]           # newest first
    today = days[0]
    assert today["total"] == 2 and today["high"] == 1 and today["medium"] == 1 and today["low"] == 0
    assert today["topAttack"] == "DDoS" and today["sources"] == 2
    assert today["firstSeen"].endswith("Z")

    # same data in UTC: the first event belongs to the 24th
    utc_days = (await client.get("/api/reports/daily?tzOffset=0", headers=headers)).json()
    assert {d["date"]: d["total"] for d in utc_days} == {"2026-09-25": 1, "2026-09-24": 2}


async def test_daily_report_downloads(client, admin):
    _, headers = admin
    await add_event(datetime(2026, 9, 25, 8, 0), SeverityLevel.HIGH, "DDoS-LOIC-HTTP")

    r = await client.get("/api/reports/daily/2026-09-25/download?format=txt&tzOffset=330", headers=headers)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert 'filename="SecureNet-daily-report-2026-09-25.txt"' in r.headers["content-disposition"]
    text = r.text
    assert "Daily report - 25 Sep 2026" in text and "UTC+05:30" in text
    assert "Abnormal traffic : 1 incident(s)" in text and "DDoS-LOIC-HTTP" in text
    assert "25 Sep 2026, 13:30:00" in text                    # 08:00 UTC shown in local time
    assert "Unusual features: Flow Bytes/s" in text

    csv = await client.get("/api/reports/daily/2026-09-25/download?format=csv&tzOffset=330", headers=headers)
    assert csv.status_code == 200 and "DDoS-LOIC-HTTP" in csv.content.decode("utf-8-sig")
    pdf = await client.get("/api/reports/daily/2026-09-25/download?format=pdf&tzOffset=330", headers=headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")

    empty = await client.get("/api/reports/daily/2026-09-20/download?format=txt&tzOffset=330", headers=headers)
    assert empty.status_code == 404
    bad = await client.get("/api/reports/daily/2026-09-25/download?format=exe", headers=headers)
    assert bad.status_code == 422


async def test_viewers_can_download_reports(client, admin, captured_otps):
    from tests.conftest import register
    viewer = await register(client, captured_otps, email="viewer@example.com")
    headers = {"Authorization": f"Bearer {viewer['tokens']['accessToken']}"}
    await add_event(datetime(2026, 9, 25, 8, 0))
    assert (await client.get("/api/reports/daily?tzOffset=330", headers=headers)).status_code == 200
    r = await client.get("/api/reports/daily/2026-09-25/download?format=txt&tzOffset=330", headers=headers)
    assert r.status_code == 200


async def test_ids_is_on_off_only(client, admin, monkeypatch):
    """Asking for the old protection mode still runs detect-and-alert (no blocking)."""
    from app.ml import network_monitor
    from app.ml.ids_service import get_ids_service

    _, headers = admin
    ids = get_ids_service()
    started = {}

    async def fake_start(mode=None):
        started["mode"] = mode

    monkeypatch.setattr(ids, "start", fake_start)
    monkeypatch.setattr(network_monitor, "check_capture_available", lambda *a, **k: None)
    r = await client.post("/api/ids/control", json={"enabled": True, "mode": "protect"}, headers=headers)
    assert r.status_code == 200, r.text
    assert started["mode"] == "monitor"
