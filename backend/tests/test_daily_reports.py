"""Reports page: one report per finished 6-hour window that had attacks; downloads."""

from datetime import datetime

import pytest

from app.db.base import AsyncSessionLocal
from app.models.security_event import (
    ActionTaken, DetectionMode, EventState, Protocol, SecurityEvent, SeverityLevel,
)
from app.utils.timeutil import utcnow


async def add_event(ts: datetime, severity=SeverityLevel.HIGH, attack="DDoS", src="203.0.113.9", owner=None):
    import uuid as _uuid
    from app.ml.ids_service import get_ids_service
    if owner is None:                                   # default: the account that is "logged in"
        oid = get_ids_service().active_owner_id
        owner = _uuid.UUID(oid) if oid else None
    async with AsyncSessionLocal() as db:
        db.add(SecurityEvent(
            timestamp=ts, owner_id=owner, source_ip=src, source_port=40000, destination_ip="192.168.1.10",
            destination_port=443, protocol=Protocol.TCP, anomaly_score=0.91, severity=severity,
            attack_type=attack, confidence=0.9, mode=DetectionMode.MONITOR, state=EventState.ACTIVE,
            action_taken=ActionTaken.ALERTED, detection_reason="unit test",
            contributing_features=[{"name": "Flow Bytes/s", "value": 4.2, "contribution": 4.2}],
        ))
        await db.commit()


async def test_no_attacks_means_no_reports(client, admin):
    _, headers = admin
    r = await client.get("/api/reports/windows?tzOffset=330", headers=headers)
    assert r.status_code == 200 and r.json() == []


async def test_windows_group_by_6_hours(client, admin):
    _, headers = admin
    # tzOffset=330 (India +05:30): UTC 01:00 -> local 06:30 and UTC 03:00 -> local 08:30 (both the
    # 6am-12pm window); UTC 08:00 -> local 13:30 (the 12pm-6pm window). All on 2026-09-25 (long past).
    await add_event(datetime(2026, 9, 25, 1, 0), SeverityLevel.MEDIUM, "DDoS", "198.51.100.4")
    await add_event(datetime(2026, 9, 25, 3, 0), SeverityLevel.LOW, "DDoS", "203.0.113.9")
    await add_event(datetime(2026, 9, 25, 8, 0), SeverityLevel.HIGH, "DDoS", "203.0.113.9")

    wins = (await client.get("/api/reports/windows?tzOffset=330", headers=headers)).json()
    assert [w["key"] for w in wins] == ["2026-09-25T12", "2026-09-25T06"]      # newest window first
    assert wins[0]["rangeLabel"] == "12:00 pm - 6:00 pm" and wins[0]["total"] == 1 and wins[0]["high"] == 1
    w6 = wins[1]
    assert w6["rangeLabel"] == "6:00 am - 12:00 pm" and w6["total"] == 2
    assert w6["medium"] == 1 and w6["low"] == 1 and w6["sources"] == 2
    assert w6["topAttack"] == "DDoS" and w6["firstSeen"].endswith("Z")


async def test_window_in_progress_is_not_reported(client, admin):
    """A report is only made AFTER the 6-hour window ends: an attack in the current window shows nothing."""
    _, headers = admin
    await add_event(utcnow())                           # happening right now -> window not finished
    assert (await client.get("/api/reports/windows?tzOffset=330", headers=headers)).json() == []


async def test_window_report_download(client, admin):
    _, headers = admin
    await add_event(datetime(2026, 9, 25, 8, 0), SeverityLevel.HIGH, "DDoS-LOIC-HTTP")   # window 2026-09-25T12

    r = await client.get("/api/reports/windows/2026-09-25T12/download?format=txt&tzOffset=330", headers=headers)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert 'filename="SecureNet-report-2026-09-25T12.txt"' in r.headers["content-disposition"]
    text = r.text
    assert "Report - 25 Sep 2026, 12:00 pm - 6:00 pm" in text
    assert "DDoS-LOIC-HTTP" in text
    assert "25 Sep 2026, 13:30:00" in text                    # 08:00 UTC shown in local time
    assert "Unusual features: Flow Bytes/s" in text

    pdf = await client.get("/api/reports/windows/2026-09-25T12/download?format=pdf&tzOffset=330", headers=headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")

    # a window with no attacks -> 404; a bad key -> 400; an unknown format -> 422
    empty = await client.get("/api/reports/windows/2026-09-25T00/download?format=txt&tzOffset=330", headers=headers)
    assert empty.status_code == 404
    assert (await client.get("/api/reports/windows/not-a-key/download?format=txt", headers=headers)).status_code == 400
    assert (await client.get("/api/reports/windows/2026-09-25T12/download?format=exe", headers=headers)).status_code == 422


async def test_viewers_can_download_reports(client, admin, captured_otps):
    from tests.conftest import register
    viewer = await register(client, captured_otps, email="viewer@example.com")
    headers = {"Authorization": f"Bearer {viewer['tokens']['accessToken']}"}
    await add_event(datetime(2026, 9, 25, 8, 0))         # owner defaults to the active owner (the viewer)
    assert (await client.get("/api/reports/windows?tzOffset=330", headers=headers)).status_code == 200
    r = await client.get("/api/reports/windows/2026-09-25T12/download?format=txt&tzOffset=330", headers=headers)
    assert r.status_code == 200


@pytest.mark.skip(reason="Advanced Protection / IPS is future work; project is IDS (detection) only.")
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
