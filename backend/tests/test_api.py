"""Settings, whitelist, events, reports and dashboard API tests."""

from datetime import timedelta

from app.db.base import AsyncSessionLocal
from app.models.security_event import (
    ActionTaken, DetectionMode, EventState, Protocol, SecurityEvent, SeverityLevel,
)
from app.utils.timeutil import utcnow
from tests.conftest import register


async def seed_events(n: int = 25):
    async with AsyncSessionLocal() as db:
        for i in range(n):
            db.add(SecurityEvent(
                timestamp=utcnow() - timedelta(minutes=i),
                source_ip=f"10.0.0.{i % 5}",
                source_port=40000 + i,
                destination_ip="192.168.1.10",
                destination_port=22 if i % 2 else 80,
                protocol=Protocol.TCP if i % 3 else Protocol.UDP,
                anomaly_score=0.5 + (i % 10) / 20,
                severity=[SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH][i % 3],
                attack_type="DDoS" if i % 2 else None,
                confidence=0.9 if i % 2 else None,
                mode=DetectionMode.MONITOR,
                state=EventState.ACTIVE,
                action_taken=ActionTaken.ALERTED,
                detection_reason="test",
                contributing_features=[{"name": "Flow Duration", "value": 1.0, "contribution": 0.5}],
            ))
        await db.commit()


async def test_settings_update_persists(client, admin):
    _, headers = admin
    r = await client.put("/api/settings/detection", headers=headers,
                         json={"anomalyThreshold": 0.65, "stage2Enabled": False})
    assert r.status_code == 200, r.text
    r = await client.get("/api/settings", headers=headers)
    detection = r.json()["detection"]
    assert detection["anomalyThreshold"] == 0.65
    assert detection["stage2Enabled"] is False

    r = await client.put("/api/settings/protection", headers=headers,
                         json={"mode": "protect", "autoBlock": True, "autoBlockSeverities": ["high", "medium"]})
    assert r.status_code == 200, r.text
    assert r.json()["autoBlockSeverities"] == ["high", "medium"]


async def test_viewer_cannot_change_settings(client, admin, captured_otps):
    viewer = await register(client, captured_otps, email="v@example.com")
    headers = {"Authorization": f"Bearer {viewer['tokens']['accessToken']}"}
    r = await client.put("/api/settings/detection", headers=headers, json={"anomalyThreshold": 0.9})
    assert r.status_code == 403
    r = await client.get("/api/settings/detection", headers=headers)
    assert r.status_code == 200


async def test_securenet_user_can_switch_ids_but_nothing_else(client, admin, captured_otps, monkeypatch):
    """Two roles: the admin configures; a SecureNet user may only turn the IDS on/off."""
    from app.db.base import AsyncSessionLocal
    from app.ml import network_monitor
    from app.ml.ids_service import get_ids_service
    from app.models.user import User, UserRole
    from sqlalchemy import update

    user = await register(client, captured_otps, email="user@example.com")
    headers = {"Authorization": f"Bearer {user['tokens']['accessToken']}"}

    ids = get_ids_service()
    calls = []

    async def fake_start(mode=None):
        calls.append(("start", mode))

    async def fake_stop():
        calls.append(("stop", None))

    monkeypatch.setattr(ids, "start", fake_start)
    monkeypatch.setattr(ids, "stop", fake_stop)
    monkeypatch.setattr(network_monitor, "check_capture_available", lambda *a, **k: None)
    r = await client.post("/api/ids/control", headers=headers, json={"enabled": True})
    assert r.status_code == 200 and calls == [("start", "monitor")]

    denied = [
        client.put("/api/settings/detection", headers=headers, json={"anomalyThreshold": 0.9}),
        client.put("/api/settings/notifications", headers=headers, json={"alertOnLow": False}),
        client.post("/api/settings/whitelist", headers=headers, json={"type": "ip", "value": "10.0.0.1"}),
        client.post("/api/model/reload", headers=headers),
        client.post(f"/api/events/{'0' * 8}-0000-0000-0000-{'0' * 12}/resolve", headers=headers),
    ]
    for request in denied:
        r = await request
        assert r.status_code == 403 and r.json()["message"] == "Only the SecureNet admin can do this."

    # a legacy "analyst" account is a SecureNet user too
    async with AsyncSessionLocal() as db:
        await db.execute(update(User).where(User.email == "user@example.com").values(role=UserRole.ANALYST))
        await db.commit()
    r = await client.put("/api/settings/detection", headers=headers, json={"anomalyThreshold": 0.9})
    assert r.status_code == 403


async def test_whitelist_crud(client, admin):
    _, headers = admin
    r = await client.post("/api/settings/whitelist", headers=headers,
                          json={"type": "cidr", "value": "10.1.2.3/24", "description": "lab"})
    assert r.status_code == 200, r.text
    entry = r.json()
    assert entry["value"] == "10.1.2.0/24" and entry["createdAt"].endswith("Z")

    r = await client.post("/api/settings/whitelist", headers=headers, json={"type": "ip", "value": "not-an-ip"})
    assert r.status_code == 422

    r = await client.get("/api/settings/whitelist", headers=headers)
    assert [e["id"] for e in r.json()] == [entry["id"]]
    r = await client.delete(f"/api/settings/whitelist/{entry['id']}", headers=headers)
    assert r.status_code == 200


async def test_events_pagination_sort_and_dates(client, admin):
    _, headers = admin
    await seed_events(25)
    r = await client.get("/api/events?page=2&pageSize=10&sortBy=anomalyScore&sortOrder=asc", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 25 and body["totalPages"] == 3 and body["pageSize"] == 10
    scores = [e["anomalyScore"] for e in body["data"]]
    assert scores == sorted(scores)
    assert body["data"][0]["contributingFeatures"][0]["name"] == "Flow Duration"

    since = (utcnow() - timedelta(minutes=4, seconds=30)).isoformat() + "Z"
    r = await client.get(f"/api/events?from={since}", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 5

    r = await client.get("/api/events?sortBy=metadata", headers=headers)
    assert r.status_code == 400


async def test_event_export_and_resolve(client, admin):
    _, headers = admin
    await seed_events(3)
    r = await client.get("/api/events/export?format=csv&severity=high", headers=headers)
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert r.content.decode("utf-8-sig").splitlines()[0].startswith("ID,")

    r = await client.get("/api/events/export?format=pdf", headers=headers)
    assert r.status_code == 200 and r.content[:4] == b"%PDF"

    event_id = (await client.get("/api/events", headers=headers)).json()["data"][0]["id"]
    r = await client.post(f"/api/events/{event_id}/resolve", headers=headers)
    assert r.status_code == 200
    r = await client.get(f"/api/events/{event_id}", headers=headers)
    assert r.json()["state"] == "resolved"


async def test_legacy_saved_report_endpoints_are_gone(client, admin):
    """Only the daily reports remain; nobody can write report files to the server any more."""
    _, headers = admin
    some_id = "00000000-0000-0000-0000-000000000000"
    for method, url in (("POST", "/api/reports"), ("GET", "/api/reports"), ("GET", "/api/reports/summary"),
                        ("GET", f"/api/reports/{some_id}/download"), ("DELETE", f"/api/reports/{some_id}")):
        r = await client.request(method, url, headers=headers, json={} if method == "POST" else None)
        assert r.status_code in (404, 405), (method, url, r.status_code)


async def test_huge_page_number_is_refused_cleanly(client, admin):
    _, headers = admin
    r = await client.get("/api/events", headers=headers, params={"page": 10**20})
    assert r.status_code == 422 and r.json()["code"] == "VALIDATION_ERROR"


async def test_dashboard_shows_history_when_ids_off(client, admin):
    _, headers = admin
    await seed_events(9)
    r = await client.get("/api/dashboard/summary", headers=headers)
    assert r.status_code == 200
    s = r.json()
    assert s["anomaliesLastHour"] == 9
    assert s["severityBreakdown"] == {"low": 3, "medium": 3, "high": 3}
    assert len(s["recentEvents"]) == 9
    r = await client.get("/api/dashboard/top-sources?limit=3", headers=headers)
    assert r.status_code == 200 and len(r.json()) == 3
    r = await client.get("/api/dashboard/protocol-distribution", headers=headers)
    assert r.json()["totalFlows"] == 9
    r = await client.get("/api/dashboard/host-status", headers=headers)
    assert r.status_code == 200 and r.json()["hostname"]
