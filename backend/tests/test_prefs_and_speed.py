"""Per-user alert-email switch, and the caches that keep the dashboard fast
(signed-in user remembered, dashboard answers cached until events change)."""

import contextlib

from sqlalchemy import event

from app.db.base import AsyncSessionLocal, engine
from app.ml.detector import Detection
from app.ml.ids_service import IDSService
from app.services.notifier import get_recipients
from tests.conftest import register
from tests.test_ids import FakeDetector, make_flow


@contextlib.contextmanager
def count_queries():
    counter = {"n": 0}

    def on_execute(*args, **kwargs):
        counter["n"] += 1

    event.listen(engine.sync_engine, "before_cursor_execute", on_execute)
    try:
        yield counter
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", on_execute)


async def test_each_user_can_switch_alert_emails_off_and_on(client, captured_otps):
    admin = await register(client, captured_otps, email="boss@example.com")
    user = await register(client, captured_otps, email="worker@example.com")
    h = {"Authorization": f"Bearer {user['tokens']['accessToken']}"}
    assert user["user"]["emailAlerts"] is True                      # on by default

    r = await client.put("/api/auth/me/preferences", headers=h, json={"emailAlerts": False})
    assert r.status_code == 200 and r.json()["emailAlerts"] is False
    assert (await client.get("/api/auth/me", headers=h)).json()["emailAlerts"] is False   # not a stale cached copy
    async with AsyncSessionLocal() as db:
        everyone = await get_recipients(db, None)
    assert everyone == []                                           # admin never gets attack emails

    r = await client.put("/api/auth/me/preferences", headers=h, json={"emailAlerts": True})
    assert r.json()["emailAlerts"] is True
    async with AsyncSessionLocal() as db:
        users = await get_recipients(db, None)
    assert users == ["worker@example.com"]

    assert (await client.put("/api/auth/me/preferences", json={"emailAlerts": False})).status_code == 401
    assert admin["user"]["role"] == "admin"


async def test_repeat_requests_do_not_touch_the_database(client, admin):
    _, headers = admin
    for url in ("/api/ids/status", "/api/auth/me", "/api/dashboard/summary", "/api/dashboard/protocol-distribution",
                "/api/dashboard/top-sources?limit=5", "/api/settings/detection", "/api/notifications"):
        await client.get(url, headers=headers)              # first time: loads
        with count_queries() as q:
            r = await client.get(url, headers=headers)      # again: remembered
        assert r.status_code == 200 and q["n"] == 0, (url, q["n"])


async def test_dashboard_summary_needs_three_queries_and_updates_on_new_events(client, admin):
    _, headers = admin
    await client.get("/api/auth/me", headers=headers)              # the signed-in user is now remembered
    with count_queries() as q:
        first = (await client.get("/api/dashboard/summary", headers=headers)).json()
    assert q["n"] == 3 and first["anomaliesLastHour"] == 0           # was 8 separate queries

    ids = IDSService()
    ids.detector = FakeDetector(Detection(0.95, True, "DDoS", 0.99))
    stored = await ids.process_flow(make_flow())                    # a new attack is stored
    after = (await client.get("/api/dashboard/summary", headers=headers)).json()
    assert after["anomaliesLastHour"] == 1 and after["highSeverityCount"] == 1
    assert (await client.get("/api/notifications", headers=headers)).json()[0]["eventId"] == str(stored.id)

    r = await client.post(f"/api/events/{stored.id}/resolve", headers=headers)
    assert r.status_code == 200
    resolved = (await client.get("/api/dashboard/summary", headers=headers)).json()
    assert resolved["highSeverityCount"] == 0                        # resolving refreshes it too


async def test_settings_change_refreshes_cached_settings(client, admin):
    _, headers = admin
    assert (await client.get("/api/settings/detection", headers=headers)).json()["anomalyThreshold"] == 0.5
    await client.put("/api/settings/detection", headers=headers, json={"anomalyThreshold": 0.7})
    assert (await client.get("/api/settings/detection", headers=headers)).json()["anomalyThreshold"] == 0.7


async def test_expired_user_is_rechecked_in_the_background(client, captured_otps):
    import asyncio

    from sqlalchemy import select

    from app.api import dependencies
    from app.models.user import User

    auth = await register(client, captured_otps, email="leaver@example.com")
    headers = {"Authorization": f"Bearer {auth['tokens']['accessToken']}"}
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 200
    user_id = next(iter(dependencies._user_cache))
    expires, user = dependencies._user_cache[user_id]
    dependencies._user_cache[user_id] = (expires - dependencies.USER_CACHE_SECONDS - 1, user)   # a minute passed
    async with AsyncSessionLocal() as db:
        await db.delete((await db.execute(select(User).where(User.email == "leaver@example.com"))).scalar_one())
        await db.commit()
    # answered at once from memory while the account is re-checked ...
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 200
    await asyncio.gather(*dependencies._user_loading.values(), return_exceptions=True)
    # ... and refused from the next request on
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 401


async def test_history_and_recipients_are_never_stale(client, captured_otps):
    admin = await register(client, captured_otps, email="boss2@example.com")
    user = await register(client, captured_otps, email="worker2@example.com")
    ha = {"Authorization": f"Bearer {admin['tokens']['accessToken']}"}
    hu = {"Authorization": f"Bearer {user['tokens']['accessToken']}"}
    assert (await client.get("/api/events", headers=ha)).json()["total"] == 0
    assert (await client.get("/api/notifications/status", headers=ha)).json()["recipientCount"] == 1   # the user, not the admin
    await client.get("/api/settings", headers=ha)      # first load (creates the settings rows here)
    with count_queries() as q:
        await client.get("/api/events", headers=ha)
        await client.get("/api/notifications/status", headers=ha)
        await client.get("/api/settings", headers=ha)
        await client.get("/api/settings/whitelist", headers=ha)
        await client.get("/api/settings/whitelist", headers=ha)
    assert q["n"] <= 1                                  # only the first whitelist read; the rest from memory

    ids = IDSService()
    ids.detector = FakeDetector(Detection(0.95, True, "DDoS", 0.99))
    await ids.process_flow(make_flow())
    assert (await client.get("/api/events", headers=ha)).json()["total"] == 1      # new event shows at once

    await client.put("/api/auth/me/preferences", headers=hu, json={"emailAlerts": False})
    assert (await client.get("/api/notifications/status", headers=ha)).json()["recipientCount"] == 0
