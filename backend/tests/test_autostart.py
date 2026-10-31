"""IDS stays on across a shutdown: saved state, Windows start-up entry, resume + one desktop notice."""

import sys

import pytest

from app.core.config import settings
from app.ml import ids_service as ids_module
from app.ml.ids_service import get_ids_service
from app.ml.network_monitor import CaptureUnavailable
from app.services import autostart


class FakeMonitor:
    def __init__(self, **kwargs):
        self.running = False
        self.packet_count = self.active_flow_count = 0
        self.last_error = None

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


@pytest.fixture
async def capture(monkeypatch):
    """Packet capture that works (no Npcap needed) + recorded desktop notices."""
    monkeypatch.setattr(ids_module, "NetworkMonitor", FakeMonitor)
    notices = []

    async def fake_notify(title, message):
        notices.append((title, message))
        return True

    monkeypatch.setattr(autostart, "notify_desktop", fake_notify)
    monkeypatch.setattr(autostart, "RESUME_RETRY_SECONDS", 0)
    settings.ids_state_file.unlink(missing_ok=True)
    yield notices
    ids = get_ids_service()
    if ids.enabled:
        await ids.stop()
    ids.started_by = None


async def test_turning_on_is_remembered_and_off_forgets(client, admin, capture):
    _, headers = admin
    r = await client.post("/api/ids/control", headers=headers, json={"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    state = autostart.load_state()
    assert state["enabled"] is True and state["startedBy"]["email"] == "admin@example.com"
    if sys.platform == "win32":
        assert autostart.shortcut_path().is_file()          # temp "Startup" folder in tests
        assert autostart.shortcut_path().parent == settings.resolve_path(settings.IDS_STARTUP_DIR)

    r = await client.post("/api/ids/control", headers=headers, json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert autostart.load_state()["enabled"] is False
    assert not autostart.shortcut_path().exists()
    assert capture == []                                      # manual on/off: no desktop notice


async def test_failed_start_is_not_remembered(client, admin, capture, monkeypatch):
    _, headers = admin

    class NoCapture(FakeMonitor):
        def start(self):
            raise CaptureUnavailable("needs a one-time setup")

    monkeypatch.setattr(ids_module, "NetworkMonitor", NoCapture)
    r = await client.post("/api/ids/control", headers=headers, json={"enabled": True})
    assert r.status_code == 503
    assert autostart.load_state().get("enabled") is not True


async def test_off_clears_a_saved_on_even_when_not_running(client, admin, capture):
    _, headers = admin
    autostart.save_state(True, {"email": "x@example.com"})
    r = await client.post("/api/ids/control", headers=headers, json={"enabled": False})
    assert r.status_code == 200
    assert autostart.load_state()["enabled"] is False


async def test_server_shutdown_keeps_the_saved_choice(capture):
    ids = get_ids_service()
    autostart.save_state(True, {"email": "a@example.com"})
    await ids.start("monitor")
    await ids.stop()                       # what the server does when Windows shuts down
    assert autostart.load_state()["enabled"] is True


async def test_resume_after_restart_turns_ids_on_with_one_notice(capture):
    who = {"name": "Admin", "email": "admin@example.com", "phone": None, "role": "admin"}
    autostart.save_state(True, who)
    assert await autostart.resume_after_restart() is True
    ids = get_ids_service()
    assert ids.enabled and ids.started_by == who
    assert capture == [("SecureNet", "SecureNet is on and is monitoring.")]


async def test_no_resume_when_it_was_off(capture):
    autostart.save_state(False)
    assert await autostart.resume_after_restart() is False
    assert not get_ids_service().enabled and capture == []


async def test_resume_retries_until_the_database_is_reachable(capture, monkeypatch):
    ids = get_ids_service()
    real_start, calls = ids.start, []

    async def flaky_start(mode=None):
        calls.append(mode)
        if len(calls) < 3:
            raise OSError("network is not up yet")
        await real_start(mode)

    monkeypatch.setattr(ids, "start", flaky_start)
    autostart.save_state(True, None)
    assert await autostart.resume_after_restart() is True
    assert len(calls) == 3 and len(capture) == 1


async def test_resume_without_capture_shows_a_plain_notice(capture, monkeypatch):
    class NoCapture(FakeMonitor):
        def start(self):
            raise CaptureUnavailable("needs a one-time setup")

    monkeypatch.setattr(ids_module, "NetworkMonitor", NoCapture)
    autostart.save_state(True, None)
    assert await autostart.resume_after_restart() is False
    assert not get_ids_service().enabled
    assert len(capture) == 1 and capture[0][0] == autostart.FAILED_TITLE


async def test_ids_turns_on_when_securenet_starts(capture, monkeypatch):
    """IDS_ON_AT_STARTUP: live monitoring as soon as the backend starts, even if nothing was saved."""
    monkeypatch.setattr(settings, "IDS_ON_AT_STARTUP", True)
    assert autostart.load_state() == {}
    assert await autostart.resume_after_restart() is True
    assert get_ids_service().enabled
    assert capture == [("SecureNet", "SecureNet is on and is monitoring.")]
    assert autostart.load_state()["enabled"] is True          # and again after a computer restart


async def test_switching_off_during_startup_wins(capture, monkeypatch):
    monkeypatch.setattr(settings, "IDS_ON_AT_STARTUP", True)
    real_start, calls = get_ids_service().start, []

    async def slow_start(mode=None):
        calls.append(mode)
        if len(calls) == 1:
            autostart.save_state(False)                      # the user presses OFF meanwhile
            raise OSError("database not ready yet")
        await real_start(mode)

    monkeypatch.setattr(get_ids_service(), "start", slow_start)
    assert await autostart.resume_after_restart() is False
    assert not get_ids_service().enabled and capture == []
