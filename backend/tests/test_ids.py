"""IDS pipeline tests: feature extraction, detection loop, modes, model API."""

import pytest
from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.ml.detector import Detection
from app.ml.features import FEATURE_COLUMNS, Flow, FlowRecord, PacketInfo
from app.ml.ids_service import IDSService
from app.models.security_event import ActionTaken, SecurityEvent, SeverityLevel


def make_flow() -> FlowRecord:
    flow = Flow("203.0.113.5", "192.168.1.10", 51000, 22, 6, start=1000.0)
    flow.add(PacketInfo(1000.0, "203.0.113.5", "192.168.1.10", 51000, 22, 6, 0, 40, "S", 64240), True)
    flow.add(PacketInfo(1000.001, "192.168.1.10", "203.0.113.5", 22, 51000, 6, 0, 40, "SA", 65160), False)
    flow.add(PacketInfo(1000.002, "203.0.113.5", "192.168.1.10", 51000, 22, 6, 120, 32, "PA"), True)
    flow.add(PacketInfo(1007.002, "192.168.1.10", "203.0.113.5", 22, 51000, 6, 300, 32, "PA"), False)
    flow.add(PacketInfo(1007.003, "203.0.113.5", "192.168.1.10", 51000, 22, 6, 0, 32, "R"), True)
    assert flow.is_finished
    return FlowRecord.from_flow(flow)


def test_feature_extraction_units_and_columns():
    record = make_flow()
    f = record.features
    assert list(f) == FEATURE_COLUMNS                 # exact model column order
    assert f["Flow Duration"] == pytest.approx(7_003_000, rel=1e-6)   # microseconds
    assert f["Tot Fwd Pkts"] == 3 and f["Tot Bwd Pkts"] == 2
    assert f["TotLen Fwd Pkts"] == 120 and f["TotLen Bwd Pkts"] == 300
    assert f["Init Fwd Win Byts"] == 64240 and f["Init Bwd Win Byts"] == 65160
    assert f["Fwd PSH Flags"] == 1 and f["Fwd Act Data Pkts"] == 1
    assert f["Fwd Seg Size Min"] == 32
    assert f["Idle Max"] == pytest.approx(7_000_000, rel=1e-6)          # gap > 5 s activity timeout
    assert f["Protocol_6"] == 1.0
    assert record.duration_ms == 7003


class FakeDetector:
    loaded = True
    name = "fake"

    def __init__(self, detection):
        self.detection = detection

    def analyze(self, features, threshold, stage2_enabled, stage2_confidence):
        return self.detection


async def test_no_model_means_capture_only():
    ids = IDSService()
    assert ids.detector.loaded is False
    assert await ids.process_flow(make_flow()) is None
    assert ids.flows_analyzed == 1


async def test_alert_is_stored_with_flow_stats():
    ids = IDSService()
    ids.detector = FakeDetector(Detection(0.92, True, "Brute Force -SSH", 0.97, "test reason",
                                          [{"name": "Flow Duration", "value": 3.1, "contribution": 3.1}]))
    event = await ids.process_flow(make_flow())
    assert event is not None
    async with AsyncSessionLocal() as db:
        stored = (await db.execute(select(SecurityEvent))).scalars().one()
    assert stored.attack_type == "Brute Force -SSH"
    assert stored.severity == SeverityLevel.HIGH
    assert stored.action_taken == ActionTaken.ALERTED          # monitor mode never blocks
    assert stored.packets_sent == 3 and stored.bytes_received == 300
    assert stored.contributing_features[0]["name"] == "Flow Duration"
    assert ids.anomalies_detected == 1 and ids.attacks_detected == 1


async def test_whitelist_skips_detection():
    ids = IDSService()
    ids.detector = FakeDetector(Detection(0.99, True, "DDoS", 0.99))
    ids.config.wl_ports = {22}
    assert await ids.process_flow(make_flow()) is None


async def test_protect_mode_blocks_via_firewall(monkeypatch):
    ids = IDSService()
    ids.detector = FakeDetector(Detection(0.95, True, "DDoS", 0.99))
    await ids.set_mode("protect")
    ids.config.auto_block = True
    ids.config.auto_block_severities = {"high"}
    calls = []

    async def fake_block(ip, duration, max_blocked):
        calls.append(ip)
        return True, f"Blocked {ip}"

    monkeypatch.setattr(ids.blocker, "block", fake_block)
    event = await ids.process_flow(make_flow())
    assert calls == ["203.0.113.5"]
    assert event.action_taken == ActionTaken.BLOCKED


def test_blocker_never_blocks_local_addresses():
    from app.ml.protection import FirewallBlocker

    blocker = FirewallBlocker()
    assert blocker.is_protected("127.0.0.1")
    assert blocker.is_protected("::1")
    assert blocker.is_protected("not-an-ip")
    assert not blocker.is_protected("203.0.113.5")


async def test_ids_status_and_control_errors(client, admin, monkeypatch):
    _, headers = admin
    r = await client.get("/api/ids/status", headers=headers)
    assert r.status_code == 200
    status = r.json()
    assert status["enabled"] is False and status["detector"] == "none" and status["mlLoaded"] is False

    from app.ml import network_monitor

    def unavailable():
        raise network_monitor.CaptureUnavailable("Packet capture needs Npcap.")

    monkeypatch.setattr(network_monitor, "check_capture_available", unavailable)
    r = await client.post("/api/ids/control", headers=headers, json={"enabled": True, "mode": "monitor"})
    assert r.status_code == 503
    assert "Npcap" in r.json()["message"]

    r = await client.post("/api/ids/control", headers=headers, json={"enabled": True, "mode": "bogus"})
    assert r.status_code == 422


async def test_two_quick_starts_open_one_capture(monkeypatch):
    """Double-click / two users pressing ON together: one sniffer, and stop really stops it."""
    import asyncio
    import threading

    from app.ml import ids_service as ids_module

    created = []

    class SlowMonitor:
        def __init__(self, **kwargs):
            self.running = False
            self.packet_count = self.active_flow_count = 0
            self.last_error = None
            created.append(self)

        def start(self):
            threading.Event().wait(0.2)  # capture takes a moment to open
            self.running = True

        def stop(self):
            self.running = False

    monkeypatch.setattr(ids_module, "NetworkMonitor", SlowMonitor)
    ids = IDSService()
    await asyncio.gather(ids.start("monitor"), ids.start("monitor"))
    assert len(created) == 1 and ids.enabled
    await asyncio.gather(ids.stop(), ids.stop())
    assert not ids.enabled and not created[0].running and ids._tasks == []


async def test_model_endpoints_without_models(client, admin):
    _, headers = admin
    r = await client.get("/api/model/info", headers=headers)
    assert r.status_code == 200
    info = r.json()
    assert info["isolationForest"]["status"] == "not_loaded"
    assert info["xgboost"]["status"] == "not_loaded"
    r = await client.get("/api/model/feature-importance?stage=2", headers=headers)
    assert r.status_code == 200 and r.json() == []


async def test_websocket_requires_token(client):
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from app.main import app

    with TestClient(app) as tc:
        for url in ("/ws/live", "/ws/live?token=not-a-token"):
            with pytest.raises(WebSocketDisconnect) as closed:
                with tc.websocket_connect(url) as ws:
                    ws.receive_json()
            # 1008 (not a failed handshake) so the dashboard knows to refresh its token
            assert closed.value.code == 1008
