"""Normal / abnormal verdicts with the model's attack guesses, and SecureNet protecting itself."""

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.db.base import AsyncSessionLocal
from app.ml import network_monitor
from app.ml.detector import Detection
from app.ml.ids_service import IDSService
from app.models.security_event import SecurityEvent
from app.services import exporters
from app.services.verdict import guesses_text, possible_attack
from tests.test_ids import make_flow

DDOS_GUESSES = [{"label": "DDoS", "probability": 0.97}, {"label": "DoS", "probability": 0.02},
                {"label": "Benign", "probability": 0.01}]


class SequenceDetector:
    """Returns the given detections one after another (batch-capable like the real one)."""
    loaded = True
    name = "fake"
    calibrated_threshold = 0.46

    def __init__(self, detections):
        self.detections = list(detections)

    def analyze_batch(self, features_list, threshold, stage2_enabled, stage2_confidence):
        out, self.detections = self.detections[:len(features_list)], self.detections[len(features_list):]
        return out


def normal():
    return Detection(0.30, False)


def cancelled():
    return Detection(0.50, False, reason="XGBoost: Benign", flagged=True,
                     guesses=[{"label": "Benign", "probability": 0.9}, {"label": "Bot", "probability": 0.1}])


def ddos():
    return Detection(0.55, True, "DDoS", 0.97, "XGBoost: DDoS (97%)", flagged=True, guesses=DDOS_GUESSES)


async def test_verdict_tables_count_stage1_and_stage2(client, admin):
    from app.ml import ids_service as module

    ids = IDSService()
    ids.detector = SequenceDetector([normal(), normal(), cancelled(), ddos()])
    await ids.process_flows([make_flow() for _ in range(4)])

    summary = ids.verdict_summary()
    assert summary["scored"] == 4
    assert summary["normal"] == 2 and summary["abnormal"] == 2              # Table 1 (stage 1)
    rows = {g["label"]: g for g in summary["guesses"]}                       # Table 2 (stage 2)
    assert rows["Benign"]["flows"] == 1 and rows["Benign"]["cancelled"] is True
    assert rows["DDoS"]["flows"] == 1 and rows["DDoS"]["cancelled"] is False
    assert summary["final_normal"] == 3 and summary["final_abnormal"] == 1   # final verdict

    # the API carries the tables (camelCase)
    _, headers = admin
    original = module.ids_service
    module.ids_service = ids
    try:
        body = (await client.get("/api/ids/status", headers=headers)).json()
    finally:
        module.ids_service = original
    assert body["verdicts"]["abnormal"] == 2 and body["verdicts"]["finalNormal"] == 3
    assert {"label": "Benign", "flows": 1, "cancelled": True} in body["verdicts"]["guesses"]

    # only the confirmed abnormal flow became an incident, with its guesses kept
    async with AsyncSessionLocal() as db:
        events = (await db.execute(select(SecurityEvent))).scalars().all()
    assert len(events) == 1 and events[0].attack_guesses[0]["label"] == "DDoS"

    # the incident is worded as abnormal traffic with a possible attack
    event = (await client.get("/api/events", headers=headers)).json()["data"][0]
    assert event["attackGuesses"][0] == {"label": "DDoS", "probability": 0.97}
    feed = (await client.get("/api/notifications", headers=headers)).json()
    assert feed[0]["verdict"] == "abnormal" and feed[0]["possibleAttack"] == "DDoS (97%)"
    assert feed[0]["message"].startswith("Abnormal traffic detected from")


async def test_counters_restart_with_the_ids():
    ids = IDSService()
    ids.detector = SequenceDetector([normal()])
    await ids.process_flows([make_flow()])
    assert ids.verdict_summary()["scored"] == 1
    ids.reset_verdicts()
    assert ids.verdict_summary() == {"scored": 0, "normal": 0, "abnormal": 0, "guesses": [],
                                     "final_normal": 0, "final_abnormal": 0}


def test_possible_attack_wording():
    assert possible_attack("DDoS", 0.97, DDOS_GUESSES) == "DDoS (97%)"
    # stage 2 not sure enough to name it: still show its best non-benign guess, marked unsure
    assert possible_attack(None, None, [{"label": "Benign", "probability": 0.5},
                                        {"label": "Bot", "probability": 0.45}]) == "Bot (45%, unsure)"
    assert possible_attack(None, None, None) == "Unknown"
    assert guesses_text(DDOS_GUESSES) == "DDoS 97%, DoS 2%, Benign 1%"
    assert guesses_text([{"label": "<script>", "probability": "x"}]) == "-"      # junk dropped


async def test_attack_storm_cannot_flood_the_database(monkeypatch):
    monkeypatch.setattr(settings, "ALERT_STORE_MAX_PER_SOURCE_PER_MINUTE", 5)
    ids = IDSService()
    ids.detector = SequenceDetector([ddos() for _ in range(40)])
    await ids.process_flows([make_flow() for _ in range(40)])
    async with AsyncSessionLocal() as db:
        stored = (await db.execute(select(func.count()).select_from(SecurityEvent))).scalar_one()
    assert stored == 5
    assert ids.alerts_not_stored == 35
    assert ids.verdict_summary()["final_abnormal"] == 40      # still counted in the tables


def test_flow_table_is_bounded(monkeypatch):
    """Random-port floods must not grow the open-flow table without limit."""
    from app.ml.features import PacketInfo

    monkeypatch.setattr(network_monitor, "MAX_ACTIVE_FLOWS", 100)
    monkeypatch.setattr(network_monitor, "MAX_PACKETS_PER_FLOW", 50)
    monkeypatch.setattr(network_monitor, "_packet_info", lambda p: p)
    emitted = []
    monitor = network_monitor.NetworkMonitor(on_flow=emitted.append)
    for port in range(1, 1001):
        monitor._handle_packet(PacketInfo(1.0 + port / 1e4, "198.51.100.9", "192.168.1.10", port, 80, 6, 0, 20, "S", 1024))
    assert monitor.active_flow_count == 100
    assert monitor.flows_evicted == 900 and len(emitted) == 900
    for i in range(60):                      # one endless flow is cut into pieces
        monitor._handle_packet(PacketInfo(2.0 + i / 1e4, "198.51.100.9", "192.168.1.10", 1000, 80, 6, 10, 20, "A"))
    assert len(emitted) == 901


# ── the app itself ─────────────────────────────────────────────────────────

async def test_unknown_host_is_refused(client):
    """DNS rebinding: a hostile site that resolves its own name to 127.0.0.1 gets nothing."""
    r = await client.get("/health", headers={"Host": "evil.example"})
    assert r.status_code == 400 and r.json()["message"] == "Unknown host"
    r = await client.post("/api/auth/login", json={"email": "a@b.co", "password": "x"},
                          headers={"Host": "attacker.test:8000"})
    assert r.status_code == 400
    assert (await client.get("/health", headers={"Host": "localhost:8000"})).status_code == 200
    assert (await client.get("/health", headers={"Host": "127.0.0.1:8000"})).status_code == 200
    assert (await client.get("/health", headers={"Host": "[::1]:8000"})).status_code == 200


async def test_security_headers(client, admin):
    _, headers = admin
    for r in (await client.get("/health"), await client.get("/api/auth/me", headers=headers),
              await client.get("/api/nothing-here")):
        h = r.headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["cache-control"] == "no-store"


async def test_dashboard_root_gets_the_dashboard_policy():
    """The desktop app opens "/": with a built frontend it must get the dashboard CSP, not the API one."""
    from app.core.hardening import API_CSP, HardeningMiddleware

    async def page(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"<html></html>"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def policy_for(path, spa_policy):
        sent = []
        async def send(message):
            sent.append(message)
        mw = HardeningMiddleware(page, ["localhost"], [], spa_policy=spa_policy)
        scope = {"type": "http", "path": path, "headers": [(b"host", b"localhost:8000"), (b"content-length", b"0")]}
        await mw(scope, receive, send)
        return dict(sent[0]["headers"])[b"content-security-policy"].decode()

    assert await policy_for("/", "default-src 'self'") == "default-src 'self'"
    assert await policy_for("/login", "default-src 'self'") == "default-src 'self'"
    assert await policy_for("/health", "default-src 'self'") == API_CSP
    assert await policy_for("/", None) == API_CSP


async def test_oversized_requests_are_refused(client):
    big = b'{"email": "' + b"a" * 2_000_000 + b'"}'
    r = await client.post("/api/auth/login", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["code"] == "PAYLOAD_TOO_LARGE"

    async def chunked():                     # no Content-Length: counted while reading
        for _ in range(30):
            yield b"x" * 100_000
    r = await client.post("/api/auth/login", content=chunked(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413

    async def small():                       # a normal chunked request still works
        yield b'{"email": "nobody@example.com", '
        yield b'"password": "wrong-password"}'
    r = await client.post("/api/auth/login", content=small(), headers={"Content-Type": "application/json"})
    assert r.status_code == 401


async def test_live_feed_refuses_foreign_web_pages(client, admin):
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from app.main import app

    token = admin[0]["tokens"]["accessToken"]
    with TestClient(app) as tc:
        with pytest.raises(WebSocketDisconnect) as closed:
            with tc.websocket_connect(f"/ws/live?token={token}", headers={"Origin": "https://evil.example"}) as ws:
                ws.receive_json()
        assert closed.value.code == 1008
        with tc.websocket_connect(f"/ws/live?token={token}", headers={"Origin": "http://localhost:5173"}) as ws:
            assert ws.receive_json()["type"] == "system_status"


def test_csv_export_cannot_run_formulas():
    event = SecurityEvent(source_ip="=HYPERLINK(\"http://x\")", source_port=1, destination_ip="+1", destination_port=2,
                          anomaly_score=0.5, attack_type="@SUM(A1)", detection_reason="-2+3")
    from app.models.security_event import ActionTaken, DetectionMode, EventState, Protocol, SeverityLevel
    event.protocol, event.severity, event.mode = Protocol.TCP, SeverityLevel.HIGH, DetectionMode.MONITOR
    event.state, event.action_taken = EventState.ACTIVE, ActionTaken.ALERTED
    text = exporters.to_csv([event]).decode("utf-8-sig")
    assert "'=HYPERLINK" in text and "'@SUM(A1)" in text and "'+1" in text and "'-2+3" in text
    assert "Abnormal traffic detected" in text and "Possible Attack" in text
