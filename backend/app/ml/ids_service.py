"""
SecureNet — IDS service (live detection loop)

Pipeline for every finished network flow (paper, Algorithm 1):

    capture thread ──FlowRecord──▶ asyncio queue ──▶ worker
        worker: whitelist check → Detector.analyze (thread pool)
              → broadcast live score → if alert: store SecurityEvent,
                apply Protection mode, notify, broadcast alert

Modes:
    OFF      – IDS stopped (no capture)
    monitor  – "Detection" mode: score, store and alert
    protect  – "Protection" mode: as monitor + automatic IP blocking

If no model is loaded the IDS still captures and counts flows, but nothing is
scored — the status endpoint reports `detector = "none"`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import List, Optional

from sqlalchemy import select

from app.core.config import settings
from app.db.base import AsyncSessionLocal
from app.ml.detector import Detection, get_detector
from app.ml.features import FlowRecord
from app.ml.network_monitor import CaptureUnavailable, NetworkMonitor
from app.ml.protection import FirewallBlocker
from app.ml.rule_engine import RuleEngine, RuleHit
from app.models.security_event import (
    ActionTaken, DetectionMode, EventState, Protocol, SecurityEvent, SeverityLevel,
)
from app.models.settings import (
    DetectionSensitivity, DetectionSettings, NotificationSettings, ProtectionSettings,
    WhitelistEntry, WhitelistEntryType,
)
from app.utils.logger import logger
from app.utils.timeutil import to_iso_z, utcnow
from app.services.cache import events_changed
from app.services.notifier import get_notifier, get_recipients
from app.utils.email import send_email
from app.utils.desktop import notify_desktop   # backend-native Windows toast (works with the app closed)
from app.services.verdict import ABNORMAL, BENIGN_NAMES, possible_attack, pretty_label
from app.websocket.manager import manager

QUEUE_SIZE = 10_000
BATCH_MAX = 256          # flows scored together when traffic arrives faster than one at a time
RECENT_WINDOW_SECONDS = 90   # rolling window for the live "normal vs attack %" breakdown (CLI-style)
ABNORMAL_PCT_THRESHOLD = 30  # attacks must exceed this % of recent flows to count as ABNORMAL
DESKTOP_ALERT_INTERVAL = 180 # desktop pop: first immediately, then every 3 min while abnormal
TREND_POINTS = 72            # attack-% history for the dashboard trend chart (72 x 5s = last 6 min)
STORE_THROTTLE_SECONDS = 300 # store/alert at most ONE event per attack type per 5 min (not per flow)
INCIDENT_STORE_DELAY_SECONDS = 60  # wait this long into an abnormal episode before writing its ONE
                                   # History entry, so the breakdown has settled on the real attack
PROTECTION_VERDICT_DELAY = 15    # wait this long (s) after a block before judging success/failure
SUCCESS_CHECK_WINDOW = 12        # attacks in the last N s decide it: ~none => network benign again
PROTECTION_NOTIFY_COOLDOWN = 300 # at most one "protection successful/failed" notice per 5 min

# When the loaded model brings the threshold it was tested with, the Low / Medium /
# High presets are placed around it (Medium = exactly the tested value); "Custom"
# always uses the admin's own number. Models without a tested threshold keep the
# stored value.
PRESET_OFFSETS = {
    DetectionSensitivity.LOW: 0.05,      # fewer alerts
    DetectionSensitivity.MEDIUM: 0.0,    # the tested threshold
    DetectionSensitivity.HIGH: -0.03,    # catch more, more false alarms
}


# ── active owner (the logged-in account that owns new detections) ──────────────
# Persisted next to the IDS on/off state so it survives a backend restart: the IDS stamps every
# stored event with it, and each account's dashboard/alerts are filtered to its own events.

def _active_owner_file():
    return settings.ids_state_file.with_name("active-owner.txt")


def _load_active_owner() -> Optional[str]:
    try:
        value = _active_owner_file().read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def _save_active_owner(owner_id: Optional[str]) -> None:
    try:
        path = _active_owner_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(owner_id or "", encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Could not persist active owner: {exc}")


# ── "Incidents Today" counter (persisted) ─────────────────────────────────────
# Stored next to the IDS state so the count survives a PC shutdown / backend restart: if the PC is
# turned off at 4 incidents and back on the SAME local day, the dashboard still shows 4. It only
# returns to 0 when the local calendar day changes (midnight). Format: "YYYY-MM-DD count".

def _incidents_file():
    return settings.ids_state_file.with_name("incidents-today.txt")


def _load_incidents_today() -> tuple[Optional[str], int]:
    try:
        parts = _incidents_file().read_text(encoding="utf-8").strip().split()
        if len(parts) == 2:
            return parts[0], int(parts[1])
    except (OSError, ValueError):
        pass
    return None, 0


def _save_incidents_today(date: Optional[str], count: int) -> None:
    try:
        path = _incidents_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{date or ''} {count}", encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Could not persist incidents-today count: {exc}")


BENIGN_GUESS = "Benign"            # Table 2 row: stage 2 cancelled the alarm
UNCLASSIFIED_GUESS = "Unclassified"
# The behavioural rules (scan/sweep/brute/flood/ICMP) still run internally, but they are NOT shown
# under their own names — every rule hit is displayed as this single generic label instead. The
# specific rule is kept only in the backend log.
RULE_DISPLAY_LABEL = "Reconnaissance"


def alert_payload(event: SecurityEvent) -> dict:
    """WebSocket `alert` payload (same shape as GET /api/notifications items)."""
    guess = possible_attack(event.attack_type, event.confidence, event.attack_guesses)
    return {
        "eventId": str(event.id),
        "timestamp": to_iso_z(event.timestamp),
        "severity": event.severity.value,
        "verdict": "abnormal",
        "attackType": event.attack_type,
        "confidence": event.confidence,
        "possibleAttack": guess,
        "sourceIp": event.source_ip,
        "sourcePort": event.source_port,
        "destinationIp": event.destination_ip,
        "destinationPort": event.destination_port,
        "protocol": event.protocol.value,
        "anomalyScore": round(float(event.anomaly_score), 4),
        "actionTaken": event.action_taken.value,
        "message": f"{ABNORMAL} from {event.source_ip} → {event.destination_ip}:{event.destination_port} "
                   f"— possible attack: {guess} (score {event.anomaly_score:.2f})",
    }


@dataclass
class IDSConfig:
    """Runtime configuration, refreshed from the Settings tables."""
    detection_enabled: bool = True
    anomaly_threshold: float = settings.ANOMALY_THRESHOLD
    stage2_enabled: bool = True
    stage2_confidence: float = settings.CLASSIFICATION_CONFIDENCE_THRESHOLD
    default_mode: DetectionMode = DetectionMode.MONITOR
    auto_block: bool = False
    auto_block_severities: set = field(default_factory=lambda: {"high"})
    block_duration_seconds: int = 3600
    max_blocked_ips: int = 1000
    wl_ips: set = field(default_factory=set)
    wl_networks: list = field(default_factory=list)
    wl_ports: set = field(default_factory=set)
    wl_protocols: set = field(default_factory=set)


class IDSService:
    def __init__(self) -> None:
        self.detector = get_detector()
        self.config = IDSConfig()
        self.mode: DetectionMode = DetectionMode.MONITOR
        self.enabled = False
        self.monitor: Optional[NetworkMonitor] = None
        self.blocker = FirewallBlocker()
        # Additive behavioural rule layer (scan/sweep/brute-force/flood). Second opinion only —
        # it raises an extra alert when the model said Benign; it never overrides the model.
        self.rule_engine = RuleEngine()
        self.rule_engine.enabled = settings.IDS_RULES_ENABLED
        self.capture_error: Optional[str] = None
        self.started_at: Optional[float] = None
        # Who turned the IDS on (shown in the admin's alert email)
        self.started_by: Optional[dict] = None
        # The account that currently owns detections: whoever is logged in (set on login / when the
        # IDS is turned on). Every stored event is stamped with it, so each account sees only its own
        # data and its alerts go only to that user. Persisted so it survives a backend restart.
        self.active_owner_id: Optional[str] = _load_active_owner()
        # "Today's abnormal count": number of distinct abnormal episodes detected today. Incremented
        # once each time the network goes normal -> abnormal (not while it stays abnormal); resets at
        # midnight (local). Kept across IDS ON/OFF within the day (not reset by reset_verdicts) and
        # PERSISTED to disk, so a PC shutdown / backend restart on the same day restores the count
        # (get_status still shows 0 once the local day has rolled over to a new date).
        self._abnormal_count_date, self._abnormal_count = _load_incidents_today()

        self._queue: Optional[asyncio.Queue] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._tasks: list[asyncio.Task] = []
        self._lifecycle_lock = asyncio.Lock()
        self._last_score_times: list[float] = []

        self.flows_analyzed = 0
        self.flows_dropped = 0
        self.anomalies_detected = 0
        self.attacks_detected = 0
        self.reset_verdicts()
        # storm limit: times of recently stored incidents (all / per source address)
        self._stored_times: deque = deque()
        self._stored_by_source: dict = {}
        self.alerts_not_stored = 0

    def reset_verdicts(self) -> None:
        """Counters behind the dashboard's verdict tables (since the IDS was turned on)."""
        # Per-session stats shown on the dashboard — reset on every ON so a new session does not
        # inherit a previous run's totals (otherwise "FLOWS ANALYZED" keeps climbing from old
        # captures while NORMAL/ABNORMAL read 0, which looks stuck/broken right after turning ON).
        self.flows_analyzed = 0
        self.flows_dropped = 0
        self.anomalies_detected = 0
        self.attacks_detected = 0
        self.flows_scored = 0
        self.flows_normal = 0          # stage 1: not unusual
        self.flows_flagged = 0         # stage 1: abnormal
        self.guess_counts: Counter = Counter()   # stage 2's best guess for each flagged flow
        # rolling window of recent per-flow labels (Benign or attack class) for the CLI-style
        # live breakdown: (timestamp, label). Old entries are pruned in verdict_summary().
        self.recent_labels: deque = deque()
        # abnormal-state notification scheduler (attacks > 40% of recent flows)
        self._abnormal_now = False        # gates the alert email (only while abnormal)
        self._abn_episode = False         # currently inside an abnormal episode
        self._abn_last_desktop = 0.0      # last desktop pop (epoch)
        self._abn_episode_started_at = 0.0    # epoch the current abnormal episode began
        self._abn_stored_this_episode = False # the one History entry for this episode is written
        self.trend: deque = deque(maxlen=TREND_POINTS)   # (epoch, attack%) for the dashboard trend chart
        self._last_store_time = 0.0       # last epoch a (majority) event was stored (global 5-min throttle)
        self._majority_attack: Optional[str] = None   # dominant attack in the recent window (only one stored to History)
        # Protection outcome tracking: after a block we wait, then tell the user whether the
        # network went benign again (success) or the attack is still active (failed).
        self._protection_pending: Optional[dict] = None   # {"ips": set, "verdict_at": epoch}
        self._protection_last_notice = 0.0
        self._last_blocked_event_id: Optional[str] = None
        self.rule_engine.reset()          # behavioural-rule windows start fresh with each IDS run

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Called at app startup. The model load and the DB settings fetch run IN THE BACKGROUND
        so the server answers /health (and the login page loads) immediately — they finish within a
        couple of seconds, well before the user logs in and presses ON. Same model, same accuracy."""
        if settings.ML_AUTOLOAD:
            asyncio.create_task(self.reload_models())   # background: don't block app startup
        else:
            logger.info("ML_AUTOLOAD=false — no detection model loaded (IDS will run capture-only)")
        self.mode = self.config.default_mode            # default (MONITOR); start() reloads config anyway
        asyncio.create_task(self._bg_reload_config())

    async def _bg_reload_config(self) -> None:
        try:
            await self.reload_config()
            self.mode = self.config.default_mode
        except Exception as exc:  # DB may be unreachable at boot; retried on start
            logger.warning(f"Could not load IDS settings at startup: {exc}")

    async def reload_models(self) -> bool:
        loaded = await asyncio.to_thread(self.detector.load, settings.models_dir)
        try:
            await self.reload_config()        # the model may bring its own tested threshold
        except Exception as exc:
            logger.warning(f"Could not refresh IDS settings after loading the model: {exc}")
        await self.broadcast_status()
        return loaded

    async def start(self, mode: Optional[str] = None) -> None:
        """Start capture + detection. Raises CaptureUnavailable on failure."""
        # One start/stop at a time: two quick "ON" clicks (or two users) must not
        # both pass the `enabled` check and leave a second sniffer running.
        async with self._lifecycle_lock:
            if self.enabled:
                if mode:
                    await self.set_mode(mode)
                return
            await self.reload_config()
            await self.set_mode(mode or self.config.default_mode.value)

            self._loop = asyncio.get_running_loop()
            self._queue = asyncio.Queue(maxsize=QUEUE_SIZE)
            if settings.CAPTURE_SOURCE == "local_csv":
                # feed from our WinDivert -> CICFlowMeter-4.0 pipeline (no train/serve skew)
                from app.ml.csv_capture import CsvFlowSource
                self.monitor = CsvFlowSource(
                    on_flow=self._enqueue_from_thread,
                    csv_dir=settings.LIVE_CSV_DIR,
                    spawn=settings.LIVE_CAPTURE_SPAWN,
                    project_dir=settings.LIVE_PROJECT_DIR,
                    python_exe=settings.LIVE_PYTHON,
                )
            else:
                self.monitor = NetworkMonitor(
                    on_flow=self._enqueue_from_thread,
                    interface=settings.CAPTURE_INTERFACE or None,
                    idle_timeout=settings.FLOW_IDLE_TIMEOUT_SECONDS,
                    active_timeout=settings.FLOW_ACTIVE_TIMEOUT_SECONDS,
                )
            try:
                await asyncio.to_thread(self.monitor.start)
            except CaptureUnavailable as exc:
                self.capture_error = str(exc)
                self.monitor = None
                logger.error(f"IDS start failed: {exc}")
                raise

            self.capture_error = None
            self.enabled = True
            self.started_at = time.time()
            self.reset_verdicts()
            self._tasks = [
                asyncio.create_task(self._worker(), name="ids-worker"),
                asyncio.create_task(self._maintenance(), name="ids-maintenance"),
            ]
            logger.info(f"IDS started (mode={self.mode.value}, detector={self.detector.name})")
        await self.broadcast_status()

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            if not self.enabled:
                return
            self.enabled = False
            monitor, self.monitor = self.monitor, None
            if monitor is not None:
                await asyncio.to_thread(monitor.stop)
            for task in self._tasks:
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks = []
            await self.blocker.unblock_all()
            self.started_at = None
            logger.info("IDS stopped")
        await self.broadcast_status()

    async def set_mode(self, mode: str) -> None:
        try:
            self.mode = DetectionMode(mode)
        except ValueError:
            raise ValueError(f"Unknown mode '{mode}' (expected 'monitor' or 'protect')")
        if self.mode != DetectionMode.PROTECT:
            await self.blocker.unblock_all()

    def set_active_owner(self, owner_id: Optional[str]) -> None:
        """Remember which logged-in account owns new detections (and gets the alerts). Set on
        sign-in and when the IDS is turned on; persisted so a backend restart keeps the owner."""
        owner_id = str(owner_id) if owner_id else None
        if owner_id != self.active_owner_id:
            self.active_owner_id = owner_id
            _save_active_owner(owner_id)
            logger.info(f"IDS active owner set to {owner_id}")

    def _owner_uuid(self):
        """active_owner_id as a UUID for the SecurityEvent FK (None if unset/invalid)."""
        try:
            import uuid as _uuid
            return _uuid.UUID(self.active_owner_id) if self.active_owner_id else None
        except (TypeError, ValueError):
            return None

    # ── configuration ────────────────────────────────────────────────────────

    async def reload_config(self) -> None:
        """Pull detection/protection/notification settings and the whitelist from the DB."""
        cfg = IDSConfig()
        async with AsyncSessionLocal() as db:
            det = (await db.execute(select(DetectionSettings).limit(1))).scalars().first()
            prot = (await db.execute(select(ProtectionSettings).limit(1))).scalars().first()
            entries = (await db.execute(select(WhitelistEntry).where(WhitelistEntry.active.is_(True)))).scalars().all()

        if det:
            cfg.detection_enabled = det.enabled
            cfg.anomaly_threshold = self.effective_threshold(det.sensitivity, det.anomaly_threshold)
            cfg.stage2_enabled = det.stage2_enabled
            cfg.stage2_confidence = det.stage2_confidence_threshold
        else:   # no settings saved yet: the default sensitivity (Medium)
            cfg.anomaly_threshold = self.effective_threshold(DetectionSensitivity.MEDIUM, cfg.anomaly_threshold)
        if prot:
            cfg.default_mode = DetectionMode(prot.mode.value)
            cfg.auto_block = prot.auto_block
            cfg.auto_block_severities = set(prot.auto_block_severities or [])
            cfg.block_duration_seconds = prot.block_duration_seconds
            cfg.max_blocked_ips = prot.max_blocked_ips
        else:
            cfg.default_mode = DetectionMode(settings.DETECTION_MODE if settings.DETECTION_MODE in ("monitor", "protect") else "monitor")
        for entry in entries:
            try:
                if entry.type == WhitelistEntryType.IP:
                    cfg.wl_ips.add(str(ipaddress.ip_address(entry.value)))
                elif entry.type == WhitelistEntryType.CIDR:
                    cfg.wl_networks.append(ipaddress.ip_network(entry.value, strict=False))
                elif entry.type == WhitelistEntryType.PORT:
                    cfg.wl_ports.add(int(entry.value))
                elif entry.type == WhitelistEntryType.PROTOCOL:
                    cfg.wl_protocols.add(entry.value.upper())
            except ValueError:
                logger.warning(f"Ignoring invalid whitelist entry {entry.type.value}:{entry.value}")
        self.config = cfg

    def effective_threshold(self, sensitivity, stored: float) -> float:
        tested = self.detector.calibrated_threshold
        if tested is None or sensitivity not in PRESET_OFFSETS:
            return float(stored)
        return round(tested + PRESET_OFFSETS[sensitivity], 6)

    def is_whitelisted(self, flow: FlowRecord) -> bool:
        cfg = self.config
        if flow.protocol_name.upper() in cfg.wl_protocols:
            return True
        if flow.src_port in cfg.wl_ports or flow.dst_port in cfg.wl_ports:
            return True
        for ip in (flow.src_ip, flow.dst_ip):
            if ip in cfg.wl_ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in net for net in cfg.wl_networks if net.version == addr.version):
                return True
        return False

    # ── status ───────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        monitor = self.monitor
        return {
            "enabled": self.enabled,
            "mode": self.mode.value,
            "ml_loaded": self.detector.loaded,
            "detector": self.detector.name,
            "threshold": self.config.anomaly_threshold,
            "capture_active": bool(monitor and monitor.running),
            "capture_error": self.capture_error or (monitor.last_error if monitor else None),
            "packets_processed": monitor.packet_count if monitor else 0,
            "flows_analyzed": self.flows_analyzed,
            "active_flows": monitor.active_flow_count if monitor else 0,
            "abnormal_events_today": (self._abnormal_count
                                      if self._abnormal_count_date == time.strftime("%Y-%m-%d", time.localtime())
                                      else 0),
            "anomalies_detected": self.anomalies_detected,
            "attacks_detected": self.attacks_detected,
            "blocked_ips": len(self.blocker.blocked),
            "rule_hits": self.rule_engine.hits,
            "uptime_seconds": int(time.time() - self.started_at) if self.started_at else 0,
            "alerts_not_stored": self.alerts_not_stored,
            "verdicts": self.verdict_summary(),
        }

    def verdict_summary(self) -> dict:
        """Table 1 (stage 1: normal vs abnormal), Table 2 (stage 2's guess for every
        flagged flow) and the final verdict, counted since the IDS was turned on."""
        cancelled = self.guess_counts.get(BENIGN_GUESS, 0)
        guesses = [
            {"label": label, "flows": n, "cancelled": label == BENIGN_GUESS}
            for label, n in sorted(self.guess_counts.items(), key=lambda t: (-t[1], t[0]))
        ]
        # rolling-window breakdown (CLI-style): % of each class over the last RECENT_WINDOW_SECONDS
        cutoff = time.time() - RECENT_WINDOW_SECONDS
        while self.recent_labels and self.recent_labels[0][0] < cutoff:
            self.recent_labels.popleft()
        recent_counts = Counter(lbl for _, lbl in self.recent_labels)
        recent_total = sum(recent_counts.values())
        recent = [
            {"label": lbl, "flows": n, "pct": round(n / recent_total * 100, 1)}
            for lbl, n in sorted(recent_counts.items(), key=lambda t: (-t[1], t[0]))
        ] if recent_total else []
        recent_abnormal_pct = round(
            sum(n for lbl, n in recent_counts.items() if lbl.lower() not in BENIGN_NAMES)
            / recent_total * 100, 1) if recent_total else 0.0

        return {
            "scored": self.flows_scored,
            "normal": self.flows_normal,
            "abnormal": self.flows_flagged,
            "guesses": guesses,
            "final_normal": self.flows_normal + cancelled,
            "final_abnormal": self.flows_flagged - cancelled,
            # live rolling window (what the CLI printed each refresh)
            "recent": recent,
            "recent_total": recent_total,
            "recent_abnormal_pct": recent_abnormal_pct,
            # attack-% history for the dashboard trend chart (last ~5 min, 5s apart)
            "trend": [{"t": int(t), "pct": round(p, 1)} for t, p in self.trend],
        }

    async def broadcast_status(self) -> None:
        status = self.get_status()
        await manager.send_system_status({
            "detectionEnabled": status["enabled"],
            "mode": status["mode"],
            "modelStatus": status["detector"],
            "activeFlows": status["active_flows"],
        })

    # ── flow processing ──────────────────────────────────────────────────────

    def _enqueue_from_thread(self, record: FlowRecord) -> None:
        """Called from the capture threads — hand the record to the event loop."""
        loop, queue = self._loop, self._queue
        if loop is None or queue is None or loop.is_closed():
            return

        def _put() -> None:
            try:
                queue.put_nowait(record)
            except asyncio.QueueFull:
                self.flows_dropped += 1

        loop.call_soon_threadsafe(_put)

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            batch = [await self._queue.get()]
            # take whatever else is already waiting: one model call for the whole burst
            while len(batch) < BATCH_MAX:
                try:
                    batch.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            try:
                await self.process_flows(batch)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Flow processing error: {exc}", exc_info=True)
            finally:
                for _ in batch:
                    self._queue.task_done()

    async def _maintenance(self) -> None:
        while True:
            await asyncio.sleep(5)
            await self.blocker.unblock_expired()
            await self._evaluate_abnormal_state()
            await self._check_protection_outcome()
            await self.broadcast_status()

    def _arm_protection(self, ip: str) -> None:
        """A block just happened — remember it so we can judge the outcome shortly after."""
        now = time.time()
        if self._protection_pending is None:
            self._protection_pending = {"ips": {ip}, "verdict_at": now + PROTECTION_VERDICT_DELAY}
        else:
            self._protection_pending["ips"].add(ip)

    def _recent_attack_count(self, seconds: float) -> int:
        cutoff = time.time() - seconds
        return sum(1 for t, lbl in self.recent_labels if t >= cutoff and lbl.lower() not in BENIGN_NAMES)

    async def _check_protection_outcome(self) -> None:
        """A few seconds after Protection blocked an attacker, tell the user whether it worked:
        SUCCESS if the network went benign again (≈no attack flows in the last few seconds),
        otherwise the attack is still active. Exactly ONE notice per episode (desktop + popup +
        email), rate-limited so it can't spam."""
        pend = self._protection_pending
        if not pend:
            return
        now = time.time()
        if now < pend["verdict_at"]:
            return
        self._protection_pending = None
        if now - self._protection_last_notice < PROTECTION_NOTIFY_COOLDOWN:
            return
        self._protection_last_notice = now
        success = self._recent_attack_count(SUCCESS_CHECK_WINDOW) <= 1
        try:
            await self._send_protection_verdict(success, sorted(pend["ips"]))
        except Exception as exc:
            logger.error(f"Protection verdict notice failed: {exc}")

    async def _send_protection_verdict(self, success: bool, ips: list) -> None:
        ip_text = ", ".join(ips) if ips else "the attacker"
        if success:
            title = "SecureNet protection successful"
            body = f"SecureNet blocked {ip_text} and your network is back to normal."
            action = "Action taken successfully — click to view what was done."
            severity = "medium"
        else:
            title = "SecureNet protection — attack still active"
            body = f"SecureNet blocked {ip_text}, but abnormal traffic is still being detected."
            action = "Click to view what SecureNet has done."
            severity = "high"
        payload = {
            "eventId": self._last_blocked_event_id or f"protection-{int(time.time())}",
            "timestamp": to_iso_z(utcnow()),
            "severity": severity,
            "verdict": "protection",
            "success": success,
            "attackType": None,
            "confidence": None,
            "possibleAttack": None,
            "sourceIp": ips[0] if ips else "",
            "sourcePort": 0,
            "destinationIp": "",
            "destinationPort": 0,
            "protocol": "OTHER",
            "anomalyScore": 0.0,
            "actionTaken": "blocked",
            "message": f"{title}. {action}",
            "desktopPop": True,          # in-app popup + sound when the app is open
        }
        await manager.send_alert(payload, self.active_owner_id)   # only the logged-in account
        await notify_desktop(title, f"{body} {action}")   # OS toast — shows even with the app closed
        await self._email_protection_verdict(title, body, action, ips)

    async def _email_protection_verdict(self, title: str, body: str, action: str, ips: list) -> None:
        try:
            async with AsyncSessionLocal() as db:
                prefs = (await db.execute(select(NotificationSettings).limit(1))).scalars().first()
                recipients = await get_recipients(db, prefs)
        except Exception as exc:
            logger.warning(f"Could not resolve protection-email recipients: {exc}")
            return
        if not recipients:
            return
        link = f"{settings.DASHBOARD_URL}/history"
        blocked = ", ".join(ips) if ips else "the attacker"
        subject = f"[{settings.APP_NAME}] {title}"
        text = "\n".join([f"{settings.APP_NAME}: {title}", "", body, "", f"Blocked: {blocked}", "",
                          action, f"View in {settings.APP_NAME}: {link}"])
        html_body = (
            "<!DOCTYPE html><html><body style='margin:0;padding:24px;font-family:Arial,Helvetica,sans-serif;color:#1f2328'>"
            f"<p style='font-size:20px;font-weight:bold;color:#c2562f;margin:0 0 4px'>&#128737; {settings.APP_NAME}</p>"
            f"<h2 style='margin:4px 0 8px'>{title}</h2><p style='font-size:15px'>{body}</p>"
            f"<p style='color:#59636e'>Blocked: <b>{blocked}</b></p>"
            f"<p style='margin:16px 0'><a href='{link}' style='background:#c2410c;color:#fff;padding:10px 18px;"
            f"border-radius:8px;text-decoration:none;font-weight:bold'>View what SecureNet did</a></p>"
            f"<p style='color:#8c959f;font-size:12px'>{action}</p></body></html>"
        )
        try:
            await send_email(recipients, subject, text, html_body)
        except Exception as exc:
            logger.warning(f"Protection verdict email failed: {exc}")

    async def _evaluate_abnormal_state(self) -> None:
        """Drive the abnormal-traffic notifications (desktop every 3 min; the email is gated in
        _handle on self._abnormal_now so the notifier sends at episode start + every 10 min).
        Abnormal = attacks make up more than ABNORMAL_PCT_THRESHOLD of the recent window."""
        summary = self.verdict_summary()
        abnormal = summary["recent_total"] > 0 and summary["recent_abnormal_pct"] > ABNORMAL_PCT_THRESHOLD
        self._abnormal_now = abnormal
        # Dominant (majority) attack in the recent window — the ONLY attack written to History and
        # shown as the "Latest Unresolved Incident". Recomputed every maintenance tick (~5s).
        _recent_attacks = [r for r in summary["recent"] if r["label"].lower() not in BENIGN_NAMES]
        self._majority_attack = _recent_attacks[0]["label"] if _recent_attacks else None
        self.trend.append((time.time(), summary["recent_abnormal_pct"]))   # 5s-spaced attack-% history
        if not abnormal:
            self._abn_episode = False      # back to normal -> next abnormal starts a fresh episode
            return
        now = time.time()
        first = not self._abn_episode
        if first:
            self._abn_episode = True
            self._abn_last_desktop = 0.0   # force an immediate desktop pop on episode start
            # History gets ONE entry per incident, written 1 min in once the breakdown has settled on
            # the real (majority) attack — not a new random row every few minutes.
            self._abn_episode_started_at = now
            self._abn_stored_this_episode = False
            # count this new abnormal episode towards today's total (slope went up again)
            today = time.strftime("%Y-%m-%d", time.localtime())
            if self._abnormal_count_date != today:   # new local day -> start at 0
                self._abnormal_count_date = today
                self._abnormal_count = 0
            self._abnormal_count += 1
            _save_incidents_today(self._abnormal_count_date, self._abnormal_count)   # survive restart
        if first or (now - self._abn_last_desktop) >= DESKTOP_ALERT_INTERVAL:
            self._abn_last_desktop = now
            try:
                await self._send_desktop_abnormal(summary)
            except Exception as exc:
                logger.error(f"desktop abnormal alert failed: {exc}")

    async def _send_desktop_abnormal(self, summary: dict) -> None:
        """Pop one desktop notification summarising the current abnormal traffic (every 3 min)."""
        attacks = [r for r in summary["recent"] if r["label"].lower() not in ("benign", "normal")]
        top = pretty_label(attacks[0]["label"]) if attacks else "Unknown"   # display name only
        pct = summary["recent_abnormal_pct"]
        breakdown = ", ".join(f"{pretty_label(r['label'])} {r['pct']:.0f}%" for r in attacks[:3])
        payload = {
            "eventId": f"network-{int(time.time())}",
            "timestamp": to_iso_z(utcnow()),
            "severity": "high" if pct >= 70 else "medium",
            "verdict": "abnormal",
            "attackType": top,
            "confidence": None,
            "possibleAttack": top,
            "sourceIp": "",
            "sourcePort": 0,
            "destinationIp": "",
            "destinationPort": 0,
            "protocol": "OTHER",
            "anomalyScore": 0.0,
            "actionTaken": "alerted",
            "message": f"Abnormal network traffic — attacks are {pct:.0f}% of recent flows ({breakdown}).",
            "desktopPop": True,          # in-app popup when the app is open
        }
        await manager.send_alert(payload, self.active_owner_id)   # only the logged-in account
        # OS desktop toast straight from the backend → shows even when SecureNet is NOT open
        await notify_desktop("Abnormal network traffic detected",
                             f"Attacks are {pct:.0f}% of recent flows ({breakdown}). Open SecureNet to see why.")

    async def process_flow(self, flow: FlowRecord) -> Optional[SecurityEvent]:
        """Run one finished flow through the detection pipeline."""
        events = await self.process_flows([flow])
        return events[0]

    async def process_flows(self, flows: List[FlowRecord]) -> List[Optional[SecurityEvent]]:
        """Run finished flows through the pipeline; scores them in one model call."""
        self.flows_analyzed += len(flows)
        results: List[Optional[SecurityEvent]] = [None] * len(flows)
        if not self.config.detection_enabled or not self.detector.loaded:
            return results
        todo = [i for i, f in enumerate(flows) if not self.is_whitelisted(f)]
        if not todo:
            return results

        cfg = self.config
        batch = getattr(self.detector, "analyze_batch", None)
        if batch is not None:
            detections = await asyncio.to_thread(
                batch, [flows[i].features for i in todo], cfg.anomaly_threshold, cfg.stage2_enabled,
                cfg.stage2_confidence)
        else:   # detectors without a batch call (e.g. test doubles)
            detections = [await asyncio.to_thread(self.detector.analyze, flows[i].features, cfg.anomaly_threshold,
                                                  cfg.stage2_enabled, cfg.stage2_confidence) for i in todo]
        for i, detection in zip(todo, detections):
            if detection is None:
                continue
            # Additive behavioural rules: always update the sliding windows; if a cross-flow
            # pattern fires on a flow the MODEL called Benign, raise it to an alert. The model's
            # own attack calls are left exactly as they are (rules never override the model).
            if self.rule_engine.enabled:
                hit = self.rule_engine.update_and_check(flows[i])
                if hit is not None and not detection.is_alert:
                    detection = self._rule_detection(hit)
            self._count_verdict(detection)
            results[i] = await self._handle(flows[i], detection)
        return results

    def _rule_detection(self, hit: RuleHit) -> Detection:
        """Turn a behavioural-rule hit into a Detection so it flows through the normal
        count/store/alert/block path. The SPECIFIC rule (scan/sweep/flood/…) is kept only
        in the log; the displayed label is the single generic RULE_DISPLAY_LABEL."""
        logger.info(f"Behavioural rule (internal): {hit.reason}")
        return Detection(
            anomaly_score=hit.score,
            is_alert=True,
            attack_type=RULE_DISPLAY_LABEL,
            confidence=None,
            reason="SecureNet's behavioural monitoring flagged unusual activity from this source.",
            top_features=[],
            flagged=True,
            guesses=[{"label": RULE_DISPLAY_LABEL, "probability": 1.0}],
        )

    def _count_verdict(self, detection: Detection) -> None:
        self.flows_scored += 1
        flagged = detection.flagged or detection.is_alert
        if not flagged:
            self.flows_normal += 1
            self._record_recent("Benign")
            return
        self.flows_flagged += 1
        if not detection.is_alert:
            self.guess_counts[BENIGN_GUESS] += 1          # stage 2 cancelled the alarm
            self._record_recent("Benign")
            return
        top = detection.guesses[0]["label"] if detection.guesses else None
        if top is None or top.lower() in BENIGN_NAMES:
            top = UNCLASSIFIED_GUESS
        self.guess_counts[top] += 1
        self._record_recent(top)

    def _record_recent(self, label: str) -> None:
        self.recent_labels.append((time.time(), label))

    def _storm_allows(self, source_ip: str) -> bool:
        """Store at most N incidents a minute (and M per source): an attacker flooding the
        network must not be able to flood the database, the emails and every dashboard."""
        now = time.monotonic()
        while self._stored_times and now - self._stored_times[0] > 60:
            self._stored_times.popleft()
        per_source = self._stored_by_source.get(source_ip)
        if per_source is not None:
            while per_source and now - per_source[0] > 60:
                per_source.popleft()
        if len(self._stored_times) >= settings.ALERT_STORE_MAX_PER_MINUTE:
            return False
        if per_source is not None and len(per_source) >= settings.ALERT_STORE_MAX_PER_SOURCE_PER_MINUTE:
            return False
        if len(self._stored_by_source) > 10_000:       # forget quiet sources (memory stays bounded)
            self._stored_by_source = {ip: q for ip, q in self._stored_by_source.items() if q}
        self._stored_times.append(now)
        self._stored_by_source.setdefault(source_ip, deque()).append(now)
        return True

    async def _handle(self, flow: FlowRecord, detection: Detection) -> Optional[SecurityEvent]:
        """Live score for every scored flow; store + alert + email for alerts."""
        cfg = self.config
        severity = self._severity_for(detection, cfg.anomaly_threshold)
        if not detection.is_alert:
            await self._broadcast_score(flow, detection, severity, throttle=True)
            return None

        self.anomalies_detected += 1
        if detection.attack_type:
            self.attacks_detected += 1

        # Advanced Protection (Settings → Advanced Protection). While it is ON the IDS runs in
        # "protect" mode and, once the network turns ABNORMAL (attacks make up more than
        # ABNORMAL_PCT_THRESHOLD of the recent window), it blocks the ATTACKER'S SOURCE IP at the
        # Windows Firewall — whatever the attack is (a mixed verdict still has one attacker to stop).
        # Below that 30% gate it stays detection-only (normal IDS). Each source is blocked once.
        if (self.mode == DetectionMode.PROTECT and cfg.auto_block and self._abnormal_now
                and severity.value in cfg.auto_block_severities
                and flow.src_ip not in self.blocker.blocked
                and not self.blocker.is_protected(flow.src_ip)):
            ok, note = await self.blocker.block(flow.src_ip, cfg.block_duration_seconds, cfg.max_blocked_ips)
            if ok:
                logger.info(f"Advanced Protection blocked attacker {flow.src_ip}: {note}")
                self._arm_protection(flow.src_ip)   # judge success/failure in a few seconds
            else:
                logger.warning(f"Advanced Protection could not block {flow.src_ip}: {note}")

        # History timing while abnormal: write the FIRST row ~1 min into the incident (once the live
        # breakdown has settled on the real dominant attack), then a NEW row every STORE_THROTTLE_SECONDS
        # (5 min) for as long as it stays abnormal. Each row is the current majority (highest-%) attack;
        # the email is queued at the same time (below, gated on self._abnormal_now). A fresh episode
        # (network went normal then abnormal again) starts over at the 1-min mark. Scoring, the live
        # breakdown and the trend still count every flow elsewhere and are unaffected.
        now = time.time()
        episode_age = now - getattr(self, "_abn_episode_started_at", 0.0)
        is_majority = (self._abnormal_now and self._majority_attack is not None
                       and detection.attack_type == self._majority_attack)
        first = not getattr(self, "_abn_stored_this_episode", False)
        ready = is_majority and (
            (first and episode_age >= INCIDENT_STORE_DELAY_SECONDS)          # first row: 1 min in
            or (not first and (now - self._last_store_time) >= STORE_THROTTLE_SECONDS))  # then every 5 min
        if not ready:
            await self._broadcast_score(flow, detection, severity, throttle=True)
            return None

        # Anti-flood cap — checked ONLY here, AFTER the majority/timing gate, so a heavy attack's
        # thousands of flagged flows (which won't be stored anyway during the 1-min wait) can't burn
        # the storm budget and block the one row we DO want. We store ~1 row per 1–5 min, so this
        # effectively never trips now; it stays as a last-resort guard.
        if not self._storm_allows(flow.src_ip):
            self.alerts_not_stored += 1
            if self.alerts_not_stored % 100 == 1:
                logger.warning(f"Alert storm: {self.alerts_not_stored} incidents counted but not stored "
                               f"(limit {settings.ALERT_STORE_MAX_PER_MINUTE}/min)")
            await self._broadcast_score(flow, detection, severity, throttle=True)
            return None
        self._abn_stored_this_episode = True
        self._last_store_time = now

        # Record in the report whether Advanced Protection has blocked this attacker's IP.
        if flow.src_ip in self.blocker.blocked:
            action = ActionTaken.BLOCKED
            reason = f"{detection.reason}. Advanced Protection blocked {flow.src_ip} at the Windows Firewall."
        else:
            action = ActionTaken.ALERTED
            reason = detection.reason

        # Store the REAL live breakdown (every attack class and its exact % of the recent window) with
        # this incident, and set the confidence to the majority attack's actual share — so the report /
        # PDF show the exact mix (e.g. "FTP 51%, XSS 48%, Bot 1%"), not a single per-flow guess.
        _recent = self.verdict_summary().get("recent", [])
        breakdown_guesses = [{"label": r["label"], "probability": round(float(r["pct"]) / 100.0, 4)}
                             for r in _recent if str(r["label"]).lower() not in BENIGN_NAMES]
        majority_share = next((round(float(r["pct"]) / 100.0, 4) for r in _recent
                               if r["label"] == self._majority_attack), None)

        event = SecurityEvent(
            timestamp=utcnow(),
            owner_id=self._owner_uuid(),     # the logged-in account this detection belongs to
            source_ip=flow.src_ip,
            source_port=flow.src_port,
            destination_ip=flow.dst_ip,
            destination_port=flow.dst_port,
            protocol=Protocol(flow.protocol_name) if flow.protocol_name in ("TCP", "UDP", "ICMP") else Protocol.OTHER,
            anomaly_score=round(detection.anomaly_score, 6),
            severity=severity,
            attack_type=detection.attack_type,
            confidence=majority_share if majority_share is not None else detection.confidence,
            mode=self.mode,
            state=EventState.ACTIVE,
            action_taken=action,
            detection_reason=reason,
            contributing_features=detection.top_features or None,
            attack_guesses=breakdown_guesses or detection.guesses or None,
            flow_duration_ms=flow.duration_ms,
            bytes_sent=flow.fwd_bytes,
            bytes_received=flow.bwd_bytes,
            packets_sent=flow.fwd_packets,
            packets_received=flow.bwd_packets,
        )
        async with AsyncSessionLocal() as db:
            db.add(event)
            await db.commit()
            await db.refresh(event)
        events_changed()   # dashboard / reports / bell show it straight away
        if action == ActionTaken.BLOCKED:
            self._last_blocked_event_id = str(event.id)   # so "click to view" opens the block

        await self._broadcast_score(flow, detection, severity, throttle=False)
        await manager.send_alert(alert_payload(event), str(event.owner_id) if event.owner_id else None)
        # email only while the network is ABNORMAL (attacks > 40% of recent flows); the notifier
        # then sends at episode start + every ALERT_EMAIL_INTERVAL_SECONDS (10 min) while it lasts.
        if self._abnormal_now:
            get_notifier().enqueue(event)
        logger.info(f"Alert: abnormal traffic (possible {event.attack_type or 'unknown'}) from {flow.src_ip} "
                    f"score={detection.anomaly_score:.3f} severity={severity.value} action={action.value}")
        return event

    def _severity_for(self, detection: Detection, threshold: float) -> SeverityLevel:
        """Severity of a detection.

        For a model with a tested threshold (the hybrid model) the stage-1 scores sit in a narrow
        band just above the threshold, so "distance above θ" would call almost everything Low —
        a DDoS the classifier is 100 % sure of included. There the severity is how sure stage 2
        is that the flow is that attack: High ≥ 90 %, Medium ≥ 60 %, Low below. Anomalies stage 2
        cannot name (and older models) keep the distance-above-θ rule.
        """
        if (getattr(self.detector, "calibrated_threshold", None) is not None
                and detection.attack_type and detection.confidence is not None):
            if detection.confidence >= 0.9:
                return SeverityLevel.HIGH
            if detection.confidence >= 0.6:
                return SeverityLevel.MEDIUM
            return SeverityLevel.LOW
        return self._severity(detection.anomaly_score, threshold)

    @staticmethod
    def _severity(score: float, threshold: float) -> SeverityLevel:
        """Severity from how far the score is above the threshold."""
        span = max(1.0 - threshold, 1e-6)
        relative = (score - threshold) / span
        if relative >= 0.5:
            return SeverityLevel.HIGH
        if relative >= 0.2:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    async def _broadcast_score(self, flow: FlowRecord, detection: Detection, severity: SeverityLevel,
                               throttle: bool) -> None:
        if throttle:
            now = time.time()
            self._last_score_times = [t for t in self._last_score_times if now - t < 1.0]
            if len(self._last_score_times) >= settings.LIVE_SCORE_MAX_PER_SECOND:
                return
            self._last_score_times.append(now)
        await manager.send_live_score({
            "anomalyScore": round(detection.anomaly_score, 4),
            "severity": severity.value if detection.is_alert else "low",
            "isAlert": detection.is_alert,
            "verdict": "abnormal" if detection.is_alert else "normal",
            "flagged": bool(detection.flagged or detection.is_alert),
            "sourceIp": flow.src_ip,
            "destinationIp": flow.dst_ip,
            "protocol": flow.protocol_name,
            "attackType": detection.attack_type,
        })


ids_service = IDSService()


def get_ids_service() -> IDSService:
    return ids_service
