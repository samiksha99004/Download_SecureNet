"""CsvFlowSource — feeds SecureNet from our proven live pipeline instead of scapy.

Our model was trained on flows from the real Java CICFlowMeter-4.0. To avoid train/serve skew we
must score flows from that SAME tool, so this capture source does NOT sniff packets itself. It
tails the CSV folder that our existing `live_ids/1_capture_windivert.py` + `2_convert.py` produce
(the two admin terminals you already run), parses each finished flow row, and hands it to the IDS
worker as a `FlowRecord` whose `.features` is the raw CICFlowMeter-4.0 row. The dashboard then shows
exactly what the CLI `live_status.py` used to print.

Drop-in for `NetworkMonitor`: same constructor kwargs and the same .start()/.stop()/.running/
.packet_count/.active_flow_count/.last_error surface the IDS service reads.
"""
from __future__ import annotations

import csv
import glob
import os
import subprocess
import threading
import time
from typing import Callable, List, Optional

from app.ml.features import FlowRecord
from app.ml.network_monitor import CaptureUnavailable
from app.utils.logger import logger

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT"}
WRITE_SETTLE_SECONDS = 3   # only read a CSV whose mtime is older than this (fully written)
POLL_SECONDS = 2
# the two capture scripts the app launches so the user never touches a terminal
CAPTURE_SCRIPT = os.path.join("live_ids", "1_capture_windivert.py")   # WinDivert -> rotating pcap (needs admin)
CONVERT_SCRIPT = os.path.join("live_ids", "2_convert.py")             # pcap -> CICFlowMeter-4.0 CSV


def _num(row: dict, *keys) -> float:
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


class CsvFlowSource:
    def __init__(self, on_flow: Callable[[FlowRecord], None], csv_dir: str,
                 interface: Optional[str] = None, idle_timeout: float = 0.0,
                 active_timeout: float = 0.0, spawn: bool = True,
                 project_dir: str = "", python_exe: str = ""):
        self.on_flow = on_flow
        self.csv_dir = csv_dir
        # interface/timeouts are accepted for a drop-in signature but unused (flows come from CSV)
        self.spawn = spawn                 # True = app launches capture+convert itself (no terminals)
        self.project_dir = project_dir     # folder that holds live_ids/ (and the capture scripts)
        self.python_exe = python_exe       # the project venv python that has pydivert + scapy
        self._procs: List[subprocess.Popen] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: set = set()
        self.packet_count = 0
        self.flow_count = 0
        self.last_error: Optional[str] = None

    # ── interface the IDS service reads ──────────────────────────────────────
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def active_flow_count(self) -> int:
        return 0   # file-based: no in-progress flow table

    def start(self) -> None:
        try:
            os.makedirs(self.csv_dir, exist_ok=True)
        except OSError as exc:
            raise CaptureUnavailable(f"CSV folder unavailable: {self.csv_dir} ({exc})")
        self._clear_stale()            # avoid re-reading the previous run's flows (known stale-data bug)
        if self.spawn:
            self._spawn_capture()      # app launches capture + convert itself — no terminals for the user
        # ingest everything from now on (folder was just cleared)
        self._seen = set()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="csv-flow-source", daemon=True)
        self._thread.start()
        logger.info(f"CsvFlowSource started (watching {self.csv_dir}; spawn={self.spawn})")

    def _clear_stale(self) -> None:
        base = os.path.dirname(self.csv_dir)   # live_ids/
        for sub in ("pcap", "csv", "results"):
            for f in glob.glob(os.path.join(base, sub, "*")):
                try:
                    os.remove(f)
                except OSError:
                    pass   # a pcap still held open by a previous capture — harmless, it'll rotate out

    def _spawn_capture(self) -> None:
        if not self.project_dir or not self.python_exe:
            self.last_error = "capture auto-start not configured (LIVE_PROJECT_DIR / LIVE_PYTHON)"
            logger.warning(self.last_error)
            return
        if not os.path.isfile(self.python_exe):
            self.last_error = f"project python not found: {self.python_exe}"
            logger.error(self.last_error)
            return
        log_dir = os.path.dirname(self.csv_dir)
        self._err_log = os.path.join(log_dir, "capture_stderr.log")
        for script in (CAPTURE_SCRIPT, CONVERT_SCRIPT):
            path = os.path.join(self.project_dir, script)
            if not os.path.isfile(path):
                self.last_error = f"capture script missing: {path}"
                logger.error(self.last_error)
                continue
            try:
                errf = open(self._err_log, "a", buffering=1)
                errf.write(f"\n--- {script} @ {time.strftime('%H:%M:%S')} ---\n")
                # CREATE_NO_WINDOW: run the capture + convert helpers with NO console window, so the
                # user never sees terminals pop up (output still goes to DEVNULL / the stderr log).
                p = subprocess.Popen([self.python_exe, script], cwd=self.project_dir,
                                     stdout=subprocess.DEVNULL, stderr=errf,
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                self._procs.append(p)
                logger.info(f"launched capture subprocess: {script} (pid {p.pid})")
            except OSError as exc:
                self.last_error = f"could not launch {script}: {exc}"
                logger.error(self.last_error)
        # NOTE: no blocking wait here — turning the IDS ON must be instant. If the WinDivert
        # capturer dies quickly (almost always 'not Administrator'), the background loop reports it.

    def _check_capture_alive(self) -> None:
        """Non-blocking capture-health check, run once by the loop ~2s after start."""
        if self._procs and self._procs[0].poll() is not None:
            tail = ""
            try:
                with open(getattr(self, "_err_log", ""), encoding="utf-8", errors="replace") as fh:
                    tail = fh.read()[-300:].strip().replace("\n", " ")
            except OSError:
                pass
            self.last_error = ("Live capture could not start — run SecureNet as Administrator "
                               "(packet capture needs admin)." + (f" [{tail}]" if tail else ""))
            logger.error(self.last_error)

    def stop(self) -> None:
        self._stop.set()
        for p in self._procs:
            try:
                p.terminate()
            except OSError:
                pass
        self._procs = []
        t, self._thread = self._thread, None
        if t is not None:
            t.join(timeout=3)

    # ── worker loop ──────────────────────────────────────────────────────────
    def _loop(self) -> None:
        iters = 0
        while not self._stop.is_set():
            try:
                self._ingest_new()
            except Exception as exc:
                self.last_error = str(exc)
                logger.error(f"CsvFlowSource error: {exc}", exc_info=True)
            iters += 1
            if self.spawn and iters == 2:   # ~POLL_SECONDS after start: capturer had time to fail
                self._check_capture_alive()
            self._stop.wait(POLL_SECONDS)

    def _ingest_new(self) -> None:
        now = time.time()
        for path in sorted(glob.glob(os.path.join(self.csv_dir, "*.csv"))):
            if path in self._seen:
                continue
            if now - os.path.getmtime(path) < WRITE_SETTLE_SECONDS:
                continue   # still being written by the converter
            self._seen.add(path)
            try:
                with open(path, newline="", encoding="utf-8", errors="replace") as fh:
                    for row in csv.DictReader(fh):
                        self._emit(row)
            except OSError as exc:
                self.last_error = f"{os.path.basename(path)}: {exc}"

    def _emit(self, row: dict) -> None:
        try:
            proto = int(_num(row, "Protocol"))
        except (TypeError, ValueError):
            proto = 0
        fwd_pkts = int(_num(row, "Total Fwd Packet", "Tot Fwd Pkts"))
        bwd_pkts = int(_num(row, "Total Bwd packets", "Tot Bwd Pkts"))
        record = FlowRecord(
            src_ip=(row.get("Src IP") or "").strip(),
            dst_ip=(row.get("Dst IP") or "").strip(),
            src_port=int(_num(row, "Src Port")),
            dst_port=int(_num(row, "Dst Port")),
            protocol=proto,
            protocol_name=PROTO_NAMES.get(proto, str(proto)),
            duration_ms=int(_num(row, "Flow Duration") / 1000.0),   # CICFlowMeter µs -> ms
            fwd_packets=fwd_pkts,
            bwd_packets=bwd_pkts,
            fwd_bytes=int(_num(row, "Total Length of Fwd Packet", "TotLen Fwd Pkts")),
            bwd_bytes=int(_num(row, "Total Length of Bwd Packet", "TotLen Bwd Pkts")),
            features=row,   # raw CICFlowMeter-4.0 row; LocalModel maps it via JAVA_COLUMN
        )
        self.packet_count += fwd_pkts + bwd_pkts
        self.flow_count += 1
        try:
            self.on_flow(record)
        except Exception as exc:
            logger.error(f"on_flow failed: {exc}")
