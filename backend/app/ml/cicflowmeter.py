"""
SecureNet — live capture with CICFlowMeter

CICFlowMeter (the tool the CIC-IDS2018 dataset was made with) turns the network traffic into
flows and writes them to a CSV file. SecureNet runs it headless — `backend/cicflowmeter/
SecureNetLiveCapture.java` on top of CICFlowMeter's own classes, prepared by
`scripts/setup_cicflowmeter.py` — and reads the new CSV rows every few seconds:

    network ─▶ CICFlowMeter (Java, Npcap) ─▶ data/cicflowmeter/flows-<start>.csv ─▶ read every 5 s
             ─▶ FlowRecord (features under the CIC-IDS2018 column names the model was trained on)

CICFlowMeter-4.0 writes longer column names than the CIC-IDS2018 CSVs ("Total Fwd Packet" vs
"Tot Fwd Pkts"); `CIC_TO_DATASET` maps every one of them to the dataset name in lower case, which
is how the trained model names its inputs.
"""

from __future__ import annotations

import csv
import io
import json
import math
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from app.ml.features import FlowRecord
from app.ml.network_monitor import CaptureUnavailable
from app.utils.logger import logger

# CICFlowMeter-4.0 column -> CIC-IDS2018 column (lower case, as the model's inputs are named)
CIC_TO_DATASET: Dict[str, str] = {
    "Dst Port": "dst port", "Protocol": "protocol", "Flow Duration": "flow duration",
    "Total Fwd Packet": "tot fwd pkts", "Total Bwd packets": "tot bwd pkts",
    "Total Length of Fwd Packet": "totlen fwd pkts", "Total Length of Bwd Packet": "totlen bwd pkts",
    "Fwd Packet Length Max": "fwd pkt len max", "Fwd Packet Length Min": "fwd pkt len min",
    "Fwd Packet Length Mean": "fwd pkt len mean", "Fwd Packet Length Std": "fwd pkt len std",
    "Bwd Packet Length Max": "bwd pkt len max", "Bwd Packet Length Min": "bwd pkt len min",
    "Bwd Packet Length Mean": "bwd pkt len mean", "Bwd Packet Length Std": "bwd pkt len std",
    "Flow Bytes/s": "flow byts/s", "Flow Packets/s": "flow pkts/s",
    "Flow IAT Mean": "flow iat mean", "Flow IAT Std": "flow iat std",
    "Flow IAT Max": "flow iat max", "Flow IAT Min": "flow iat min",
    "Fwd IAT Total": "fwd iat tot", "Fwd IAT Mean": "fwd iat mean", "Fwd IAT Std": "fwd iat std",
    "Fwd IAT Max": "fwd iat max", "Fwd IAT Min": "fwd iat min",
    "Bwd IAT Total": "bwd iat tot", "Bwd IAT Mean": "bwd iat mean", "Bwd IAT Std": "bwd iat std",
    "Bwd IAT Max": "bwd iat max", "Bwd IAT Min": "bwd iat min",
    "Fwd PSH Flags": "fwd psh flags", "Bwd PSH Flags": "bwd psh flags",
    "Fwd URG Flags": "fwd urg flags", "Bwd URG Flags": "bwd urg flags",
    "Fwd Header Length": "fwd header len", "Bwd Header Length": "bwd header len",
    "Fwd Packets/s": "fwd pkts/s", "Bwd Packets/s": "bwd pkts/s",
    "Packet Length Min": "pkt len min", "Packet Length Max": "pkt len max",
    "Packet Length Mean": "pkt len mean", "Packet Length Std": "pkt len std",
    "Packet Length Variance": "pkt len var",
    "FIN Flag Count": "fin flag cnt", "SYN Flag Count": "syn flag cnt", "RST Flag Count": "rst flag cnt",
    "PSH Flag Count": "psh flag cnt", "ACK Flag Count": "ack flag cnt", "URG Flag Count": "urg flag cnt",
    "CWR Flag Count": "cwe flag count", "ECE Flag Count": "ece flag cnt",
    "Down/Up Ratio": "down/up ratio", "Average Packet Size": "pkt size avg",
    "Fwd Segment Size Avg": "fwd seg size avg", "Bwd Segment Size Avg": "bwd seg size avg",
    "Fwd Bytes/Bulk Avg": "fwd byts/b avg", "Fwd Packet/Bulk Avg": "fwd pkts/b avg",
    "Fwd Bulk Rate Avg": "fwd blk rate avg", "Bwd Bytes/Bulk Avg": "bwd byts/b avg",
    "Bwd Packet/Bulk Avg": "bwd pkts/b avg", "Bwd Bulk Rate Avg": "bwd blk rate avg",
    "Subflow Fwd Packets": "subflow fwd pkts", "Subflow Fwd Bytes": "subflow fwd byts",
    "Subflow Bwd Packets": "subflow bwd pkts", "Subflow Bwd Bytes": "subflow bwd byts",
    "FWD Init Win Bytes": "init fwd win byts", "Bwd Init Win Bytes": "init bwd win byts",
    "Fwd Act Data Pkts": "fwd act data pkts", "Fwd Seg Size Min": "fwd seg size min",
    "Active Mean": "active mean", "Active Std": "active std", "Active Max": "active max", "Active Min": "active min",
    "Idle Mean": "idle mean", "Idle Std": "idle std", "Idle Max": "idle max", "Idle Min": "idle min",
}

PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}
SKIP_DEVICES = ("loopback", "virtualbox", "vmware", "wi-fi direct", "wan miniport", "bluetooth", "hyper-v")


def _number(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan      # "NaN" / "Infinity" parse; anything else is unknown (the model handles missing)


def record_from_row(row: Dict[str, str]) -> Optional[FlowRecord]:
    """One CICFlowMeter CSV row -> FlowRecord (features under the dataset's column names)."""
    try:
        features = {name: _number(row[col]) for col, name in CIC_TO_DATASET.items() if col in row}
        protocol = int(_number(row.get("Protocol", "0")) or 0)
        fwd, bwd = features.get("tot fwd pkts", 0.0), features.get("tot bwd pkts", 0.0)
        return FlowRecord(
            src_ip=row.get("Src IP", ""), dst_ip=row.get("Dst IP", ""),
            src_port=int(_number(row.get("Src Port", "0")) or 0),
            dst_port=int(_number(row.get("Dst Port", "0")) or 0),
            protocol=protocol, protocol_name=PROTOCOL_NAMES.get(protocol, "other"),
            duration_ms=int((features.get("flow duration") or 0) / 1000),
            fwd_packets=int(fwd if math.isfinite(fwd) else 0), bwd_packets=int(bwd if math.isfinite(bwd) else 0),
            fwd_bytes=int(features.get("totlen fwd pkts") or 0), bwd_bytes=int(features.get("totlen bwd pkts") or 0),
            features=features,
        )
    except (KeyError, ValueError) as exc:
        logger.debug(f"Skipping a CICFlowMeter row: {exc}")
        return None


class CsvTail:
    """Reads the rows appended to a CSV file since the last call (keeps a half-written last line)."""

    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self.header: Optional[List[str]] = None
        self._partial = ""

    def read_new_rows(self) -> List[Dict[str, str]]:
        if not self.path.is_file():
            return []
        with self.path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            fh.seek(self.offset)
            chunk = fh.read()
            self.offset = fh.tell()
        if not chunk:
            return []
        text = self._partial + chunk
        lines = text.split("\n")
        self._partial = lines.pop()          # "" when the chunk ended with a newline
        rows = []
        for line in lines:
            line = line.rstrip("\r")
            if not line:
                continue
            values = next(csv.reader(io.StringIO(line)))
            if self.header is None:
                self.header = [v.strip() for v in values]
                continue
            if len(values) == len(self.header):
                rows.append(dict(zip(self.header, values)))
        return rows


def load_config(tools_dir: Path) -> dict:
    path = tools_dir / "cicflowmeter.json"
    if not path.is_file():
        raise CaptureUnavailable("Live monitoring is not set up yet. Run SETUP.bat again (it prepares CICFlowMeter).")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not Path(config.get("java", "")).is_file():
        raise CaptureUnavailable("Live monitoring needs Java, which was not found. Run SETUP.bat again.")
    return config


def _java(config: dict, *args: str) -> List[str]:
    return [config["java"], f"-Djava.library.path={config['native']}", "-cp", config["classpath"], config["main"], *args]


def _local_ip() -> Optional[str]:
    """This computer's address on the network that has the default route (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def list_devices(config: dict) -> List[dict]:
    result = subprocess.run(_java(config, "--list"), capture_output=True, text=True, timeout=60,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode != 0:
        raise CaptureUnavailable("The network adapters could not be read. Is Npcap installed?")
    devices = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].startswith("\\Device\\"):
            devices.append({"name": parts[0], "description": parts[1],
                            "addresses": parts[2].split() if len(parts) > 2 else []})
    return devices


def choose_device(devices: List[dict], wanted: Optional[str] = None) -> dict:
    """The adapter to watch: CAPTURE_INTERFACE when set (name, part of the description or an IP),
    otherwise the adapter that carries this computer's internet traffic."""
    if wanted:
        w = wanted.lower()
        for d in devices:
            if w == d["name"].lower() or w in d["description"].lower() or wanted in d["addresses"]:
                return d
        raise CaptureUnavailable(f"The network adapter '{wanted}' was not found.")
    ip = _local_ip()
    if ip:
        for d in devices:
            if ip in d["addresses"]:
                return d
    for d in devices:
        usable = [a for a in d["addresses"] if not a.startswith(("127.", "169.254."))]
        if usable and not any(s in d["description"].lower() for s in SKIP_DEVICES):
            return d
    raise CaptureUnavailable("No connected network adapter was found to watch.")


class CicFlowMeterCapture:
    """Runs CICFlowMeter for live capture and reads the flows it writes to the CSV file."""

    def __init__(self, tools_dir: Path, csv_path: Path, interface: Optional[str] = None, idle_seconds: int = 15):
        self.tools_dir = tools_dir
        self.csv_path = csv_path
        self.interface = interface
        self.idle_seconds = idle_seconds
        self.device: Optional[dict] = None
        self.process: Optional[subprocess.Popen] = None
        self.tail = CsvTail(csv_path)
        self.packet_count = 0
        self.flow_count = 0             # flows written by CICFlowMeter
        self.active_flow_count = 0      # flows still open inside CICFlowMeter
        self.last_error: Optional[str] = None
        self._ready = threading.Event()
        self._stderr: List[str] = []

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self) -> None:
        """Start CICFlowMeter on the adapter; raises CaptureUnavailable when it cannot capture."""
        config = load_config(self.tools_dir)
        self.device = choose_device(list_devices(config), self.interface)
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self.process = subprocess.Popen(
            _java(config, self.device["name"], str(self.csv_path), str(self.idle_seconds)),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        threading.Thread(target=self._read_stdout, name="cicflowmeter-out", daemon=True).start()
        threading.Thread(target=self._read_stderr, name="cicflowmeter-err", daemon=True).start()
        deadline = time.time() + 30
        while not self._ready.wait(0.2):
            if self.process.poll() is not None or time.time() > deadline:
                detail = " ".join(l for l in self._stderr if not l.startswith("SLF4J")) or "no reason given"
                self.stop()
                logger.error(f"CICFlowMeter did not start on {self.device['description']}: {detail}")
                raise CaptureUnavailable("Live monitoring could not start on this computer's network adapter. "
                                         "Make sure Npcap is installed, then try again.")
        logger.info(f"CICFlowMeter capturing on {self.device['description']} → {self.csv_path}")

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "READY":
                self._ready.set()
            elif parts[0] == "STATS" and len(parts) >= 4:
                self.packet_count, self.flow_count, self.active_flow_count = (int(p) for p in parts[1:4])
            elif parts[0] == "STOPPED" and len(parts) >= 3:
                self.packet_count, self.flow_count = int(parts[1]), int(parts[2])
                self.active_flow_count = 0

    def _read_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        for line in self.process.stderr:
            line = line.strip()
            if line:
                self._stderr = (self._stderr + [line])[-20:]
                if line.startswith("ERROR"):
                    self.last_error = "Live capture stopped unexpectedly."
                    logger.error(f"CICFlowMeter: {line}")

    def read_new_records(self) -> List[FlowRecord]:
        records = []
        for row in self.tail.read_new_rows():
            record = record_from_row(row)
            if record is not None:
                records.append(record)
        return records

    def stop(self) -> None:
        """Ask CICFlowMeter to finish (it writes the open flows), then make sure it is gone."""
        process, self.process = self.process, None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(timeout=5)
        self.process = None
