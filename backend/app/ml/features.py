"""
SecureNet — CICIDS2018 flow features

Builds the CICFlowMeter-style feature vector that the trained models expect
(the 71 columns saved in models/feature_columns.pkl) from live packets.

Units follow CICIDS2018: all durations / inter-arrival times are in
MICROSECONDS, packet "lengths" are L4 payload sizes in bytes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Default feature order (identical to backend/models/feature_columns.pkl).
# A loaded model may override this with its own saved column list.
FEATURE_COLUMNS: List[str] = [
    "Dst Port", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt",
    "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
    "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
    "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "Protocol_0", "Protocol_6", "Protocol_17",
    # used by the retrained hybrid model (cleaned_dataset_2: protocol number, not one-hot)
    "Protocol", "Fwd URG Flags",
]

# CICFlowMeter default activity timeout (µs): a gap longer than this splits
# the flow into active / idle periods.
ACTIVITY_TIMEOUT_US = 5_000_000

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _stats(values: List[float]) -> tuple[float, float, float, float]:
    """(min, max, mean, population std) — zeros for an empty list."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    return float(min(values)), float(max(values)), float(mean), math.sqrt(var)


@dataclass
class PacketInfo:
    """The per-packet fields the flow tracker needs (extracted from Scapy)."""
    timestamp: float          # seconds (packet capture time)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int             # IP protocol number
    payload_len: int          # L4 payload bytes
    header_len: int           # L4 header bytes
    flags: str = ""           # TCP flags, e.g. "SA"
    window: Optional[int] = None


@dataclass
class Flow:
    """Bidirectional flow; 'forward' is the direction of the first packet."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start: float
    last: float = 0.0

    fwd_lens: List[int] = field(default_factory=list)
    bwd_lens: List[int] = field(default_factory=list)
    fwd_times: List[float] = field(default_factory=list)
    bwd_times: List[float] = field(default_factory=list)
    all_times: List[float] = field(default_factory=list)
    fwd_header_bytes: int = 0
    bwd_header_bytes: int = 0
    fwd_header_min: Optional[int] = None
    fwd_psh: int = 0
    fwd_urg: int = 0
    flag_counts: Dict[str, int] = field(default_factory=lambda: {k: 0 for k in "FSRPAUEC"})
    init_fwd_win: int = -1
    init_bwd_win: int = -1
    fwd_act_data: int = 0
    fwd_fin: bool = False
    bwd_fin: bool = False
    rst: bool = False

    # active / idle tracking (µs)
    active_start: float = 0.0
    active_periods: List[float] = field(default_factory=list)
    idle_periods: List[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.last = self.start
        self.active_start = self.start

    @property
    def protocol_name(self) -> str:
        return PROTO_NAMES.get(self.protocol, "other")

    @property
    def packet_count(self) -> int:
        return len(self.fwd_lens) + len(self.bwd_lens)

    @property
    def is_finished(self) -> bool:
        """TCP teardown seen (RST, or FIN in both directions)."""
        return self.rst or (self.fwd_fin and self.bwd_fin)

    def add(self, pkt: PacketInfo, forward: bool) -> None:
        ts = pkt.timestamp
        gap_us = (ts - self.last) * 1e6
        if self.all_times and gap_us > ACTIVITY_TIMEOUT_US:
            self.active_periods.append((self.last - self.active_start) * 1e6)
            self.idle_periods.append(gap_us)
            self.active_start = ts
        self.all_times.append(ts)
        self.last = ts

        for flag in pkt.flags:
            if flag in self.flag_counts:
                self.flag_counts[flag] += 1
        if "R" in pkt.flags:
            self.rst = True

        if forward:
            self.fwd_lens.append(pkt.payload_len)
            self.fwd_times.append(ts)
            self.fwd_header_bytes += pkt.header_len
            self.fwd_header_min = (
                pkt.header_len if self.fwd_header_min is None else min(self.fwd_header_min, pkt.header_len)
            )
            if "P" in pkt.flags:
                self.fwd_psh += 1
            if "U" in pkt.flags:
                self.fwd_urg += 1
            if pkt.payload_len > 0:
                self.fwd_act_data += 1
            if self.init_fwd_win < 0 and pkt.window is not None:
                self.init_fwd_win = pkt.window
            if "F" in pkt.flags:
                self.fwd_fin = True
        else:
            self.bwd_lens.append(pkt.payload_len)
            self.bwd_times.append(ts)
            self.bwd_header_bytes += pkt.header_len
            if self.init_bwd_win < 0 and pkt.window is not None:
                self.init_bwd_win = pkt.window
            if "F" in pkt.flags:
                self.bwd_fin = True

    def extract_features(self) -> Dict[str, float]:
        """Compute the CICIDS2018 feature dictionary for this flow."""
        duration_us = max((self.last - self.start) * 1e6, 0.0)
        duration_s = duration_us / 1e6

        n_fwd, n_bwd = len(self.fwd_lens), len(self.bwd_lens)
        tot_fwd, tot_bwd = float(sum(self.fwd_lens)), float(sum(self.bwd_lens))
        all_lens = self.fwd_lens + self.bwd_lens

        fwd_min, fwd_max, fwd_mean, fwd_std = _stats(self.fwd_lens)
        bwd_min, bwd_max, bwd_mean, bwd_std = _stats(self.bwd_lens)
        pkt_min, pkt_max, pkt_mean, pkt_std = _stats(all_lens)

        def iats(times: List[float]) -> List[float]:
            return [(b - a) * 1e6 for a, b in zip(times, times[1:])]

        flow_iat = iats(self.all_times)
        fwd_iat = iats(self.fwd_times)
        bwd_iat = iats(self.bwd_times)
        fi_min, fi_max, fi_mean, fi_std = _stats(flow_iat)
        fw_min, fw_max, fw_mean, fw_std = _stats(fwd_iat)
        bw_min, bw_max, bw_mean, bw_std = _stats(bwd_iat)

        active = self.active_periods + [(self.last - self.active_start) * 1e6]
        active = [a for a in active if a > 0]
        ac_min, ac_max, ac_mean, ac_std = _stats(active if self.idle_periods else [])
        id_min, id_max, id_mean, id_std = _stats(self.idle_periods)

        per_sec = (lambda v: v / duration_s) if duration_s > 0 else (lambda v: 0.0)

        return {
            "Dst Port": float(self.dst_port),
            "Flow Duration": duration_us,
            "Tot Fwd Pkts": float(n_fwd),
            "Tot Bwd Pkts": float(n_bwd),
            "TotLen Fwd Pkts": tot_fwd,
            "TotLen Bwd Pkts": tot_bwd,
            "Fwd Pkt Len Max": fwd_max,
            "Fwd Pkt Len Min": fwd_min,
            "Fwd Pkt Len Mean": fwd_mean,
            "Fwd Pkt Len Std": fwd_std,
            "Bwd Pkt Len Max": bwd_max,
            "Bwd Pkt Len Min": bwd_min,
            "Bwd Pkt Len Mean": bwd_mean,
            "Bwd Pkt Len Std": bwd_std,
            "Flow Byts/s": per_sec(tot_fwd + tot_bwd),
            "Flow Pkts/s": per_sec(float(n_fwd + n_bwd)),
            "Flow IAT Mean": fi_mean,
            "Flow IAT Std": fi_std,
            "Flow IAT Max": fi_max,
            "Flow IAT Min": fi_min,
            "Fwd IAT Tot": float(sum(fwd_iat)),
            "Fwd IAT Mean": fw_mean,
            "Fwd IAT Std": fw_std,
            "Fwd IAT Max": fw_max,
            "Fwd IAT Min": fw_min,
            "Bwd IAT Tot": float(sum(bwd_iat)),
            "Bwd IAT Mean": bw_mean,
            "Bwd IAT Std": bw_std,
            "Bwd IAT Max": bw_max,
            "Bwd IAT Min": bw_min,
            "Fwd PSH Flags": float(self.fwd_psh),
            "Fwd Header Len": float(self.fwd_header_bytes),
            "Bwd Header Len": float(self.bwd_header_bytes),
            "Fwd Pkts/s": per_sec(float(n_fwd)),
            "Bwd Pkts/s": per_sec(float(n_bwd)),
            "Pkt Len Min": pkt_min,
            "Pkt Len Max": pkt_max,
            "Pkt Len Mean": pkt_mean,
            "Pkt Len Std": pkt_std,
            "Pkt Len Var": pkt_std ** 2,
            "FIN Flag Cnt": float(self.flag_counts["F"]),
            "SYN Flag Cnt": float(self.flag_counts["S"]),
            "RST Flag Cnt": float(self.flag_counts["R"]),
            "PSH Flag Cnt": float(self.flag_counts["P"]),
            "ACK Flag Cnt": float(self.flag_counts["A"]),
            "URG Flag Cnt": float(self.flag_counts["U"]),
            "CWE Flag Count": float(self.flag_counts["C"]),
            "ECE Flag Cnt": float(self.flag_counts["E"]),
            "Down/Up Ratio": float(n_bwd / n_fwd) if n_fwd else 0.0,
            "Pkt Size Avg": pkt_mean,
            "Fwd Seg Size Avg": fwd_mean,
            "Bwd Seg Size Avg": bwd_mean,
            "Subflow Fwd Pkts": float(n_fwd),
            "Subflow Fwd Byts": tot_fwd,
            "Subflow Bwd Pkts": float(n_bwd),
            "Subflow Bwd Byts": tot_bwd,
            "Init Fwd Win Byts": float(self.init_fwd_win),
            "Init Bwd Win Byts": float(self.init_bwd_win),
            "Fwd Act Data Pkts": float(self.fwd_act_data),
            "Fwd Seg Size Min": float(self.fwd_header_min or 0),
            "Active Mean": ac_mean,
            "Active Std": ac_std,
            "Active Max": ac_max,
            "Active Min": ac_min,
            "Idle Mean": id_mean,
            "Idle Std": id_std,
            "Idle Max": id_max,
            "Idle Min": id_min,
            "Protocol_0": 1.0 if self.protocol == 0 else 0.0,
            "Protocol_6": 1.0 if self.protocol == 6 else 0.0,
            "Protocol_17": 1.0 if self.protocol == 17 else 0.0,
            "Protocol": float(self.protocol),
            "Fwd URG Flags": float(self.fwd_urg),
        }


@dataclass
class FlowRecord:
    """A finished flow handed from the capture thread to the IDS worker."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    protocol_name: str
    duration_ms: int
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    features: Dict[str, float]

    @classmethod
    def from_flow(cls, flow: Flow) -> "FlowRecord":
        return cls(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            protocol_name=flow.protocol_name,
            duration_ms=int((flow.last - flow.start) * 1000),
            fwd_packets=len(flow.fwd_lens),
            bwd_packets=len(flow.bwd_lens),
            fwd_bytes=int(sum(flow.fwd_lens)),
            bwd_bytes=int(sum(flow.bwd_lens)),
            features=flow.extract_features(),
        )
