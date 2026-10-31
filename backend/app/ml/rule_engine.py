"""
SecureNet — Behavioural rule layer (additive second opinion)

Signature IDS like Snort/Suricata match patterns in packet *payloads*; our input is
CICFlowMeter *flow* records (no payloads), so payload signatures don't apply here.
What does apply to flow data — and what the per-flow XGBoost model is blind to — are
the classic *cross-flow* threshold rules used by Zeek/Suricata: count events from one
source over a sliding window and flag a scan / sweep / brute-force / flood.

This engine is **additive help only**:
  * it runs on the SAME finished flows the model scores, inside the single IDS worker
    (so no locking is needed);
  * it NEVER cancels or weakens a model decision — `ids_service` only consults it for a
    flow the model called *Benign*, and uses a rule hit to raise an extra alert;
  * thresholds are deliberately conservative so ordinary traffic does not trip them, and
    a per-(source, rule) cooldown stops one attack from alerting on every single flow.

Thresholds are starting points (Zeek defaults: ~30 ports / 5 min vertical, ~20 hosts /
5 min horizontal; Emerging-Threats SSH scan: 5 in 120 s) tuned for live lab traffic.
Change the constants below to fit your network.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple

from app.ml.features import FlowRecord

# ── thresholds (tune to your traffic) ──────────────────────────────────────────
PORTSCAN_PORTS = 20          # distinct destination ports from one source …
PORTSCAN_WINDOW = 60.0       # … within this many seconds  → vertical port scan
SWEEP_HOSTS = 20             # distinct destination IPs from one source …
SWEEP_WINDOW = 60.0          # … within this many seconds  → horizontal network sweep
BRUTE_COUNT = 10             # connections from one source to one service …
BRUTE_WINDOW = 60.0          # … within this many seconds  → brute force
FLOOD_COUNT = 200            # flows from one source to one destination …
FLOOD_WINDOW = 10.0          # … within this many seconds  → flood (possible DoS)
ICMP_COUNT = 100             # ICMP flows from one source …
ICMP_WINDOW = 10.0           # … within this many seconds  → ICMP flood

# service ports where repeated connections mean credential brute force (not browsing)
BRUTE_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}

HIT_COOLDOWN = 30.0          # one alert per (source, rule) per this many seconds
MAX_TRACKED = 50_000         # cap tracked sources so memory stays bounded


@dataclass
class RuleHit:
    label: str
    reason: str
    severity: str            # "high" | "medium" | "low" (informational; score drives severity)
    score: float             # synthetic anomaly score (maps to severity in ids_service)


def _prune(q: Deque[float], cutoff: float) -> None:
    while q and q[0] < cutoff:
        q.popleft()


def _prune2(q: "Deque[Tuple[float, object]]", cutoff: float) -> None:
    while q and q[0][0] < cutoff:
        q.popleft()


class RuleEngine:
    """Stateful sliding-window behavioural rules. One instance per IDS, reset on start."""

    def __init__(self) -> None:
        self.enabled = True
        self.hits = 0
        self._ports: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)   # src -> (t, dport)
        self._hosts: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)   # src -> (t, dstip)
        self._brute: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(deque)  # (src,dst,port) -> t
        self._flood: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)   # (src,dst) -> t
        self._icmp: Dict[str, Deque[float]] = defaultdict(deque)                # src -> t
        self._last_hit: Dict[Tuple[str, str], float] = {}                       # (src,label) -> t

    def reset(self) -> None:
        self.hits = 0
        for d in (self._ports, self._hosts, self._brute, self._flood, self._icmp, self._last_hit):
            d.clear()

    def _bound(self) -> None:
        """Keep memory bounded: if too many sources are tracked, drop the ones that have
        aged out (empty deques). Crude but safe and O(n) only when the cap is hit."""
        if len(self._ports) <= MAX_TRACKED:
            return
        for store in (self._ports, self._hosts, self._icmp):
            for k in [k for k, q in store.items() if not q]:
                del store[k]
        for store in (self._brute, self._flood):
            for k in [k for k, q in store.items() if not q]:
                del store[k]

    def update_and_check(self, flow: FlowRecord) -> Optional[RuleHit]:
        """Record `flow` in the sliding windows and return a RuleHit if a threshold is crossed.
        Checked most-severe first; a per-(source, rule) cooldown prevents per-flow alert floods."""
        if not self.enabled:
            return None
        now = time.time()
        src = flow.src_ip
        dst = flow.dst_ip
        dport = int(flow.dst_port or 0)
        proto = (flow.protocol_name or "").upper()
        self._bound()

        # ICMP flood (ICMP has no ports → its own counter)
        if proto == "ICMP":
            q = self._icmp[src]
            q.append(now)
            _prune(q, now - ICMP_WINDOW)
            if len(q) >= ICMP_COUNT:
                return self._fire(src, "ICMP flood", "high", 0.95, now,
                                  f"{len(q)} ICMP flows from {src} in {int(ICMP_WINDOW)}s")
            return None

        # flood: many flows from one source to one destination in a short window
        fq = self._flood[(src, dst)]
        fq.append(now)
        _prune(fq, now - FLOOD_WINDOW)

        # brute force: repeated connections to one service port
        brute_hit = False
        if dport in BRUTE_PORTS:
            bq = self._brute[(src, dst, dport)]
            bq.append(now)
            _prune(bq, now - BRUTE_WINDOW)
            brute_hit = len(bq) >= BRUTE_COUNT

        # vertical port scan: distinct destination ports from one source
        pq = self._ports[src]
        pq.append((now, dport))
        _prune2(pq, now - PORTSCAN_WINDOW)
        distinct_ports = len({p for _, p in pq})

        # horizontal sweep: distinct destination hosts from one source
        hq = self._hosts[src]
        hq.append((now, dst))
        _prune2(hq, now - SWEEP_WINDOW)
        distinct_hosts = len({d for _, d in hq})

        # fire in priority order (most severe first)
        if len(fq) >= FLOOD_COUNT:
            return self._fire(src, "Flood (possible DoS)", "high", 0.95, now,
                              f"{len(fq)} flows from {src} to {dst} in {int(FLOOD_WINDOW)}s")
        if brute_hit:
            return self._fire(src, "Brute-force attempt", "high", 0.9, now,
                              f"{BRUTE_COUNT}+ connections from {src} to {dst}:{dport} in {int(BRUTE_WINDOW)}s")
        if distinct_ports >= PORTSCAN_PORTS:
            return self._fire(src, "Port scan (recon)", "medium", 0.7, now,
                              f"{distinct_ports} ports probed from {src} in {int(PORTSCAN_WINDOW)}s")
        if distinct_hosts >= SWEEP_HOSTS:
            return self._fire(src, "Network sweep (recon)", "medium", 0.7, now,
                              f"{distinct_hosts} hosts contacted from {src} in {int(SWEEP_WINDOW)}s")
        return None

    def _fire(self, src: str, label: str, severity: str, score: float, now: float,
              detail: str) -> Optional[RuleHit]:
        key = (src, label)
        if now - self._last_hit.get(key, 0.0) < HIT_COOLDOWN:
            return None
        self._last_hit[key] = now
        self.hits += 1
        return RuleHit(label=label, severity=severity, score=score,
                       reason=f"Behavioural rule: {label.lower()} — {detail}.")
