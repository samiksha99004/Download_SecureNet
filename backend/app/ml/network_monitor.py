"""
SecureNet — Live packet capture and flow assembly

Captures packets with Scapy, groups them into bidirectional flows and hands
each *finished* flow (TCP teardown, idle timeout or active timeout) to a
callback exactly once. The callback runs on a capture/housekeeping thread, so
it must be thread-safe (the IDS service forwards records into its asyncio
queue with loop.call_soon_threadsafe).
"""

from __future__ import annotations

import os
import platform
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from app.ml.features import Flow, FlowRecord, PacketInfo
from app.utils.logger import logger

FlowKey = Tuple[str, str, int, int, int]

# Limits that keep a packet flood from exhausting memory (an attacker spraying random
# ports would otherwise create millions of open flows, or one endless flow):
MAX_ACTIVE_FLOWS = 50_000        # oldest open flow is finished early when full
MAX_PACKETS_PER_FLOW = 20_000    # a flow this long is finished and scored (a new one starts)


class CaptureUnavailable(RuntimeError):
    """Raised when live packet capture cannot run on this machine."""


def check_capture_available() -> None:
    """Raise CaptureUnavailable with an actionable message if sniffing can't work."""
    try:
        # Import Scapy fully: on Windows `conf.use_pcap` only becomes True once the platform
        # layer (scapy.arch.windows) has loaded and found Npcap. Checking scapy.config alone
        # always saw False, so the IDS refused to start even with Npcap installed.
        import scapy.all  # noqa: F401
        from scapy.config import conf
    except ImportError as exc:  # pragma: no cover - scapy is a hard dependency
        raise CaptureUnavailable("Network monitoring is not installed completely. Run SETUP.bat again.") from exc

    system = platform.system()
    if system == "Windows":
        if not conf.use_pcap:
            raise CaptureUnavailable(
                "The IDS can't start on this computer yet. It needs a one-time setup: install Npcap "
                "from npcap.com, then start SecureNet as Administrator."
            )
    elif system in ("Linux", "Darwin"):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise CaptureUnavailable(
                "The IDS can't start yet: start SecureNet with administrator (root) rights."
            )


def _packet_info(packet) -> Optional[PacketInfo]:
    """Extract the fields we need from a Scapy packet (None for non-IP)."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6

    if IP in packet:
        ip = packet[IP]
        proto = int(ip.proto)
        src, dst = ip.src, ip.dst
    elif IPv6 in packet:
        ip = packet[IPv6]
        proto = int(ip.nh)
        src, dst = ip.src, ip.dst
    else:
        return None

    ts = float(packet.time)
    if TCP in packet:
        tcp = packet[TCP]
        header = int(tcp.dataofs or 5) * 4
        return PacketInfo(ts, src, dst, int(tcp.sport), int(tcp.dport), 6,
                          len(tcp.payload), header, str(tcp.flags), int(tcp.window))
    if UDP in packet:
        udp = packet[UDP]
        return PacketInfo(ts, src, dst, int(udp.sport), int(udp.dport), 17, len(udp.payload), 8)
    if ICMP in packet:
        icmp = packet[ICMP]
        return PacketInfo(ts, src, dst, 0, 0, 1, len(icmp.payload), 8)
    return PacketInfo(ts, src, dst, 0, 0, proto, 0, 0)


class NetworkMonitor:
    """Scapy-based flow monitor."""

    def __init__(
        self,
        on_flow: Callable[[FlowRecord], None],
        interface: Optional[str] = None,
        idle_timeout: float = 15.0,
        active_timeout: float = 120.0,
    ):
        self.on_flow = on_flow
        self.interface = interface or None
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout

        self._flows: Dict[FlowKey, Flow] = {}
        self._lock = threading.Lock()
        self._sniffer = None
        self._housekeeper: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self.packet_count = 0
        self.flow_count = 0
        self.flows_evicted = 0
        self.last_error: Optional[str] = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._sniffer is not None and not self._stop.is_set()

    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def start(self) -> None:
        """Start capturing. Raises CaptureUnavailable if sniffing can't start."""
        check_capture_available()
        from scapy.sendrecv import AsyncSniffer

        self._stop.clear()
        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                filter="ip or ip6",
            )
            self._sniffer.start()
        except Exception as exc:  # permission errors, bad interface, …
            self._sniffer = None
            raise CaptureUnavailable(f"Could not start packet capture: {exc}") from exc

        # Give the sniffer thread a moment to fail fast (e.g. no permission).
        time.sleep(0.5)
        thread = getattr(self._sniffer, "thread", None)
        if thread is not None and not thread.is_alive():
            self._sniffer = None
            raise CaptureUnavailable(
                "Packet capture stopped immediately — run the backend as Administrator/root "
                "and check CAPTURE_INTERFACE."
            )

        self._housekeeper = threading.Thread(target=self._housekeeping, name="flow-housekeeper", daemon=True)
        self._housekeeper.start()
        logger.info(f"Packet capture started (interface={self.interface or 'default'})")

    def stop(self) -> None:
        """Stop capturing and flush all in-progress flows."""
        self._stop.set()
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop(join=True)
            except Exception as exc:  # stop() raises if the sniffer already died
                logger.debug(f"Sniffer stop: {exc}")
        if self._housekeeper is not None:
            self._housekeeper.join(timeout=3)
            self._housekeeper = None
        self._flush(lambda flow, now: True)
        logger.info("Packet capture stopped")

    # ── packet path (sniffer thread) ─────────────────────────────────────────

    def _handle_packet(self, packet) -> None:
        try:
            info = _packet_info(packet)
            if info is None:
                return
            finished: Optional[Flow] = None
            evicted: Optional[Flow] = None
            fwd_key: FlowKey = (info.src_ip, info.dst_ip, info.src_port, info.dst_port, info.protocol)
            bwd_key: FlowKey = (info.dst_ip, info.src_ip, info.dst_port, info.src_port, info.protocol)
            with self._lock:
                self.packet_count += 1
                if fwd_key in self._flows:
                    flow, forward, key = self._flows[fwd_key], True, fwd_key
                elif bwd_key in self._flows:
                    flow, forward, key = self._flows[bwd_key], False, bwd_key
                else:
                    if len(self._flows) >= MAX_ACTIVE_FLOWS:
                        # dicts keep insertion order: the first one is the oldest open flow
                        evicted = self._flows.pop(next(iter(self._flows)))
                        self.flows_evicted += 1
                    flow = Flow(info.src_ip, info.dst_ip, info.src_port, info.dst_port, info.protocol,
                                start=info.timestamp)
                    self._flows[fwd_key] = flow
                    forward, key = True, fwd_key
                flow.add(info, forward)
                if flow.is_finished or flow.packet_count >= MAX_PACKETS_PER_FLOW:
                    finished = self._flows.pop(key)
            if evicted is not None:
                self._emit(evicted)
            if finished is not None:
                self._emit(finished)
        except Exception as exc:
            logger.debug(f"Packet handling error: {exc}")

    # ── housekeeping thread ──────────────────────────────────────────────────

    def _housekeeping(self) -> None:
        while not self._stop.wait(1.0):
            self._flush(
                lambda flow, now: (now - flow.last) > self.idle_timeout
                or (now - flow.start) > self.active_timeout
            )
            sniffer = self._sniffer
            thread = getattr(sniffer, "thread", None) if sniffer else None
            if thread is not None and not thread.is_alive() and not self._stop.is_set():
                self.last_error = "Packet capture thread stopped unexpectedly"
                logger.error(self.last_error)
                break

    def _flush(self, should_expire) -> None:
        now = time.time()
        with self._lock:
            expired = [key for key, flow in self._flows.items() if should_expire(flow, now)]
            flows = [self._flows.pop(key) for key in expired]
        for flow in flows:
            self._emit(flow)

    def _emit(self, flow: Flow) -> None:
        self.flow_count += 1
        try:
            self.on_flow(FlowRecord.from_flow(flow))
        except Exception as exc:
            logger.error(f"Flow callback error: {exc}")
