"""Scenario 1 (VM -> same machine), correct architecture: Windows (the victim) captures its OWN
incoming traffic with WinDivert. The Kali VM only attacks - it is never involved in capture.

WHY WinDivert, not Npcap: confirmed 4 ways that VM->host traffic on a VirtualBox Host-only
adapter never reaches Npcap (it bypasses the NDIS chain Npcap hooks). WinDivert hooks the Windows
Filtering Platform instead and DOES see it. See CLAUDE.md.

TWO CAPTURE BUGS FOUND AND FIXED 2026-10-18 (why Slowloris scored 100% Benign before):
1. PACKET LOSS: the old version used WinDivert in divert mode and re-injected every packet with
   w.send() one-at-a-time in Python. Under attack-rate traffic this couldn't keep up - ~75% of
   packets were dropped (pcaps 5s apart only held ~3.6s each, and backward/server packets went
   missing, zeroing out tot-bwd-pkts / bwd-pkt-len / init-fwd-win - which are top model features).
   FIX: WinDivert SNIFF mode copies matching packets WITHOUT removing them from the stack, so no
   re-injection is needed (traffic flows untouched) and capture is far faster. Queue params are
   also maxed to survive the socket-creation bursts.
2. FRAGMENTATION: 5s pcap segments physically cannot contain a ~105s-duration Slowloris flow, so
   the flow's defining signature (long duration, multi-second IATs) was destroyed - captured flows
   had ~0.26s duration vs training's ~105s. FIX: CAPTURE_WINDOW_SECONDS = 130 (just over
   CICFlowMeter's 120s flow timeout) so slow-attack flows reach their natural timeout and get the
   correct long-duration features. Detection latency is ~130s, which is inherent to a *slow* DoS.

WinDivert gives raw IP packets (layer 3, no Ethernet header). Each is wrapped in a synthetic
Ethernet header (fields CICFlowMeter ignores - it reads only L3/L4) and written to rotating pcaps
in pcap/ using the SAME seg_YYYYMMDD_HHMMSS.pcap naming 2_convert.py / 3_predict.py expect, so
those two scripts need no changes. Real per-packet timestamps are preserved (verified).

Usage:  python 1_capture_windivert.py
MUST run as Administrator (WinDivert loads a driver). Stop with Ctrl+C.
"""
from common import CAPTURE_WINDOW_SECONDS, PCAP_DIR  # keep first (WMI patch)

import sys
sys.stdout.reconfigure(line_buffering=True, write_through=True)
sys.stderr.reconfigure(line_buffering=True, write_through=True)

import os
import time

import pydivert
from scapy.all import Ether, wrpcap

# Capture ALL of THIS host's TCP/UDP traffic (loopback excluded) so the IDS processes every source:
#   1) this PC's own browsing (Chrome etc. over the Wi-Fi adapter),
#   2) a same-PC VM on the host-only subnet 192.168.56.0/24, and
#   3) another PC attacking this machine over the network (-> 10.216.78.44).
# WinDivert only sees traffic to/from THIS host, which is exactly what all 3 cases involve.
# TRADE-OFF (owner asked for all 3): the model's benign/"normal" training was lab-only, so scoring
# ordinary modern internet HTTPS will again produce some FALSE POSITIVES on normal browsing. The real
# cure is retraining on varied current benign traffic. To go back to the no-false-positive lab-only
# setup, restore the host-only filter:
#   FILTER = ("(tcp or udp) and (ip.SrcAddr >= 192.168.56.0 and ip.SrcAddr <= 192.168.56.255) or "
#             "(ip.DstAddr >= 192.168.56.0 and ip.DstAddr <= 192.168.56.255)")
FILTER = "(tcp or udp) and ip.SrcAddr != 127.0.0.1 and ip.DstAddr != 127.0.0.1"

FAKE_SRC_MAC = "02:00:00:00:00:01"
FAKE_DST_MAC = "02:00:00:00:00:02"


def to_scapy_packet(raw: bytes, is_ipv6: bool, ts: float):
    ethertype = 0x86DD if is_ipv6 else 0x0800
    pkt = Ether(src=FAKE_SRC_MAC, dst=FAKE_DST_MAC, type=ethertype) / raw
    pkt.time = ts  # preserve WinDivert's real capture timestamp so IAT/duration are correct
    return pkt


def main():
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"writing a new pcap every {CAPTURE_WINDOW_SECONDS}s into {PCAP_DIR}", flush=True)
    print("NOTE: must run as Administrator (WinDivert loads a driver). SNIFF mode - does not touch traffic.", flush=True)
    print(f"filter: {FILTER}", flush=True)
    print(f"capturing (WinDivert SNIFF). First pcap ready in ~{CAPTURE_WINDOW_SECONDS}s. Ctrl+C to stop.\n", flush=True)

    # SNIFF: capture copies without diverting (no re-injection, no traffic impact, much faster).
    with pydivert.WinDivert(FILTER, flags=pydivert.Flag.SNIFF) as w:
        # Max out the kernel queue so socket-creation bursts aren't dropped while Python drains it.
        try:
            w.set_param(pydivert.Param.QUEUE_LEN, 16384)
            w.set_param(pydivert.Param.QUEUE_TIME, 8000)
        except Exception:
            pass  # param names/limits vary by WinDivert version; defaults still work

        try:
            while True:
                window_pkts = []
                window_end = time.time() + CAPTURE_WINDOW_SECONDS
                try:
                    while True:
                        remaining = window_end - time.time()
                        if remaining <= 0:
                            break
                        try:
                            packet = w.recv(timeout=min(remaining, 2.0))
                        except (OSError, TimeoutError):
                            continue  # no packet in this slice - keep waiting until the window ends
                        if packet is None:
                            continue
                        is_ipv6 = packet.ipv6 is not None
                        window_pkts.append(
                            to_scapy_packet(packet.raw.tobytes(), is_ipv6, time.time()))
                except KeyboardInterrupt:
                    # Ctrl+C mid-window: still flush what we captured so a short attack isn't lost.
                    if window_pkts:
                        stamp = time.strftime("%Y%m%d_%H%M%S")
                        path = os.path.join(PCAP_DIR, f"seg_{stamp}.pcap")
                        wrpcap(path, window_pkts)
                        print(f"\n[{time.strftime('%H:%M:%S')}] flushed partial window on stop -> {path} "
                              f"({len(window_pkts)} packets)", flush=True)
                    print("stopped.")
                    return

                stamp = time.strftime("%Y%m%d_%H%M%S")
                path = os.path.join(PCAP_DIR, f"seg_{stamp}.pcap")
                if window_pkts:
                    wrpcap(path, window_pkts)
                    print(f"[{time.strftime('%H:%M:%S')}] wrote {path} ({len(window_pkts)} packets)", flush=True)
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] no packets this window", flush=True)
        except KeyboardInterrupt:
            print("\nstopped.")


if __name__ == "__main__":
    main()
