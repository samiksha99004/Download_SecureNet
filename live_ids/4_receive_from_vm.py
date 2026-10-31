"""Scenario 1 fix (VM -> same machine): receives rotating pcap segments uploaded from the
attacking VM and drops them straight into pcap/, so 2_convert.py and 3_predict.py work
completely unchanged.

WHY THIS EXISTS (do not remove without re-testing first):
Packets sent from a VM to the host's OWN IP on a VirtualBox Host-only adapter were confirmed,
on this machine, to NEVER reach Npcap - not with elevation, not with the raw \\Device\\NPF_{...}
path, not with the Npcap/NDIS binding confirmed enabled (Get-NetAdapterBinding showed
"Npcap Packet Driver (NPCAP)" Enabled=True on Ethernet 2). Meanwhile ICMP replies were verified
received at the IP layer (ping worked, 27/27, during the exact 30s capture window that still
caught 0 packets). This is a known class of issue: host-destined traffic from a hypervisor's
virtual switch can take an internal fast path that never reaches the NDIS send/receive
indication chain Npcap hooks into, so Wireshark/Npcap on the host-only adapter sees nothing for
VM-to-host traffic specifically, even though the traffic is real and the OS received it fine.
Capturing on a real physical adapter (Wi-Fi) was separately confirmed to work normally (1666+
real flows captured from ordinary browsing), so this is specific to virtual-adapter,
host-destined traffic - not a general Npcap/scapy problem.

Fix: capture on the VM's own interface instead (its outbound view isn't subject to this
shortcut), and ship each finished pcap segment to this receiver over HTTP. Only binds to the
host-only adapter's own IP (not 0.0.0.0), so it is not reachable from Wi-Fi/the internet - only
from VMs on that same host-only network.

Usage:  python 4_receive_from_vm.py
Then on the VM, run vm_capture.sh (same folder) pointed at this machine's host-only IP.
Stop with Ctrl+C.
"""
from common import PCAP_DIR  # keep first (WMI patch)

import sys
sys.stdout.reconfigure(line_buffering=True, write_through=True)
sys.stderr.reconfigure(line_buffering=True, write_through=True)

import http.server
import os
import re
import socket
import time

PORT = 9929
SAFE_NAME = re.compile(r"^seg_[0-9]{8}_[0-9]{6}(_[0-9]+)?\.pcap$")


def host_only_ip():
    """Find this machine's VirtualBox Host-only IP (192.168.56.0/24, the usual default) so the
    receiver binds only there, not on Wi-Fi/every interface."""
    for info in socket.getaddrinfo(socket.gethostname(), None):
        ip = info[4][0]
        if ip.startswith("192.168.56."):
            return ip
    return "0.0.0.0"  # fallback: bind everywhere if the host-only subnet can't be found


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep our own one-line-per-upload logging below instead

    def do_PUT(self):
        name = os.path.basename(self.path.lstrip("/"))
        if not SAFE_NAME.match(name):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"bad filename")
            print(f"[{time.strftime('%H:%M:%S')}] rejected upload with bad filename: {name!r}", flush=True)
            return
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        os.makedirs(PCAP_DIR, exist_ok=True)
        out_path = os.path.join(PCAP_DIR, name)
        with open(out_path, "wb") as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
        print(f"[{time.strftime('%H:%M:%S')}] received {name} ({len(data)} bytes) -> {out_path}", flush=True)


def main():
    ip = host_only_ip()
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"listening on {ip}:{PORT}, saving uploaded pcaps into {PCAP_DIR}", flush=True)
    if ip == "0.0.0.0":
        print("WARNING: could not find a 192.168.56.x address - bound to all interfaces instead.", flush=True)
    print("point vm_capture.sh on the VM at this IP. Ctrl+C to stop.\n", flush=True)
    server = http.server.HTTPServer((ip, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
