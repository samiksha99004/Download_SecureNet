#!/bin/bash
# Scenario 1 (VM -> same machine): run this ON THE ATTACKING VM (e.g. Kali), not on Windows.
# Captures a rotating 5s pcap with tcpdump, then uploads each finished segment to
# 4_receive_from_vm.py running on the Windows host, which drops it straight into live_ids/pcap/
# so the existing 2_convert.py / 3_predict.py need no changes.
#
# Usage:  sudo ./vm_capture.sh 192.168.56.1
#         (first argument = the Windows host's host-only IP; same one you ping/attack)
# Needs: tcpdump, curl (both already on Kali by default). Must run as root (sudo) - tcpdump
# needs raw-socket access the same way Npcap needs admin on Windows.
# Stop with Ctrl+C.
set -u

HOST_IP="${1:?Usage: sudo ./vm_capture.sh <windows-host-only-ip>}"
PORT=9929
WINDOW_SECONDS=5
IFACE="${IFACE:-eth0}"   # override with: IFACE=eth1 sudo -E ./vm_capture.sh 192.168.56.1

echo "capturing on $IFACE, uploading a new segment every ${WINDOW_SECONDS}s to http://$HOST_IP:$PORT"
echo "Ctrl+C to stop."

trap 'echo; echo stopped.; exit 0' INT

while true; do
    stamp=$(date +%Y%m%d_%H%M%S)
    file="/tmp/seg_${stamp}.pcap"
    # -G rotates by time, -W 1 keeps only the current file under that exact name (no counter
    # suffix), so the filename matches SAFE_NAME on the receiver.
    timeout "$WINDOW_SECONDS" tcpdump -i "$IFACE" -w "$file" 2>/dev/null
    if [ -s "$file" ]; then
        curl -s -X PUT --data-binary "@${file}" "http://${HOST_IP}:${PORT}/$(basename "$file")" \
            && echo "[$(date +%H:%M:%S)] uploaded $(basename "$file")" \
            || echo "[$(date +%H:%M:%S)] WARNING: upload failed for $(basename "$file")"
        rm -f "$file"
    fi
done
