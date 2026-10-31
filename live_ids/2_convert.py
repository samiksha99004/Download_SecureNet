"""Step 2 - converts each finished pcap with the real Java CICFlowMeter-v3 (not a guess at its
conventions). Skips the newest pcap (step 1 may still be writing it). Prunes old pcaps/csvs so
disk usage stays bounded on a long-running capture.

Usage:  python 2_convert.py
Needs CONV_DIR (common.py) to point at a built CICFlowMeter-4.0 distribution - already set to
this machine's F:\\CICFlowMeter-master\\build\\distributions\\CICFlowMeter-4.0.
Stop with Ctrl+C.
"""
from common import CONV_DIR, CSV_DIR, JAVA_EXE, KEEP_FILES, MAX_FILES, PCAP_DIR  # keep first (WMI patch)

import sys
sys.stdout.reconfigure(line_buffering=True, write_through=True)
sys.stderr.reconfigure(line_buffering=True, write_through=True)

import glob
import os
import subprocess
import time


def convert(pcap_path):
    out_csv = os.path.join(CSV_DIR, os.path.basename(pcap_path) + "_Flow.csv")
    if os.path.exists(out_csv):
        return out_csv
    subprocess.run(
        [JAVA_EXE, "-Djava.library.path=lib/native", "-cp", "lib/*", "cic.cs.unb.ca.ifm.Cmd", pcap_path, CSV_DIR],
        cwd=CONV_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        # no console window, so Java doesn't flash a terminal when run from the windowless app
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return out_csv if os.path.exists(out_csv) else None


def prune(folder, pattern):
    files = sorted(glob.glob(os.path.join(folder, pattern)), key=os.path.getmtime)
    if len(files) > MAX_FILES:
        for f in files[:len(files) - KEEP_FILES]:
            os.remove(f)


def main():
    os.makedirs(CSV_DIR, exist_ok=True)
    if not os.path.isdir(CONV_DIR):
        raise SystemExit(f"CICFlowMeter not found at {CONV_DIR} - check common.py CONV_DIR.")
    print(f"converting new pcaps from {PCAP_DIR} into {CSV_DIR} (Ctrl+C to stop)", flush=True)

    done = set()
    try:
        while True:
            pcaps = sorted(glob.glob(os.path.join(PCAP_DIR, "seg_*.pcap")), key=os.path.getmtime)
            now = time.time()
            for p in pcaps:
                # Process a pcap as soon as it is fully written (mtime >2s old) instead of waiting
                # for a whole extra window by skipping the newest file. 1_capture writes each pcap
                # atomically with wrpcap() at window close, so a >2s-old file is complete. This
                # removes ~one capture-window of detection latency.
                if p in done or (now - os.path.getmtime(p)) < 2:
                    continue
                out = convert(p)
                done.add(p)
                stamp = time.strftime("%H:%M:%S")
                if out:
                    print(f"[{stamp}] converted {os.path.basename(p)} -> {os.path.basename(out)}", flush=True)
                else:
                    print(f"[{stamp}] WARNING: conversion failed for {os.path.basename(p)}", flush=True)
            prune(PCAP_DIR, "seg_*.pcap")
            prune(CSV_DIR, "*.csv")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
