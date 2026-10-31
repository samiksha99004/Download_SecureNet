"""Live network status - prints a one-line class breakdown every 10 seconds using the locally
retrained model. Reads the CSVs that 2_convert.py produces (so run 1_capture_windivert.py and
2_convert.py alongside this).

Output example:
    [22:30:15] Benign 100.0%
    [22:30:25] Benign 45.0%  |  DoS attacks-Hulk 45.0%  |  DDOS attack-LOIC-UDP 10.0%

Note: the capture window is CAPTURE_WINDOW_SECONDS (130s by default), so genuinely new flow data
only arrives every ~130s; this just refreshes/holds the latest verdict every 10s so you get a
steady live readout. Lower CAPTURE_WINDOW_SECONDS in common.py for faster-updating data (but slow
attacks like Slowloris need the long window).

Usage:  python live_status.py
Stop with Ctrl+C.
"""
from common import CSV_DIR, JAVA_COLUMN, MODEL_PATH, LABEL_SOURCE  # keep first (WMI patch)

import sys
sys.stdout.reconfigure(line_buffering=True, write_through=True)

import csv
import glob
import json
import os
import time
from collections import Counter

import dill
import numpy as np
import pandas as pd

PRINT_EVERY = 10  # seconds
LOCAL_MODEL = r"F:\local_trained_model\model\local_model.pkl"
LOCAL_CLASSES = r"F:\local_trained_model\model\classes.json"


def load_model():
    if not os.path.exists(LOCAL_MODEL):
        sys.exit(f"local model not found at {LOCAL_MODEL} - train it first.")
    model = dill.load(open(LOCAL_MODEL, "rb"))
    feats = model.get_booster().feature_names
    classes = np.array(json.load(open(LOCAL_CLASSES, encoding="utf-8")))
    return model, feats, classes


def read_flows(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def score(rows, model, feats, classes):
    n = len(rows)
    X = np.full((n, len(feats)), np.nan)
    for j, fcol in enumerate(feats):
        col = JAVA_COLUMN[fcol]
        for i, r in enumerate(rows):
            v = r.get(col)
            if v not in (None, ""):
                try:
                    X[i, j] = float(v)
                except ValueError:
                    pass
    ok = np.isfinite(X).all(axis=1)
    if ok.sum() == 0:
        return []
    proba = model.predict_proba(pd.DataFrame(X[ok], columns=feats))
    return classes[proba.argmax(axis=1)].tolist()


def status_line(labels):
    total = len(labels)
    if total == 0:
        return "(no data)"
    counts = Counter(labels)
    parts = [f"{name} {c / total * 100:.1f}%" for name, c in counts.most_common()
             if round(c / total * 100, 1) >= 0.1]
    return "  |  ".join(parts)


def main():
    model, feats, classes = load_model()
    print(f"loaded local model ({len(classes)} classes). status every {PRINT_EVERY}s. Ctrl+C to stop.\n")
    seen = set()
    latest = []  # labels from the most recent window that had data
    try:
        while True:
            new_files = sorted(p for p in glob.glob(os.path.join(CSV_DIR, "*.csv"))
                               if p not in seen and (time.time() - os.path.getmtime(p)) > 3)
            fresh = []
            for p in new_files:
                seen.add(p)
                fresh.extend(read_flows(p))
            if fresh:
                preds = score(fresh, model, feats, classes)
                if preds:
                    latest = preds
            print(f"[{time.strftime('%H:%M:%S')}] {status_line(latest)}")
            time.sleep(PRINT_EVERY)
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
