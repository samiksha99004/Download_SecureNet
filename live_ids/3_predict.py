"""Step 3 (same machine as steps 1-2) - feed new flows to the trained model every 5 seconds
and print what the network looks like: Benign (normal) or which of the 15 trained attack types.

Model: artifacts/model_trained.pkl - the plain XGBoost this repo trained (54 features, see
README "Step 3 - Transform and Train"). Class names are not saved by training, so they are
rebuilt here from dataset/train_data_SAMPLED_20.csv the same way predict_live.py does it
(sorted-unique label list, same rule sklearn's LabelEncoder used during training), and the
class count is checked against the model before anything is scored.

Strict rules this script follows (same as F:\\all_10_csv_manual\\live_ids_app\\3_predict.py):
  - Only the 54 features the model was trained on are read from CICFlowMeter's CSV (via
    JAVA_COLUMN in common.py), cast to float.
  - A flow is used ONLY if every one of those 54 values is present and a finite number. Any
    flow missing a value, or with text/inf/NaN in a required column, is DROPPED and counted -
    never filled with 0, an average, or any other placeholder.
  - If a window has no usable flows, that is reported as-is ("no data"), never guessed.

Every result is also saved to disk:
  - results/flow_log.csv   one row per scored flow (time, source/destination, predicted
                            class, status = normal if Benign, abnormal otherwise, and
                            remote_host = a reverse-DNS name for the non-local IP, for
                            abnormal flows only)
  - results/window_log.csv one row per 5-second window (counts, the window's verdict)
Both are opened in append mode and flushed after every write.
The reverse-DNS lookup only runs for abnormal flows, is cached per IP, and is skipped (left
blank) if it can't resolve within 0.3s - it never blocks the cycle for long, never invents a
name.

Usage:  python 3_predict.py
Stop with Ctrl+C.
"""
from common import CSV_DIR, JAVA_COLUMN, LABEL_SOURCE, MODEL_PATH, RESULTS_DIR, WINDOW_SECONDS  # keep first

import sys
sys.stdout.reconfigure(line_buffering=True, write_through=True)
sys.stderr.reconfigure(line_buffering=True, write_through=True)

import csv
import glob
import ipaddress
import os
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

import dill
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

_host_cache = {}
_dns_pool = ThreadPoolExecutor(max_workers=8)


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def remote_ip_of(row):
    src, dst = row.get("Src IP", ""), row.get("Dst IP", "")
    if src and not is_private(src):
        return src
    if dst and not is_private(dst):
        return dst
    return None


def resolve_host(ip):
    if ip is None:
        return ""
    if ip in _host_cache:
        return _host_cache[ip]
    future = _dns_pool.submit(socket.gethostbyaddr, ip)
    try:
        name = future.result(timeout=0.3)[0]
    except (socket.herror, socket.gaierror, OSError, FutureTimeoutError):
        name = ""
    _host_cache[ip] = name
    return name


LOCAL_MODEL_PATH = r"F:\local_trained_model\model\local_model.pkl"
LOCAL_CLASSES_PATH = r"F:\local_trained_model\model\classes.json"


def load_model_and_encoder(use_local=False):
    """Load either the CIC-IDS2018 model (default) or the locally-retrained model (--local).
    The local model fixes the train/serve skew documented in F:\\local_trained_model\\CLAUDE.md -
    the CIC model scores live Slowloris 99.8% Benign because its training distribution differs from
    this environment's live CICFlowMeter-4.0 output. Use --local once train_local.py has been run."""
    if use_local:
        import json
        if not os.path.exists(LOCAL_MODEL_PATH):
            raise SystemExit(f"Local model not found at {LOCAL_MODEL_PATH}. "
                             f"Train it first: see F:\\local_trained_model\\CLAUDE.md.")
        with open(LOCAL_MODEL_PATH, "rb") as f:
            model = dill.load(f)
        feats = model.get_booster().feature_names
        classes = np.array(json.load(open(LOCAL_CLASSES_PATH, encoding="utf-8")))
        missing = [f for f in feats if f not in JAVA_COLUMN]
        if missing:
            raise SystemExit(f"common.py JAVA_COLUMN has no mapping for: {missing}")
        print(f"using LOCAL retrained model ({LOCAL_MODEL_PATH})", flush=True)
        return model, feats, classes

    with open(MODEL_PATH, "rb") as f:
        model = dill.load(f)
    feats = model.get_booster().feature_names
    missing = [f for f in feats if f not in JAVA_COLUMN]
    if missing:
        raise SystemExit(f"common.py JAVA_COLUMN has no mapping for: {missing}")

    labels = pd.read_csv(LABEL_SOURCE, usecols=lambda c: c.strip().lower() == "label")
    le = LabelEncoder()
    le.fit(labels.iloc[:, 0])
    if len(le.classes_) != model.n_classes_:
        raise SystemExit(f"Class mismatch: {len(le.classes_)} labels in {LABEL_SOURCE} "
                         f"but model has {model.n_classes_} classes. Not predicting.")
    return model, feats, le.classes_


def read_flows(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def build_matrix(rows, feats):
    """Returns (X float64 [n_usable, 54], kept_rows, n_dropped). A row is kept only if every
    required value is present and finite - no fakes, no blanks."""
    n = len(rows)
    X = np.full((n, len(feats)), np.nan, dtype=np.float64)
    for j, f in enumerate(feats):
        col = JAVA_COLUMN[f]
        for i, r in enumerate(rows):
            v = r.get(col)
            if v is None or v == "":
                continue
            try:
                X[i, j] = float(v)
            except ValueError:
                continue
    ok = np.isfinite(X).all(axis=1)
    kept_rows = [r for r, k in zip(rows, ok) if k]
    return X[ok], kept_rows, int((~ok).sum())


def predict(X, model, feats, classes):
    if len(X) == 0:
        return np.array([], dtype=object)
    frame = pd.DataFrame(X, columns=feats)
    proba = model.predict_proba(frame)
    idx = proba.argmax(axis=1)
    return classes[idx]


def open_logs():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    flow_path = os.path.join(RESULTS_DIR, "flow_log.csv")
    window_path = os.path.join(RESULTS_DIR, "window_log.csv")
    flow_new = not os.path.exists(flow_path)
    window_new = not os.path.exists(window_path)
    flow_f = open(flow_path, "a", newline="", encoding="utf-8")
    window_f = open(window_path, "a", newline="", encoding="utf-8")
    flow_w = csv.writer(flow_f)
    window_w = csv.writer(window_f)
    if flow_new:
        flow_w.writerow(["time", "src_ip", "dst_ip", "dst_port", "predicted_label", "status", "remote_host"])
        flow_f.flush()
    if window_new:
        window_w.writerow(["time", "flows_captured", "flows_scored", "dropped", "verdict", "breakdown"])
        window_f.flush()
    print(f"logging every scored flow to {flow_path}", flush=True)
    print(f"logging every window's summary to {window_path}", flush=True)
    return flow_w, flow_f, window_w, window_f


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true",
                    help="use the locally-retrained model (F:\\local_trained_model) instead of the "
                         "CIC-IDS2018 model - fixes train/serve skew once train_local.py has run")
    args = ap.parse_args()

    model, feats, classes = load_model_and_encoder(use_local=args.local)
    benign_name = "Benign"
    print(f"loaded model: {len(feats)} features, {len(classes)} classes", flush=True)
    print(f"watching {CSV_DIR} every {WINDOW_SECONDS}s. Ctrl+C to stop.\n", flush=True)
    flow_w, flow_f, window_w, window_f = open_logs()

    seen = set()
    cumulative = Counter()
    cum_dropped = 0
    cum_total = 0

    try:
        while True:
            cycle_start = time.time()
            # Only consider CSVs that finished being written >3s ago, so we never read one while
            # the converter is still creating it (that race made us mark a half-written file "seen"
            # with 0 rows and never re-read it -> permanent "(no data)" despite valid flows).
            now = time.time()
            new_files = sorted(p for p in glob.glob(os.path.join(CSV_DIR, "*.csv"))
                               if p not in seen and (now - os.path.getmtime(p)) > 3)
            window_rows = []
            for p in new_files:
                rows = read_flows(p)
                seen.add(p)
                window_rows.extend(rows)

            stamp_full = time.strftime("%Y-%m-%d %H:%M:%S")
            stamp = time.strftime("%H:%M:%S")
            if not window_rows:
                print(f"[{stamp}] no new flows this window - NETWORK STATUS: (no data)", flush=True)
                window_w.writerow([stamp_full, 0, 0, 0, "(no data)", ""]); window_f.flush()
            else:
                X, kept_rows, dropped = build_matrix(window_rows, feats)
                pred_names = predict(X, model, feats, classes)
                cum_dropped += dropped
                cum_total += len(pred_names)
                cumulative.update(pred_names.tolist())

                counts = Counter(pred_names.tolist())
                top_ips = Counter(r.get("Src IP", "?") for r in kept_rows).most_common(1)
                top_ip = top_ips[0][0] if top_ips else "?"

                abnormal_sources = []
                for r, name in zip(kept_rows, pred_names.tolist()):
                    status = "normal" if name == benign_name else "abnormal"
                    host = ""
                    if status == "abnormal":
                        ip = remote_ip_of(r)
                        host = resolve_host(ip)
                        abnormal_sources.append((name, ip or "?", host))
                    flow_w.writerow([stamp_full, r.get("Src IP", ""), r.get("Dst IP", ""),
                                     r.get("Dst Port", ""), name, status, host])
                flow_f.flush()

                print(f"[{stamp}] window: {len(window_rows)} flows captured, {len(pred_names)} scored, "
                      f"{dropped} dropped (missing/non-numeric value)", flush=True)
                if counts:
                    verdict = counts.most_common(1)[0][0]
                    breakdown = "; ".join(f"{n}={c}" for n, c in counts.most_common())
                    benign_count = counts.get(benign_name, 0)
                    attack_count = len(pred_names) - benign_count
                    benign_pct = benign_count / len(pred_names) * 100
                    attack_pct = attack_count / len(pred_names) * 100
                    print(f"  NETWORK STATUS: Benign {benign_pct:5.1f}%   Attack {attack_pct:5.1f}%"
                          f"   (majority: {verdict})", flush=True)
                    for name, c in counts.most_common():
                        print(f"    {name:<28}{c:>5}  {c/len(pred_names)*100:6.1f}%", flush=True)
                    print(f"  most active source IP this window: {top_ip}", flush=True)
                    if abnormal_sources:
                        print(f"  abnormal flow sources this window:", flush=True)
                        for name, ip, host in abnormal_sources:
                            where = f"{ip} ({host})" if host else ip
                            print(f"    {name:<28}{where}", flush=True)
                else:
                    verdict = f"(no usable flows - all {dropped} incomplete)"
                    breakdown = ""
                    print(f"  NETWORK STATUS: {verdict}", flush=True)
                window_w.writerow([stamp_full, len(window_rows), len(pred_names), dropped, verdict, breakdown])
                window_f.flush()

            print(f"  cumulative: {cum_total} flows scored, {cum_dropped} dropped, since start", flush=True)
            print("-" * 70, flush=True)

            elapsed = time.time() - cycle_start
            time.sleep(max(0.0, WINDOW_SECONDS - elapsed))
    except KeyboardInterrupt:
        print("\nstopped.")
        print("final cumulative counts:")
        for name, c in cumulative.most_common():
            print(f"  {name:<28}{c:>6}")
    finally:
        flow_f.close()
        window_f.close()


if __name__ == "__main__":
    main()
