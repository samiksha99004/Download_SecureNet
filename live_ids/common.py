"""Shared settings for live_ids. Import this first (WMI patch for Windows; harmless elsewhere).

Same method as F:\\all_10_csv_manual\\live_ids_app: rotate short pcaps, convert each one with
the real Java CICFlowMeter-v3 (not a hand-written feature guess), then score the finished CSVs
with the model this repo actually trained (artifacts/model_trained.pkl, 54 features, plain
XGBoost) - not the other project's Isolation-Forest+XGBoost hybrid.
"""
import platform
platform._wmi_query = lambda *a, **k: (_ for _ in ()).throw(OSError())

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)

MODEL_PATH = os.path.join(PROJECT_ROOT, "artifacts", "model_trained.pkl")
LABEL_SOURCE = os.path.join(PROJECT_ROOT, "dataset", "train_data_SAMPLED_20.csv")

PCAP_DIR = os.path.join(HERE, "pcap")
CSV_DIR = os.path.join(HERE, "csv")
RESULTS_DIR = os.path.join(HERE, "results")

if sys.platform.startswith("win"):
    # Already-built Windows CICFlowMeter-4.0 distribution on this machine.
    CONV_DIR = r"F:\CICFlowMeter-master\build\distributions\CICFlowMeter-4.0"
    # System `java` (Program Files\Java, javapath shim) was found uninstalled/broken on this
    # machine (2026-10-18 - worked fine on 2026-10-12, something removed it since). Point
    # straight at the portable JDK 8 already on F: instead of relying on PATH.
    JAVA_EXE = r"F:\jdk8\jdk8u504-b01\bin\java.exe"
else:
    CONV_DIR = os.path.expanduser("~/live_ids_app/CICFlowMeter-4.0")
    JAVA_EXE = "java"

WINDOW_SECONDS = 5   # 3_predict poll interval (how often it checks for new CSVs / prints)

# How long each captured pcap segment covers. This is the main detection-latency knob: first verdict
# lands ~1 window after an attack starts (2_convert now processes a pcap as soon as it is written,
# not a window later). 30s -> ~35-45s latency.
# TRADE-OFF: the two SLOW attacks (DoS-Slowloris, DoS-SlowHTTPTest) are defined by a ~105s flow
# duration with multi-second idle gaps; that signature cannot form inside a window shorter than
# ~120s, so at 30s they get fragmented and will be MISSED/misclassified. Every other class (Hulk,
# GoldenEye, LOIC-UDP, SSH/FTP/Web brute, SQLi, XSS, Infiltration, Bot) makes short flows and is
# caught fine at 30s. Set this back to 130 if you need the slow-DoS classes and can accept ~5min
# latency. (History: was 130s for full slow-attack coverage; lowered to 30s for <60s live latency.)
CAPTURE_WINDOW_SECONDS = 30

KEEP_FILES = 40      # pcap/csv retention: keep the newest this many
MAX_FILES = 60       # ... delete the oldest once more than this many exist

# Training feature name (artifacts/test_processed.csv / model.get_booster().feature_names)
# -> Java CICFlowMeter-v3 CSV header name. Verified by exact text match against a real
# CICFlowMeter-v3 output file (F:\all_10_csv_manual\live_ids_app\csv\*.csv), the same way the
# other project's JAVA_COLUMN mapping was verified.
JAVA_COLUMN = {
    "subflow bwd byts": "Subflow Bwd Bytes",
    "totlen bwd pkts": "Total Length of Bwd Packet",
    "bwd header len": "Bwd Header Length",
    "fwd act data pkts": "Fwd Act Data Pkts",
    "tot fwd pkts": "Total Fwd Packet",
    "subflow fwd pkts": "Subflow Fwd Packets",
    "idle max": "Idle Max",
    "idle mean": "Idle Mean",
    "pkt len std": "Packet Length Std",
    "flow iat min": "Flow IAT Min",
    "flow iat mean": "Flow IAT Mean",
    "fwd header len": "Fwd Header Length",
    "bwd pkt len std": "Bwd Packet Length Std",
    "tot bwd pkts": "Total Bwd packets",
    "subflow bwd pkts": "Subflow Bwd Packets",
    "bwd pkt len max": "Bwd Packet Length Max",
    "pkt len max": "Packet Length Max",
    "pkt size avg": "Average Packet Size",
    "pkt len mean": "Packet Length Mean",
    "fwd iat max": "Fwd IAT Max",
    "fwd seg size min": "Fwd Seg Size Min",
    "fwd pkt len std": "Fwd Packet Length Std",
    "idle min": "Idle Min",
    "pkt len var": "Packet Length Variance",
    "fwd iat tot": "Fwd IAT Total",
    "ack flag cnt": "ACK Flag Count",
    "flow duration": "Flow Duration",
    "flow iat max": "Flow IAT Max",
    "psh flag cnt": "PSH Flag Count",
    "fwd iat min": "Fwd IAT Min",
    "bwd pkt len mean": "Bwd Packet Length Mean",
    "bwd seg size avg": "Bwd Segment Size Avg",
    "flow iat std": "Flow IAT Std",
    "fwd iat std": "Fwd IAT Std",
    "fwd iat mean": "Fwd IAT Mean",
    "bwd iat tot": "Bwd IAT Total",
    "fwd pkt len max": "Fwd Packet Length Max",
    "bwd pkt len min": "Bwd Packet Length Min",
    "bwd iat max": "Bwd IAT Max",
    "active min": "Active Min",
    "bwd iat mean": "Bwd IAT Mean",
    "ece flag cnt": "ECE Flag Count",
    "fwd seg size avg": "Fwd Segment Size Avg",
    "fwd pkt len mean": "Fwd Packet Length Mean",
    "subflow fwd byts": "Subflow Fwd Bytes",
    "totlen fwd pkts": "Total Length of Fwd Packet",
    "rst flag cnt": "RST Flag Count",
    "active mean": "Active Mean",
    "bwd iat std": "Bwd IAT Std",
    "pkt len min": "Packet Length Min",
    "bwd iat min": "Bwd IAT Min",
    "idle std": "Idle Std",
    "active std": "Active Std",
    "active max": "Active Max",
    "init fwd win byts": "FWD Init Win Bytes",
}
