"""SecureNet <- our locally-trained model (plain XGBoost, 55 CICFlowMeter-4.0 features).

This replaces the old removed hybrid model. Our model was trained on LIVE, locally-captured
traffic put through the real Java CICFlowMeter-4.0, so it must be fed flows extracted by that
SAME tool (the live_ids pipeline) - NOT SecureNet's scapy extractor - or it re-introduces the
train/serve skew that made live attacks read as Benign. The `csv_capture.CsvFlowSource` feeds it
exactly those CICFlowMeter-4.0 CSV rows.

`JAVA_COLUMN` maps each model feature name -> the real CICFlowMeter-4.0 output header (copied
verbatim from the project's live_ids/common.py, kept here so the backend is self-contained).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

BENIGN = "Benign"

# model-feature name -> CICFlowMeter-4.0 CSV header (55 features)
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

LOCAL_MODEL_FILE = "local_model.pkl"
LOCAL_CLASSES_FILE = "classes.json"


class LocalModel:
    """Our plain-XGBoost multiclass model. Scores dicts keyed by CICFlowMeter-4.0 headers."""

    def __init__(self, model, feats: List[str], classes: np.ndarray):
        self.model = model
        self.feats = feats
        self.classes = classes

    @classmethod
    def present(cls, models_dir: Path) -> bool:
        return (Path(models_dir) / LOCAL_MODEL_FILE).exists()

    @classmethod
    def load(cls, models_dir: Path) -> Optional["LocalModel"]:
        mp = Path(models_dir) / LOCAL_MODEL_FILE
        if not mp.exists():
            return None
        import dill  # local import: only needed when this model is used
        with open(mp, "rb") as fh:
            model = dill.load(fh)
        feats = list(model.get_booster().feature_names)
        cp = Path(models_dir) / LOCAL_CLASSES_FILE
        if cp.exists():
            classes = np.array(json.load(open(cp, encoding="utf-8")))
        else:
            classes = np.array([str(c) for c in model.classes_])
        return cls(model, feats, classes)

    @property
    def n_classes(self) -> int:
        return len(self.classes)

    def benign_index(self) -> int:
        idx = np.where(self.classes == BENIGN)[0]
        return int(idx[0]) if len(idx) else -1

    def score_batch(self, feature_dicts: List[dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Returns (proba [n, n_classes], ok_mask [n]).

        A row is `ok=False` when any of the 55 required features is missing/non-finite - we never
        fill a placeholder (same strict rule as the CLI pipeline); its proba row is all zeros and
        the caller treats it as 'not scored' (benign/no-alert)."""
        n = len(feature_dicts)
        X = np.full((n, len(self.feats)), np.nan)
        for j, fcol in enumerate(self.feats):
            col = JAVA_COLUMN.get(fcol, fcol)
            for i, r in enumerate(feature_dicts):
                v = r.get(col)
                if v not in (None, ""):
                    try:
                        X[i, j] = float(v)
                    except (TypeError, ValueError):
                        pass
        ok = np.isfinite(X).all(axis=1)
        proba = np.zeros((n, self.n_classes))
        if ok.any():
            p = self.model.predict_proba(pd.DataFrame(X[ok], columns=self.feats))
            proba[ok] = p
        return proba, ok
