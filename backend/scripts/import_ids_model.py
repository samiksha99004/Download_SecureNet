"""
Bring the trained XGBoost model of the Intrusion_Detection-System project into SecureNet.

    backend\\venv\\Scripts\\python.exe scripts\\import_ids_model.py [path\\to\\Intrusion_Detection-System]

Writes into backend/models/ (not in git):
  model_trained.pkl    the trained model, copied unchanged (artifacts/model_trained.pkl)
  model_trained.json   what SecureNet needs alongside it:
      classes        the 15 class names in the order the model outputs them. The training code
                     never saved its LabelEncoder, so — exactly like that project's predict_live.py —
                     they are rebuilt as the sorted unique labels of dataset/train_data_SAMPLED_20.csv
                     (the file the model was trained from); the count is checked against the model.
      features       the model's 55 input columns, in order (from the model itself)
      display_names  plain names for people ("DoS attacks-Hulk" -> "DoS (Hulk)")
      test_metrics   real results of THIS model on artifacts/test_processed.csv (the project's held-out
                     test split): accuracy and per-class precision / recall / F1 / rows
"""

from __future__ import annotations

import csv
import json
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
import app  # noqa: E402,F401  (Windows WMI guard before numpy / xgboost load)

import dill  # noqa: E402
import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402

MODELS = BACKEND / "models"

DISPLAY_NAMES = {
    "Benign": "Benign",
    "Bot": "Bot",
    "Brute Force -Web": "Web Brute Force",
    "Brute Force -XSS": "XSS (cross-site scripting)",
    "DDOS attack-HOIC": "DDoS (HOIC)",
    "DDOS attack-LOIC-UDP": "DDoS (LOIC UDP)",
    "DDoS attacks-LOIC-HTTP": "DDoS (LOIC HTTP)",
    "DoS attacks-GoldenEye": "DoS (GoldenEye)",
    "DoS attacks-Hulk": "DoS (Hulk)",
    "DoS attacks-SlowHTTPTest": "DoS (SlowHTTPTest)",
    "DoS attacks-Slowloris": "DoS (Slowloris)",
    "FTP-BruteForce": "FTP Brute Force",
    "Infilteration": "Infiltration",
    "SQL Injection": "SQL Injection",
    "SSH-Bruteforce": "SSH Brute Force",
}


def class_names(train_csv: Path) -> list[str]:
    """Sorted unique values of the label column (what sklearn's LabelEncoder.fit does)."""
    labels: Counter = Counter()
    with train_csv.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        header = [c.strip().lower() for c in fh.readline().rstrip("\r\n").split(",")]
        if header[-1] != "label":
            sys.exit(f"Expected the label as the last column of {train_csv}")
        for line in fh:
            labels[line.rstrip("\r\n").rsplit(",", 1)[-1]] += 1
    return sorted(labels)


def evaluate(model, features: list[str], test_csv: Path, n_classes: int) -> dict:
    booster = model.get_booster()
    confusion = np.zeros((n_classes, n_classes), dtype=np.int64)
    with test_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        index = [header.index(f) for f in features]
        label_at = header.index("label")
        rows, labels = [], []

        def flush():
            if not rows:
                return
            proba = booster.predict(xgb.DMatrix(np.asarray(rows, dtype=np.float64), feature_names=features))
            pred = proba.argmax(axis=1)
            np.add.at(confusion, (np.asarray(labels, dtype=np.int64), pred), 1)
            rows.clear()
            labels.clear()

        for r in reader:
            rows.append([float(r[i]) for i in index])
            labels.append(int(float(r[label_at])))
            if len(rows) >= 50_000:
                flush()
        flush()
    return confusion


def main() -> None:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else r"F:\Intrusion_Detection-System")
    model_src = src / "artifacts" / "model_trained.pkl"
    train_csv = src / "dataset" / "train_data_SAMPLED_20.csv"
    test_csv = src / "artifacts" / "test_processed.csv"
    for p in (model_src, train_csv, test_csv):
        if not p.is_file():
            sys.exit(f"Not found: {p}")

    with model_src.open("rb") as fh:
        model = dill.load(fh)
    features = list(model.get_booster().feature_names or [])
    if not features:
        features = [c for c in test_csv.open().readline().strip().split(",") if c != "label"]
    print(f"model: {type(model).__name__}, {model.n_classes_} classes, {len(features)} features")

    print("reading class names from the training data (one pass over the file)...")
    classes = class_names(train_csv)
    if len(classes) != model.n_classes_:
        sys.exit(f"{len(classes)} labels in {train_csv} but the model has {model.n_classes_} classes — not importing.")

    print("testing the model on the held-out test split...")
    confusion = evaluate(model, features, test_csv, len(classes))
    total = int(confusion.sum())
    per_class = {}
    for i, name in enumerate(classes):
        tp = int(confusion[i, i])
        support = int(confusion[i].sum())
        predicted = int(confusion[:, i].sum())
        precision = tp / predicted if predicted else None
        recall = tp / support if support else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (0.0 if support else None)
        per_class[name] = {"test_rows": support, "precision": precision, "recall": recall, "f1": f1}
    accuracy = float(np.trace(confusion) / total) if total else None

    MODELS.mkdir(exist_ok=True)
    shutil.copy2(model_src, MODELS / "model_trained.pkl")
    config = {
        "kind": "xgboost_cic",
        "source": str(model_src),
        "trained_with": "Intrusion_Detection-System (CIC-IDS2018, XGBoost multi:softprob)",
        "classes": classes,
        "benign_class": "Benign",
        "display_names": {c: DISPLAY_NAMES.get(c, c) for c in classes},
        "features": features,
        "label_source": str(train_csv),
        "test_metrics": {
            "source": str(test_csv),
            "test_rows": total,
            "overall_accuracy": accuracy,
            "per_class": per_class,
        },
        "imported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (MODELS / "model_trained.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(f"accuracy {accuracy:.4f} on {total:,} test flows")
    for name, m in per_class.items():
        print(f"  {name:28} rows {m['test_rows']:>8,}  recall {m['recall'] if m['recall'] is not None else '-'}")


if __name__ == "__main__":
    main()
