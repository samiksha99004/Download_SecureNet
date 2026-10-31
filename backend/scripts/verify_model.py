"""Check that SecureNet's live detector gives exactly the model's tested results.

Takes rows from the model's held-out test split (default F:\\retraining_hybrid\\data), feeds each
row to the app's own Detector.analyze() - one flow at a time, exactly like live traffic - and
compares the verdict with the reference pipeline that produced the published test results
(4_evaluate.py). Prints agreement and the accuracy on those rows.

    venv\\Scripts\\python.exe scripts\\verify_model.py [--rows 20000] [--data F:\\retraining_hybrid\\data]

Read-only: touches no database.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("ALLOW_LOCAL_DATABASE", "true")            # never connects; settings just need values
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///unused.db")
os.environ.setdefault("JWT_SECRET", "verify-script-not-used-for-anything-0123456789")

import numpy as np  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.ml.detector import Detector  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=20000)
    ap.add_argument("--data", default=r"F:\retraining_hybrid\data")
    args = ap.parse_args()

    det = Detector()
    if not det.load(settings.models_dir) or det.kind != "hybrid":
        sys.exit(f"Hybrid model not loaded from {settings.models_dir}: {det.errors}")
    meta = json.loads((Path(args.data) / "meta.json").read_text(encoding="utf-8"))
    X = np.load(Path(args.data) / "X_test.npy", mmap_mode="r")
    y = np.load(Path(args.data) / "y_test.npy")
    rng = np.random.default_rng(7)
    idx = np.sort(rng.choice(len(y), size=min(args.rows, len(y)), replace=False))
    cols = [meta["features"].index(name) for name in det.feature_columns]
    Xs = np.asarray(X[idx][:, cols], dtype=np.float64)
    ys = y[idx]

    # reference: the tested pipeline, vectorised (4_evaluate.py)
    import xgboost as xgb
    ref_score = -det.isolation_forest.score_samples(det.scaler.transform(np.log1p(np.clip(Xs, 0, None) + 1.0)))
    flagged = ref_score >= det.calibrated_threshold
    ref = np.full(len(ys), det.benign_index, dtype=np.int64)
    if flagged.any():
        ref[flagged] = det.booster.predict(xgb.DMatrix(Xs[flagged])).argmax(1)

    # SecureNet: one flow at a time through Detector.analyze (what the live IDS calls)
    t0 = time.time()
    app = np.empty(len(ys), dtype=np.int64)
    max_diff = 0.0
    for i, row in enumerate(Xs):
        d = det.analyze(dict(zip(det.feature_columns, row)), det.calibrated_threshold, True, 0.0)
        max_diff = max(max_diff, abs(d.anomaly_score - ref_score[i]))
        app[i] = det.classes.index(d.attack_type) if d.is_alert and d.attack_type else det.benign_index
    secs = time.time() - t0

    print(f"rows checked:           {len(ys):,} (random sample of the {len(y):,}-row test split)")
    print(f"same verdict as tested: {(app == ref).mean() * 100:.3f}%   (largest score difference {max_diff:.2e})")
    print(f"accuracy on these rows: SecureNet {(app == ys).mean() * 100:.2f}%   reference {(ref == ys).mean() * 100:.2f}%"
          f"   published (all rows) {json.loads((settings.models_dir / 'hybrid_metrics.json').read_text())['overall_accuracy'] * 100:.2f}%")
    print(f"speed:                  {secs / len(ys) * 1000:.2f} ms per flow")
    for c, name in enumerate(det.classes):
        m = ys == c
        if m.any():
            print(f"  {name:<15} {m.sum():>6,} rows   recall {(app[m] == c).mean() * 100:5.1f}%")


if __name__ == "__main__":
    main()
