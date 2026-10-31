"""The retrained hybrid model (Isolation Forest + XGBoost) inside SecureNet.

Skipped automatically where the model files (backend/models, not in git) or the ML libraries
are missing. Where they exist, checks that the app gives exactly the tested verdicts.
"""

import json
from pathlib import Path

import pytest

from app.core.config import BACKEND_DIR
from app.ml.detector import Detector
from tests.test_ids import make_flow

MODELS = BACKEND_DIR / "models"
TEST_DATA = Path(r"F:\retraining_hybrid\data")

pytest.importorskip("sklearn")
pytest.importorskip("xgboost")
if not (MODELS / "model_config.json").is_file():
    pytest.skip("hybrid model files are not in backend/models", allow_module_level=True)


@pytest.fixture(scope="module")
def detector():
    d = Detector()
    assert d.load(MODELS), d.errors
    return d


def test_loads_as_the_tested_hybrid(detector):
    cfg = json.loads((MODELS / "model_config.json").read_text(encoding="utf-8"))
    assert detector.kind == "hybrid" and detector.name == "isolation_forest+xgboost"
    assert detector.feature_columns == cfg["features_used"] and len(detector.feature_columns) == 63
    assert detector.classes[detector.benign_index] == "Benign"
    assert detector.calibrated_threshold == pytest.approx(cfg["threshold"])
    assert detector.test_metrics["overall_accuracy"] > 0.9
    assert abs(sum(detector.importances) - 1.0) < 1e-6
    assert not detector.errors


def test_live_flow_has_every_feature_the_model_needs(detector):
    features = make_flow().features
    missing = [name for name in detector.feature_columns if name not in features]
    assert missing == []                                   # Protocol and Fwd URG Flags included
    d = detector.analyze(features, detector.calibrated_threshold)
    assert 0.0 < d.anomaly_score < 1.0                    # a real Isolation Forest score


def test_batch_and_single_give_the_same_verdicts(detector):
    flows = [make_flow().features for _ in range(3)]
    flows[1] = {**flows[1], "Dst Port": 4444.0, "Flow Duration": 1.0, "SYN Flag Cnt": 50.0}
    batch = detector.analyze_batch(flows, detector.calibrated_threshold)
    single = [detector.analyze(f, detector.calibrated_threshold) for f in flows]
    assert [(b.is_alert, b.attack_type, b.anomaly_score) for b in batch] == \
           [(s.is_alert, s.attack_type, s.anomaly_score) for s in single]


@pytest.mark.skipif(not (TEST_DATA / "X_test.npy").is_file(), reason="model test split not on this PC")
def test_reproduces_the_published_test_results(detector):
    """1,000 rows of the held-out test split: the app's verdicts equal the tested pipeline's."""
    import numpy as np
    import xgboost as xgb

    meta = json.loads((TEST_DATA / "meta.json").read_text(encoding="utf-8"))
    X = np.load(TEST_DATA / "X_test.npy", mmap_mode="r")
    idx = np.linspace(0, len(X) - 1, 1000).astype(int)
    cols = [meta["features"].index(n) for n in detector.feature_columns]
    Xs = np.asarray(X[idx][:, cols], dtype=np.float64)
    ref_score = -detector.isolation_forest.score_samples(detector.scaler.transform(np.log1p(np.clip(Xs, 0, None) + 1)))
    flagged = ref_score >= detector.calibrated_threshold
    ref = np.full(len(Xs), detector.benign_index)
    ref[flagged] = detector.booster.predict(xgb.DMatrix(Xs[flagged])).argmax(1)

    got = detector.analyze_batch([dict(zip(detector.feature_columns, r)) for r in Xs], detector.calibrated_threshold)
    app = [detector.classes.index(d.attack_type) if d.is_alert and d.attack_type else detector.benign_index for d in got]
    assert list(app) == list(ref)
    assert np.allclose([d.anomaly_score for d in got], ref_score)


async def test_model_page_shows_the_real_test_results(client, admin, monkeypatch, detector):
    from app.ml import ids_service as ids_module

    _, headers = admin
    ids = ids_module.get_ids_service()
    monkeypatch.setattr(ids, "detector", detector)
    monkeypatch.setattr("app.api.routes.model.get_detector", lambda: detector)
    await ids.reload_config()
    info = (await client.get("/api/model/info", headers=headers)).json()
    stage1, stage2 = info["isolationForest"], info["xgboost"]
    assert stage1["status"] == "loaded" and stage1["nEstimators"] == 300 and stage1["featureCount"] == 63
    assert stage1["testedThreshold"] == pytest.approx(detector.calibrated_threshold)
    assert stage1["threshold"] == pytest.approx(detector.calibrated_threshold)   # Medium = the tested threshold
    assert stage2["status"] == "loaded" and stage2["nEstimators"] == 200
    assert stage2["maxDepth"] is None and stage2["learningRate"] is None   # not stored in the model file: never guessed
    assert stage2["metrics"]["accuracy"] == pytest.approx(detector.test_metrics["overall_accuracy"])
    assert stage2["metrics"]["testRows"] == 465837
    assert {m["className"] for m in stage2["metrics"]["perClassMetrics"]} == set(detector.classes)
    assert "SQL Injection" in stage2["supportedAttackClasses"] and "Benign" not in stage2["supportedAttackClasses"]
    top = (await client.get("/api/model/feature-importance?stage=2&limit=5", headers=headers)).json()
    assert len(top) == 5 and top[0]["rank"] == 1


async def test_severity_follows_how_sure_stage_2_is(detector):
    from app.ml.detector import Detection
    from app.ml.ids_service import IDSService
    from app.models.security_event import SeverityLevel

    ids = IDSService()
    ids.detector = detector
    th = detector.calibrated_threshold
    assert ids._severity_for(Detection(0.48, True, "DDoS", 1.0), th) == SeverityLevel.HIGH
    assert ids._severity_for(Detection(0.48, True, "Bot", 0.7), th) == SeverityLevel.MEDIUM
    assert ids._severity_for(Detection(0.48, True, "Infilteration", 0.45), th) == SeverityLevel.LOW
    assert ids._severity_for(Detection(0.48, True, None, None), th) == SeverityLevel.LOW   # unnamed anomaly
