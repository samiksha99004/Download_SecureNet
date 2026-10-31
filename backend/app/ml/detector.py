"""
SecureNet — Two-stage detector (paper, Algorithm 1)

    scaled   ← Scaler.transform(features)
    score    ← IsolationForest.score(scaled)
    if score > θ:
        category    ← XGBoost.predict(...)
        topFeatures ← ExplainTop(scaled, category)

Two model formats are understood (looked up in ML_MODELS_DIR):

* **Hybrid** (the retrained model, `F:\\retraining_hybrid`) — `model_config.json`
  + `isolation_forest.joblib` + `scaler.joblib` + `xgboost_stage2.json`
  (+ `hybrid_metrics.json` with the test results). Exactly the pipeline that was
  tested (92.2 % accuracy on 465,837 unseen CICIDS2018 flows):
    x      = the 63 features in `features_used` order
    stage 1: score = -IF.score_samples(scaler(log1p(max(x, 0) + 1)));  flagged if score ≥ θ
             (θ = the model's tested threshold unless the admin chose a custom one)
    stage 2: XGBoost on the raw x → 7 classes; "Benign" cancels the stage-1 flag,
             any other class is the attack.
* **Legacy** (`isolation_forest.pkl`, `xgboost*.pkl`, `scaler.pkl`, `feature_columns.pkl`,
  `label_encoder.pkl`) — each part optional, as before.

Nothing is loaded at import time; call `load()` (done at startup when
ML_AUTOLOAD=true, or via POST /api/model/reload).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from app.ml.features import FEATURE_COLUMNS
from app.utils.logger import logger

# Legacy artifact names (first match wins).
IF_FILES = ("isolation_forest_model.pkl", "isolation_forest.pkl", "isolation_forest.joblib")
XGB_FILES = ("xgboost_multiclass_model.pkl", "xgboost_model.pkl", "xgboost.pkl", "xgboost_classifier.joblib")
SCALER_FILES = ("scaler.pkl", "feature_scaler.joblib")
ENCODER_FILES = ("label_encoder.pkl",)
COLUMNS_FILES = ("feature_columns.pkl",)

# Hybrid (retrained) model files.
HYBRID_CONFIG = "model_config.json"
HYBRID_IF = "isolation_forest.joblib"
HYBRID_SCALER = "scaler.joblib"
HYBRID_XGB = "xgboost_stage2.json"
HYBRID_METRICS = "hybrid_metrics.json"

BENIGN_LABELS = {"benign", "normal", "0"}
MIN_GUESS = 0.005        # guesses below 0.5 % are not worth showing
# The local model must be at least this sure of a specific attack class before it raises an alert.
# This is a FLOOR applied on top of the admin's confidence setting (it only ever raises the bar,
# never lowers it), so even if the stored setting drifts low the model can't fire on a weak guess —
# the classic false positive (argmax lands on an attack class at ~20-40% while Benign is close
# behind). Real attacks score ~99% here, so this never costs a true detection.
MIN_LOCAL_CONFIDENCE = 0.70


@dataclass
class Detection:
    """Result of scoring one flow."""
    anomaly_score: float                 # stage-1 score, higher = more anomalous
    is_alert: bool                       # store + alert?
    attack_type: Optional[str] = None    # stage-2 category (None = unknown/none)
    confidence: Optional[float] = None   # stage-2 probability of attack_type
    reason: str = ""
    top_features: List[Dict] = field(default_factory=list)
    flagged: bool = False                # stage 1 said "abnormal" (score at/above θ)
    guesses: List[Dict] = field(default_factory=list)   # stage 2: [{label, probability}], best first


def _guesses(classes: List[str], proba) -> List[Dict]:
    """Every class the model thinks is possible, most likely first."""
    pairs = [(classes[i] if i < len(classes) else str(i), float(p)) for i, p in enumerate(proba)]
    pairs.sort(key=lambda t: t[1], reverse=True)
    return [{"label": label, "probability": round(p, 4)} for label, p in pairs if p >= MIN_GUESS]


def _first_existing(directory: Path, names) -> Optional[Path]:
    for name in names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


class Detector:
    """Holds the Isolation Forest / XGBoost models and scores flows."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.kind = "none"                       # none | legacy | hybrid | local
        self.isolation_forest = None
        self.xgboost = None                      # legacy sklearn-style classifier
        self.booster = None                      # hybrid xgboost.Booster
        self.local = None                        # our local plain-XGBoost model (kind 'local')
        self.scaler = None
        self.label_encoder = None
        self.feature_columns: List[str] = list(FEATURE_COLUMNS)
        self.xgb_appends_if_score = False
        self.models_dir: Optional[Path] = None
        self.errors: Dict[str, str] = {}
        # hybrid metadata
        self.classes: List[str] = []
        self.benign_index: Optional[int] = None
        self.calibrated_threshold: Optional[float] = None   # the threshold the model was tested with
        self.config: Dict = {}
        self.test_metrics: Optional[Dict] = None            # hybrid_metrics.json (real test results)
        self.importances: List[float] = []                 # stage-2 gain per feature (sums to 1)
        self.trained_at: Optional[datetime] = None
        self.versions: Dict[str, str] = {}

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def has_isolation_forest(self) -> bool:
        return self.isolation_forest is not None

    @property
    def has_xgboost(self) -> bool:
        return self.xgboost is not None or self.booster is not None or self.local is not None

    @property
    def has_local(self) -> bool:
        return self.local is not None

    @property
    def loaded(self) -> bool:
        return self.has_isolation_forest or self.has_xgboost or self.has_local

    @property
    def name(self) -> str:
        if self.has_local:
            return "local-xgboost"
        parts = []
        if self.has_isolation_forest:
            parts.append("isolation_forest")
        if self.has_xgboost:
            parts.append("xgboost")
        return "+".join(parts) if parts else "none"

    # ── loading ──────────────────────────────────────────────────────────────

    def load(self, models_dir: Path) -> bool:
        """Load whatever model is in `models_dir`. Returns self.loaded."""
        self.reset()
        self.models_dir = models_dir
        if not models_dir.is_dir():
            self.errors["models_dir"] = f"Directory not found: {models_dir}"
            logger.warning(self.errors["models_dir"])
            return False
        try:
            import joblib  # noqa: F401
        except ImportError:
            self.errors["dependencies"] = "ML libraries missing — pip install -r requirements-ml.txt"
            logger.warning(self.errors["dependencies"])
            return False

        from app.ml.local_adapter import LocalModel
        if LocalModel.present(models_dir):
            self._load_local(models_dir)
        elif (models_dir / HYBRID_CONFIG).is_file():
            self._load_hybrid(models_dir)
        else:
            self._load_legacy(models_dir)
        logger.info(f"Detector ready: {self.name} ({self.kind})")
        return self.loaded

    def _load_local(self, models_dir: Path) -> None:
        """Load our plain-XGBoost model (local_model.pkl + classes.json). Scores CICFlowMeter-4.0
        feature dicts via local_adapter.JAVA_COLUMN. No Isolation-Forest stage: argmax class, and
        any non-Benign class is the attack (confidence floor = stage2_confidence setting)."""
        from app.ml.local_adapter import LocalModel

        self.kind = "local"
        try:
            lm = LocalModel.load(models_dir)
        except Exception as exc:
            self.errors["local"] = f"local_model.pkl: {exc}"
            logger.error(f"Failed to load local model: {exc}")
            self.kind = "none"
            return
        if lm is None:
            self.errors["local"] = "local_model.pkl not found"
            self.kind = "none"
            return
        self.local = lm
        self.classes = [str(c) for c in lm.classes]
        self.benign_index = lm.benign_index() if lm.benign_index() >= 0 else None
        self.feature_columns = list(lm.feats)
        self.versions["model"] = "local-xgboost"
        try:
            import xgboost as xgb
            self.versions["xgboost"] = xgb.__version__
        except Exception:
            pass
        try:
            self.importances = [float(x) for x in getattr(lm.model, "feature_importances_", [])]
        except Exception:
            self.importances = []
        self.trained_at = datetime.fromtimestamp(
            (models_dir / "local_model.pkl").stat().st_mtime, tz=timezone.utc).replace(tzinfo=None)
        logger.info(f"Loaded local model: {lm.n_classes} classes, {len(lm.feats)} features")

    def _load_hybrid(self, models_dir: Path) -> None:
        import joblib
        import numpy as np

        self.kind = "hybrid"
        try:
            cfg = json.loads((models_dir / HYBRID_CONFIG).read_text(encoding="utf-8"))
            self.feature_columns = [str(c) for c in cfg["features_used"]]
            self.classes = [str(c) for c in cfg["classes"]]
            self.benign_index = int(cfg.get("benign_code", self.classes.index("Benign")))
            self.calibrated_threshold = float(cfg["threshold"])
            self.config = cfg
        except (OSError, ValueError, KeyError) as exc:
            self.errors["config"] = f"{HYBRID_CONFIG}: {exc}"
            logger.error(f"Hybrid model config unreadable: {exc}")
            self.kind = "none"
            return
        n = len(self.feature_columns)

        def _joblib(kind: str, name: str):
            path = models_dir / name
            if not path.is_file():
                self.errors[kind] = f"{name} not found"
                return None
            try:
                obj = joblib.load(path)
            except Exception as exc:
                self.errors[kind] = f"{name}: {exc}"
                logger.error(f"Failed to load {kind} from {path}: {exc}")
                return None
            if getattr(obj, "n_features_in_", n) != n:
                self.errors[kind] = f"{name} expects {obj.n_features_in_} features, the config lists {n}"
                logger.error(self.errors[kind])
                return None
            logger.info(f"Loaded {kind}: {name}")
            return obj

        self.scaler = _joblib("scaler", HYBRID_SCALER)
        iforest = _joblib("isolation_forest", HYBRID_IF)
        # stage 1 needs its scaler: the forest was trained on scaled log features
        self.isolation_forest = iforest if self.scaler is not None else None
        if iforest is not None and self.scaler is None:
            self.errors["isolation_forest"] = "scaler.joblib is required by the Isolation Forest"

        xgb_path = models_dir / HYBRID_XGB
        if xgb_path.is_file():
            try:
                import xgboost as xgb

                booster = xgb.Booster()
                booster.load_model(str(xgb_path))
                params = json.loads(booster.save_config())["learner"]["learner_model_param"]
                n_class = int(params.get("num_class", 0))
                if booster.num_features() != n or n_class != len(self.classes):
                    raise ValueError(f"model has {booster.num_features()} features / {n_class} classes, "
                                     f"config lists {n} / {len(self.classes)}")
                self.booster = booster
                gain = booster.get_score(importance_type="gain")
                raw = [float(gain.get(f"f{i}", 0.0)) for i in range(n)]
                total = sum(raw) or 1.0
                self.importances = [g / total for g in raw]
                self.versions["xgboost"] = xgb.__version__
                self.trained_at = datetime.fromtimestamp(xgb_path.stat().st_mtime, tz=timezone.utc).replace(tzinfo=None)
                logger.info(f"Loaded xgboost: {HYBRID_XGB} ({booster.num_boosted_rounds()} rounds x {n_class} classes)")
            except Exception as exc:
                self.errors["xgboost"] = f"{HYBRID_XGB}: {exc}"
                logger.error(f"Failed to load stage-2 XGBoost: {exc}")
        else:
            self.errors["xgboost"] = f"{HYBRID_XGB} not found"

        try:
            import sklearn
            self.versions["scikit-learn"] = sklearn.__version__
        except ImportError:
            pass
        metrics_path = models_dir / HYBRID_METRICS
        if metrics_path.is_file():
            try:
                self.test_metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                self.errors["metrics"] = f"{HYBRID_METRICS}: {exc}"
        _ = np  # numpy is needed by both stages; imported here so a missing install fails at load time

    def _load_legacy(self, models_dir: Path) -> None:
        import joblib

        self.kind = "legacy"

        def _load(kind: str, names) -> object:
            path = _first_existing(models_dir, names)
            if path is None:
                return None
            try:
                obj = joblib.load(path)
                logger.info(f"Loaded {kind}: {path.name}")
                return obj
            except Exception as exc:
                self.errors[kind] = f"{path.name}: {exc}"
                logger.error(f"Failed to load {kind} from {path}: {exc}")
                return None

        columns = _load("feature_columns", COLUMNS_FILES)
        if columns is not None:
            self.feature_columns = [str(c) for c in list(columns)]
        self.scaler = _load("scaler", SCALER_FILES)
        self.isolation_forest = _load("isolation_forest", IF_FILES)
        self.xgboost = _load("xgboost", XGB_FILES)
        self.label_encoder = _load("label_encoder", ENCODER_FILES)

        n_features = len(self.feature_columns)
        if self.scaler is not None and getattr(self.scaler, "n_features_in_", n_features) != n_features:
            self.errors["scaler"] = "Scaler feature count does not match feature_columns — scaler ignored"
            logger.warning(self.errors["scaler"])
            self.scaler = None
        if self.xgboost is not None:
            expected = getattr(self.xgboost, "n_features_in_", n_features)
            self.xgb_appends_if_score = expected == n_features + 1
            if expected not in (n_features, n_features + 1):
                self.errors["xgboost"] = f"XGBoost expects {expected} features, have {n_features} — disabled"
                logger.error(self.errors["xgboost"])
                self.xgboost = None
            elif self.xgb_appends_if_score and self.isolation_forest is None:
                self.errors["xgboost"] = "This XGBoost model needs the Isolation Forest score as input — disabled"
                logger.error(self.errors["xgboost"])
                self.xgboost = None
        if not self.loaded:
            self.kind = "none"

    # ── metadata ─────────────────────────────────────────────────────────────

    def attack_classes(self) -> List[str]:
        return [c for c in self._classes() if c.lower() not in BENIGN_LABELS]

    def _classes(self) -> List[str]:
        if self.kind in ("hybrid", "local"):
            return list(self.classes)
        if self.label_encoder is not None:
            return [str(c) for c in self.label_encoder.classes_]
        if self.xgboost is not None and hasattr(self.xgboost, "classes_"):
            return [str(c) for c in self.xgboost.classes_]
        return []

    def _weights(self) -> Optional[List[float]]:
        if self.kind in ("hybrid", "local"):
            return self.importances or None
        if self.xgboost is not None and hasattr(self.xgboost, "feature_importances_"):
            return [float(w) for w in list(self.xgboost.feature_importances_)[: len(self.feature_columns)]]
        return None

    def feature_importance(self, limit: int = 20) -> List[Dict]:
        """Global stage-2 feature importances (the Isolation Forest has none)."""
        if self.kind == "hybrid":
            weights = self.importances
            names = self.feature_columns
        elif self.xgboost is not None and hasattr(self.xgboost, "feature_importances_"):
            weights = [float(w) for w in self.xgboost.feature_importances_]
            names = list(self.feature_columns) + (["IF anomaly score"] if self.xgb_appends_if_score else [])
        else:
            return []
        pairs = sorted(zip(names, weights), key=lambda p: p[1], reverse=True)
        return [
            {"feature_name": n, "importance_score": round(s, 6), "rank": i + 1}
            for i, (n, s) in enumerate(pairs[:limit]) if s > 0
        ]

    def stage2_info(self) -> Dict:
        """n_estimators / max_depth / learning_rate of the stage-2 model — only what is really known.

        An XGBoost model file does not keep its training settings (reading them back gives
        XGBoost's defaults), so for the hybrid model depth / learning rate come only from
        model_config.json when it records them ("xgb_params"); otherwise they are left empty.
        """
        if self.booster is not None:
            params = self.config.get("xgb_params") or {}
            return {
                "n_estimators": self.booster.num_boosted_rounds(),
                "max_depth": params.get("max_depth"),
                "learning_rate": params.get("learning_rate"),
            }
        if self.xgboost is not None and hasattr(self.xgboost, "get_params"):
            p = self.xgboost.get_params()
            return {"n_estimators": p.get("n_estimators"), "max_depth": p.get("max_depth"),
                    "learning_rate": p.get("learning_rate")}
        return {}

    # ── scoring (CPU-bound: call via asyncio.to_thread) ──────────────────────

    def analyze(
        self,
        features: Dict[str, float],
        threshold: float,
        stage2_enabled: bool = True,
        stage2_confidence: float = 0.0,
    ) -> Optional[Detection]:
        """Score one flow. Returns None when no model is loaded."""
        if not self.loaded:
            return None
        if self.kind == "local":
            return self._analyze_local_batch([features], threshold, stage2_enabled, stage2_confidence)[0]
        if self.kind == "hybrid":
            return self._analyze_hybrid([features], threshold, stage2_enabled, stage2_confidence)[0]
        return self._analyze_legacy(features, threshold, stage2_enabled, stage2_confidence)

    def analyze_batch(
        self,
        features_list: List[Dict[str, float]],
        threshold: float,
        stage2_enabled: bool = True,
        stage2_confidence: float = 0.0,
    ) -> List[Optional[Detection]]:
        """Score many flows at once — same verdicts as analyze(), much faster for a burst
        (the models' fixed per-call cost is paid once)."""
        if not features_list:
            return []
        if not self.loaded:
            return [None] * len(features_list)
        if self.kind == "local":
            return self._analyze_local_batch(features_list, threshold, stage2_enabled, stage2_confidence)
        if self.kind == "hybrid":
            return self._analyze_hybrid(features_list, threshold, stage2_enabled, stage2_confidence)
        return [self._analyze_legacy(f, threshold, stage2_enabled, stage2_confidence) for f in features_list]

    def _analyze_local_batch(self, features_list: List[Dict[str, float]], threshold: float,
                             stage2_enabled: bool, stage2_confidence: float) -> List[Optional[Detection]]:
        """Score flows with our plain-XGBoost model. `threshold` (the IF alarm level) is not used -
        our model has no anomaly stage; the attack call is argmax != Benign, gated by the confidence
        floor (stage2_confidence). A flow missing any required feature is not scored (no placeholder)."""
        import numpy as np

        proba, ok = self.local.score_batch(features_list)
        classes = self._classes()
        binx = self.local.benign_index()
        floor = max(stage2_confidence, MIN_LOCAL_CONFIDENCE)   # never fire on a weak guess
        out: List[Optional[Detection]] = []
        for i in range(len(features_list)):
            if not ok[i]:
                out.append(Detection(anomaly_score=0.0, is_alert=False,
                                     reason="Flow was missing required features — not scored"))
                continue
            p = proba[i]
            idx = int(np.argmax(p))
            label = classes[idx] if idx < len(classes) else str(idx)
            conf = float(p[idx])
            benign_p = float(p[binx]) if binx >= 0 else None
            anomaly = (1.0 - benign_p) if benign_p is not None else conf
            is_attack = label.lower() not in BENIGN_LABELS and conf >= floor
            out.append(Detection(
                anomaly_score=anomaly,
                is_alert=is_attack,
                attack_type=label if is_attack else None,
                confidence=conf if is_attack else None,
                reason=(f"Matches the pattern of {label} ({conf:.0%} sure)" if is_attack
                        else f"Looks normal ({label} {conf:.0%} sure)"),
                top_features=[],
                flagged=is_attack,
                guesses=_guesses(classes, p) if is_attack else [],
            ))
        return out

    def _analyze_hybrid(self, features_list: List[Dict[str, float]], threshold: float,
                        stage2_enabled: bool, stage2_confidence: float) -> List[Detection]:
        import numpy as np

        X = np.array([[float(f.get(name, 0.0)) for name in self.feature_columns] for f in features_list],
                     dtype=np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        n = len(X)

        Z = None
        scores = None
        if self.isolation_forest is not None:
            Z = self.scaler.transform(np.log1p(np.clip(X, 0, None) + 1.0))
            scores = -self.isolation_forest.score_samples(Z)
            flagged = np.flatnonzero(scores >= threshold)
        else:
            flagged = np.arange(n)

        results: List[Optional[Detection]] = [None] * n
        for i in range(n):
            if scores is not None and scores[i] < threshold:
                results[i] = Detection(anomaly_score=float(scores[i]), is_alert=False)

        use_stage2 = self.booster is not None and (stage2_enabled or scores is None)
        proba = None
        if use_stage2 and len(flagged):
            import xgboost as xgb
            proba = self.booster.predict(xgb.DMatrix(X[flagged]))

        for k, i in enumerate(flagged):
            score = float(scores[i]) if scores is not None else None
            top = self._top_features(Z[i] if Z is not None else X[i])
            # plain words for people (no model names): what was unusual, then the attack guess
            stage1 = (f"The traffic looked unusual: score {score:.3f} is at or above the alarm level {threshold:.3f}"
                      if score is not None else "Checked for known attack patterns")
            if proba is None:
                # anomaly without a category
                results[i] = Detection(score, True, None, None, stage1, top, flagged=True)
                continue
            p = proba[k]
            idx = int(np.argmax(p))
            label = self.classes[idx] if idx < len(self.classes) else str(idx)
            confidence = float(p[idx])
            anomaly = score if score is not None else 1.0 - float(p[self.benign_index or 0])
            guesses = _guesses(self.classes, p)
            if idx == self.benign_index:
                # tested behaviour: stage 2 answering Benign cancels the stage-1 flag
                results[i] = Detection(anomaly_score=anomaly, is_alert=False,
                                       reason=f"{stage1}. A second check found normal traffic ({confidence:.0%} sure) - not an attack",
                                       flagged=scores is not None, guesses=guesses)
                continue
            attack_type = label if confidence >= stage2_confidence else None
            results[i] = Detection(anomaly, True, attack_type, confidence,
                                   f"{stage1}. Most likely attack: {label} ({confidence:.0%} sure)", top,
                                   flagged=True, guesses=guesses)
        return results

    def _analyze_legacy(self, features: Dict[str, float], threshold: float,
                        stage2_enabled: bool, stage2_confidence: float) -> Detection:
        import numpy as np

        raw = np.array(
            [[float(features.get(name, 0.0)) for name in self.feature_columns]], dtype=np.float64
        )
        raw = np.nan_to_num(raw, nan=0.0, posinf=0.0, neginf=0.0)
        scaled = self.scaler.transform(raw) if self.scaler is not None else raw

        # Stage 1 — Isolation Forest
        if_score = None
        if self.isolation_forest is not None:
            if_score = float(-self.isolation_forest.score_samples(scaled)[0])
            if if_score <= threshold:
                return Detection(anomaly_score=if_score, is_alert=False)

        # Stage 2 — XGBoost
        label, confidence, benign_p, guesses = None, None, None, []
        if self.xgboost is not None and (stage2_enabled or self.isolation_forest is None):
            x2 = scaled
            if self.xgb_appends_if_score:
                decision = float(self.isolation_forest.decision_function(scaled)[0])
                x2 = np.column_stack([scaled, [decision]])
            proba = self.xgboost.predict_proba(x2)[0]
            idx = int(np.argmax(proba))
            classes = self._classes()
            label = classes[idx] if idx < len(classes) else str(idx)
            confidence = float(proba[idx])
            benign_idx = next((i for i, c in enumerate(classes) if c.lower() in BENIGN_LABELS), None)
            benign_p = float(proba[benign_idx]) if benign_idx is not None else None
            guesses = _guesses(classes, proba)

        top = self._top_features(scaled[0])

        if if_score is not None:
            attack_type = None
            if label is not None and label.lower() not in BENIGN_LABELS and confidence >= stage2_confidence:
                attack_type = label
            reason = f"The traffic looked unusual: score {if_score:.3f} is above the alarm level {threshold:.2f}"
            if label is not None:
                reason += f". Most likely attack: {label} ({confidence:.0%} sure)"
            return Detection(if_score, True, attack_type, confidence if attack_type else None, reason, top,
                             flagged=True, guesses=guesses)

        # XGBoost only
        anomaly = 1.0 - benign_p if benign_p is not None else confidence or 0.0
        is_attack = label is not None and label.lower() not in BENIGN_LABELS and confidence >= stage2_confidence
        return Detection(
            anomaly_score=anomaly,
            is_alert=is_attack,
            attack_type=label if is_attack else None,
            confidence=confidence if is_attack else None,
            reason=f"Matches the pattern of {label} ({confidence:.0%} sure)",
            top_features=top if is_attack else [],
            flagged=is_attack,
            guesses=guesses if is_attack else [],
        )

    def _top_features(self, row, k: int = 5) -> List[Dict]:
        """ExplainTop: features furthest from the training distribution.

        With a StandardScaler the scaled value is a z-score, so |z| is a
        direct measure of how unusual the feature is. Stage-2 importances
        (when available) weight the ranking toward features the model uses.
        """
        weights = self._weights()
        scored = []
        for i, name in enumerate(self.feature_columns):
            value = float(row[i])
            if not math.isfinite(value):
                continue
            contribution = abs(value) * (float(weights[i]) if weights and i < len(weights) else 1.0)
            scored.append((name, value, contribution))
        scored.sort(key=lambda t: t[2], reverse=True)
        return [
            {"name": n, "value": round(v, 4), "contribution": round(c, 4)}
            for n, v, c in scored[:k] if c > 0
        ]


detector = Detector()


def get_detector() -> Detector:
    return detector
