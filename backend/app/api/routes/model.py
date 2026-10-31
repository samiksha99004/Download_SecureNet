"""
SecureNet Backend — ML Model Routes

Status of the optional Isolation Forest / XGBoost models, feature importance,
and an admin endpoint to (re)load models from ML_MODELS_DIR without a restart.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_current_user, require_admin
from app.ml.detector import get_detector
from app.ml.ids_service import get_ids_service
from app.models.user import User
from app.schemas.model import (FeatureImportance, IsolationForestInfo, IsolationForestMetrics, ModelInfo,
                               PerClassMetric, XGBoostInfo, XGBoostMetrics)
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/model", tags=["ML Model"])


def _status(loaded: bool, error_key: str) -> str:
    detector = get_detector()
    if loaded:
        return "loaded"
    return "error" if error_key in detector.errors else "not_loaded"


def _test_metrics(detector) -> tuple[Optional[IsolationForestMetrics], Optional[XGBoostMetrics]]:
    """The model's real test results (hybrid_metrics.json + model_config.json) — never invented."""
    if detector.kind != "hybrid":
        return None, None
    roc = detector.config.get("roc_auc")
    if_metrics = IsolationForestMetrics(roc_auc=float(roc)) if roc is not None else None
    tm = detector.test_metrics
    if not tm or "per_class" not in tm:
        return if_metrics, None
    per = [
        PerClassMetric(class_name=name, precision=v.get("precision"), recall=v.get("recall"),
                       f1_score=v.get("f1"), support=v.get("test_rows"))
        for name, v in tm["per_class"].items()
    ]
    rows = sum(p.support or 0 for p in per)
    f1s = [p.f1_score for p in per if p.f1_score is not None]
    weighted = (sum((p.f1_score or 0) * (p.support or 0) for p in per) / rows) if rows else None
    xgb_metrics = XGBoostMetrics(
        evaluation=(f"Whole two-stage pipeline (Isolation Forest, then XGBoost) on {rows:,} CICIDS2018 test "
                    "flows that neither model saw during training"),
        test_rows=rows or None,
        accuracy=tm.get("overall_accuracy"),
        macro_f1=(sum(f1s) / len(f1s)) if f1s else None,
        weighted_f1=weighted,
        per_class_metrics=per,
    )
    return if_metrics, xgb_metrics


def build_model_info() -> ModelInfo:
    detector = get_detector()
    ids = get_ids_service()
    names = detector.feature_columns
    if_metrics, xgb_metrics = _test_metrics(detector)

    iso = detector.isolation_forest
    max_samples = getattr(iso, "max_samples_", None) if iso is not None else None
    if_info = IsolationForestInfo(
        status=_status(iso is not None, "isolation_forest"),
        version=(f"scikit-learn {detector.versions.get('scikit-learn') or getattr(iso, '_sklearn_version', '')}".strip()
                 if iso is not None else None),
        n_estimators=getattr(iso, "n_estimators", None),
        max_samples=int(max_samples) if max_samples is not None else None,
        contamination=(iso.contamination if iso is not None and isinstance(iso.contamination, float) else None),
        threshold=ids.config.anomaly_threshold,
        tested_threshold=detector.calibrated_threshold,
        feature_count=len(names),
        feature_names=names if iso is not None else [],
        trained_at=detector.trained_at,
        metrics=if_metrics,
    )

    stage2 = detector.stage2_info()
    has_xgb = detector.has_xgboost
    xgb_info = XGBoostInfo(
        status=_status(has_xgb, "xgboost"),
        version=(f"xgboost {detector.versions['xgboost']}" if "xgboost" in detector.versions
                 else ("xgboost" if has_xgb else None)),
        n_estimators=stage2.get("n_estimators"),
        max_depth=stage2.get("max_depth"),
        learning_rate=stage2.get("learning_rate"),
        feature_count=len(names) + (1 if detector.xgb_appends_if_score else 0),
        feature_names=names if has_xgb else [],
        supported_attack_classes=detector.attack_classes(),
        trained_at=detector.trained_at,
        metrics=xgb_metrics,
    )
    return ModelInfo(isolation_forest=if_info, xgboost=xgb_info, last_refreshed_at=utcnow())


@router.get("/info", response_model=ModelInfo)
async def get_model_info(current_user: User = Depends(get_current_user)):
    """Information about both detection stages."""
    return build_model_info()


@router.get("/feature-importance", response_model=List[FeatureImportance])
async def get_feature_importance(
    stage: int = Query(2, ge=1, le=2),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Global feature importance. Only XGBoost (stage 2) provides one; stage 1 returns []."""
    if stage == 1:
        return []
    return [FeatureImportance(**item) for item in get_detector().feature_importance(limit)]


@router.post("/reload", response_model=ModelInfo)
async def reload_models(current_user: User = Depends(require_admin)):
    """Load whatever model artifacts are present in ML_MODELS_DIR (admin only)."""
    ids = get_ids_service()
    loaded = await ids.reload_models()
    if not loaded:
        detail = "; ".join(get_detector().errors.values()) or "No model files found in ML_MODELS_DIR"
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail)
    return build_model_info()
