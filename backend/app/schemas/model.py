"""
SecureNet Backend — ML Model Schemas
"""

from typing import Optional, List

from app.schemas.base import CamelModel, UtcDatetime


class IsolationForestMetrics(CamelModel):
    roc_auc: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None


class IsolationForestInfo(CamelModel):
    status: str  # loaded | not_loaded | error
    version: Optional[str] = None
    n_estimators: Optional[int] = None
    max_samples: Optional[int] = None
    contamination: Optional[float] = None
    threshold: Optional[float] = None            # in use now (settings preset / custom)
    tested_threshold: Optional[float] = None     # the threshold the model was tested with
    feature_count: Optional[int] = None
    feature_names: List[str] = []
    trained_at: Optional[UtcDatetime] = None
    metrics: Optional[IsolationForestMetrics] = None


class PerClassMetric(CamelModel):
    class_name: str
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    support: Optional[int] = None


class XGBoostMetrics(CamelModel):
    evaluation: Optional[str] = None             # what the numbers were measured on
    test_rows: Optional[int] = None
    accuracy: Optional[float] = None
    macro_f1: Optional[float] = None
    weighted_f1: Optional[float] = None
    per_class_metrics: List[PerClassMetric] = []


class XGBoostInfo(CamelModel):
    status: str  # loaded | not_loaded | error
    version: Optional[str] = None
    n_estimators: Optional[int] = None
    max_depth: Optional[int] = None
    learning_rate: Optional[float] = None
    feature_count: Optional[int] = None
    feature_names: List[str] = []
    supported_attack_classes: List[str] = []
    trained_at: Optional[UtcDatetime] = None
    metrics: Optional[XGBoostMetrics] = None


class ModelInfo(CamelModel):
    isolation_forest: Optional[IsolationForestInfo] = None
    xgboost: Optional[XGBoostInfo] = None
    last_refreshed_at: Optional[UtcDatetime] = None


class FeatureImportance(CamelModel):
    feature_name: str
    importance_score: float
    rank: int
