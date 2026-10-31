# Detection models

The model files are not stored in git (about 60 MB). SecureNet loads them from this folder at startup
(`ML_AUTOLOAD=true`) or from *Settings → Model → Load / reload models*.

## Current model: hybrid Isolation Forest + XGBoost (retrained 2026-10-06)

Copy these five files from the training folder (`F:\retraining_hybrid`) into this folder:

| File | What it is |
|---|---|
| `model_config.json` | 63 input features (CICIDS2018 names), the 7 classes, the tested stage-1 threshold (0.4602) |
| `scaler.joblib` | StandardScaler for the stage-1 input (`log1p(x + 1)` features) |
| `isolation_forest.joblib` | stage 1 — Isolation Forest, 300 trees, 8,192 rows per tree |
| `xgboost_stage2.json` | stage 2 — XGBoost, 200 rounds × 7 classes, depth 10, raw features |
| `hybrid_metrics.json` | the real test results shown on the Model page |

Tested on 465,837 CICIDS2018 flows that neither model saw: **92.2 % accuracy**
(Benign recall 98.7 %, DDoS 90.7 %, DoS 95.5 %, Bot 99.2 %, Brute Force 99.6 %, Infilteration 27.5 %,
SQL Injection 60 % of 15). Needs `pip install -r requirements-ml.txt` (scikit-learn 1.9.1, XGBoost 3.4.1 —
the versions it was trained with).

`archive_2026-08/` holds the older August models (not used).
