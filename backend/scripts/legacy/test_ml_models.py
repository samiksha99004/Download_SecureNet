"""Test ML models loading"""
from app.ml.models import get_ml_models

print("Testing ML models...")
ml_models = get_ml_models()
success = ml_models.load_models()

if success:
    print(f"✓ ML Models Loaded Successfully")
    print(f"  - Feature count: {ml_models.get_feature_count()}")
    print(f"  - Feature names: {len(ml_models.get_feature_names())} features")
    print(f"  - Attack types: {len(ml_models.get_attack_types())} classes")
    print(f"  - Threshold: {ml_models.xgboost_threshold}")
else:
    print("✗ ML Models Failed to Load")
    exit(1)
