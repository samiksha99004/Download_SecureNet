"""
Verify actual ML model features from F:\\all_10_csv_manual
"""
import joblib
import os

ML_DIR = r"F:\all_10_csv_manual"

print("="*80)
print("FEATURE VERIFICATION")
print("="*80)

# Check feature columns
feature_path = os.path.join(ML_DIR, "feature_columns.pkl")
if os.path.exists(feature_path):
    features = joblib.load(feature_path)
    print(f"\n✓ feature_columns.pkl: {len(features)} features")
    print("\nFeature names (in order):")
    for i, f in enumerate(features, 1):
        print(f"  {i:2d}. {f}")
else:
    print(f"\n✗ feature_columns.pkl NOT FOUND")

# Check hybrid feature columns
hybrid_path = os.path.join(ML_DIR, "hybrid_feature_columns.pkl")
if os.path.exists(hybrid_path):
    hybrid = joblib.load(hybrid_path)
    print(f"\n✓ hybrid_feature_columns.pkl: {len(hybrid)} features")
    if len(hybrid) == len(features) + 1:
        print("  ✓ Correct: 71 + 1 IF score = 72 features")
    else:
        print(f"  ✗ INCORRECT: Expected {len(features)+1}, got {len(hybrid)}")
else:
    print(f"\n✗ hybrid_feature_columns.pkl NOT FOUND")

# Check threshold
threshold_path = os.path.join(ML_DIR, "xgboost_threshold.pkl")
if os.path.exists(threshold_path):
    threshold = joblib.load(threshold_path)
    print(f"\n✓ xgboost_threshold.pkl: {threshold}")
else:
    print(f"\n✗ xgboost_threshold.pkl NOT FOUND")

# Check label encoder
label_path = os.path.join(ML_DIR, "label_encoder.pkl")
if os.path.exists(label_path):
    encoder = joblib.load(label_path)
    print(f"\n✓ label_encoder.pkl: {len(encoder.classes_)} classes")
    print("  Attack types:")
    for c in encoder.classes_:
        print(f"    - {c}")
else:
    print(f"\n✗ label_encoder.pkl NOT FOUND")

print("\n" + "="*80)
