"""Check ML-NIDS-main model details"""
import pickle
import json
import numpy as np

print("=" * 70)
print("ML-NIDS-main Model Analysis")
print("=" * 70)

# Load label encoder
with open(r'F:\ML-NIDS-main\ML-NIDS-main\models\label_encoder.pkl', 'rb') as f:
    label_encoder = pickle.load(f)

print(f"\n✓ Attack Classes ({len(label_encoder.classes_)}):")
for i, cls in enumerate(label_encoder.classes_):
    print(f"  {i}: {cls}")

# Load feature columns
with open(r'F:\ML-NIDS-main\ML-NIDS-main\models\feature_cols.json', 'r') as f:
    features = json.load(f)

print(f"\n✓ Total Features: {len(features)}")
print(f"\nFirst 10 features:")
for i, feat in enumerate(features[:10]):
    print(f"  {i+1}. {feat}")

# Check selected indices
selected_indices = np.load(r'F:\ML-NIDS-main\ML-NIDS-main\models\selected_indices.npy')
print(f"\n✓ Selected Features (after feature selection): {len(selected_indices)}")

# Check ensemble weights
ensemble_weights = np.load(r'F:\ML-NIDS-main\ML-NIDS-main\models\ensemble_weight.npy')
print(f"\n✓ Ensemble Weights: RF={ensemble_weights[0]:.2f}, XGBoost={ensemble_weights[1]:.2f}")

# Check thresholds
thresholds = np.load(r'F:\ML-NIDS-main\ML-NIDS-main\models\thresholds_ensemble.npy')
print(f"\n✓ Per-class Thresholds: {len(thresholds)} classes")

print("\n" + "=" * 70)
print("Summary:")
print("  - Model Type: Random Forest + XGBoost Ensemble")
print("  - Architecture: Autoencoder + Ensemble Classifiers")
print("  - Input Features: 76 (CICFlowMeter features)")
print(f"  - Selected Features: {len(selected_indices)}")
print(f"  - Attack Classes: {len(label_encoder.classes_)}")
print("=" * 70)
