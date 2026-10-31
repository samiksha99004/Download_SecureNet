"""Get exact feature names in order from pickle file"""
import joblib

features = joblib.load(r"F:\all_10_csv_manual\feature_columns.pkl")
print("# Exact feature list from feature_columns.pkl")
print("features_in_order = [")
for f in features:
    print(f"    '{f}',")
print("]")
print(f"\n# Total: {len(features)} features")
