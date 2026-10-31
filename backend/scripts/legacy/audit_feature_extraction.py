"""
Audit: Compare network_monitor.py feature extraction against actual model requirements
"""
import joblib

# Load actual feature names from model
features_actual = joblib.load(r"F:\all_10_csv_manual\feature_columns.pkl")

# Features extracted by network_monitor.py (UPDATED - after fix)
features_extracted = [
    'Dst Port',
    'Flow Duration',
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    'Fwd Pkt Len Max',
    'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean',
    'Fwd Pkt Len Std',
    'Bwd Pkt Len Max',
    'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std',
    'Flow Byts/s',
    'Flow Pkts/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Tot',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Tot',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Fwd Header Len',
    'Bwd Header Len',
    'Fwd Pkts/s',
    'Bwd Pkts/s',
    'Pkt Len Min',
    'Pkt Len Max',
    'Pkt Len Mean',
    'Pkt Len Std',
    'Pkt Len Var',
    'FIN Flag Cnt',
    'SYN Flag Cnt',
    'RST Flag Cnt',
    'PSH Flag Cnt',
    'ACK Flag Cnt',
    'URG Flag Cnt',
    'CWE Flag Count',
    'ECE Flag Cnt',
    'Down/Up Ratio',
    'Pkt Size Avg',
    'Fwd Seg Size Avg',
    'Bwd Seg Size Avg',
    'Subflow Fwd Pkts',
    'Subflow Fwd Byts',
    'Subflow Bwd Pkts',
    'Subflow Bwd Byts',
    'Init Fwd Win Byts',
    'Init Bwd Win Byts',
    'Fwd Act Data Pkts',
    'Fwd Seg Size Min',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min',
    'Protocol_0',
    'Protocol_6',
    'Protocol_17',
]

print("="*80)
print("FEATURE EXTRACTION AUDIT")
print("="*80)

print(f"\nModel expects: {len(features_actual)} features")
print(f"Code extracts: {len(features_extracted)} features")

# Check for missing features
missing_in_code = []
for i, feature in enumerate(features_actual):
    if feature not in features_extracted:
        missing_in_code.append((i+1, feature))

# Check for extra features
extra_in_code = []
for feature in features_extracted:
    if feature not in features_actual:
        extra_in_code.append(feature)

# Check order mismatch
order_mismatches = []
for i, feature in enumerate(features_extracted):
    if i < len(features_actual) and feature != features_actual[i]:
        order_mismatches.append((i+1, feature, features_actual[i]))

print("\n" + "="*80)
print("RESULTS")
print("="*80)

if missing_in_code:
    print(f"\n✗ MISSING FEATURES ({len(missing_in_code)}):")
    for pos, feature in missing_in_code:
        print(f"  Position {pos}: {feature}")
else:
    print("\n✓ No missing features")

if extra_in_code:
    print(f"\n✗ EXTRA FEATURES ({len(extra_in_code)}):")
    for feature in extra_in_code:
        print(f"  {feature}")
else:
    print("\n✓ No extra features")

if order_mismatches:
    print(f"\n✗ ORDER MISMATCHES ({len(order_mismatches)}):")
    for pos, extracted, expected in order_mismatches:
        print(f"  Position {pos}:")
        print(f"    Extracted: {extracted}")
        print(f"    Expected:  {expected}")
else:
    print("\n✓ Feature order matches")

if not missing_in_code and not extra_in_code and not order_mismatches:
    print("\n" + "="*80)
    print("✓✓✓ FEATURE EXTRACTION IS CORRECT ✓✓✓")
    print("="*80)
else:
    print("\n" + "="*80)
    print("✗✗✗ FEATURE EXTRACTION HAS ERRORS ✗✗✗")
    print("="*80)
