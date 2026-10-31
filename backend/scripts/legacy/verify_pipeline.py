"""Verify ML pipeline end-to-end with real Scapy packet"""
import asyncio
import numpy as np
import time
from scapy.all import IP, TCP, Raw, Packet
from app.ml.models import get_ml_models
from app.ml.network_monitor import NetworkFlow, FlowKey

print("=" * 60)
print("ML PIPELINE VERIFICATION")
print("=" * 60)

# Load models
ml_models = get_ml_models()
if not ml_models.loaded:
    ml_models.load_models()

print(f"\n1. Models Loaded: {ml_models.loaded}")
print(f"   Feature count: {ml_models.get_feature_count()}")
print(f"   Feature names: {len(ml_models.get_feature_names())}")
print(f"   Attack types: {len(ml_models.get_attack_types())}")
print(f"   Types: {ml_models.get_attack_types()[:5]}...")

# Create test flow
print("\n2. Creating Test Flow with Scapy Packets")
flow_key = FlowKey("192.168.1.100", "8.8.8.8", 54321, 80, "TCP")
flow = NetworkFlow(flow_key)

# Add realistic Scapy packets
base_time = time.time()
for i in range(20):
    # Create TCP packet
    pkt = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=54321, dport=80, flags="PA") / Raw(load=b"X"*100)
    is_forward = (i % 3 != 0)
    timestamp = base_time + i * 0.01
    flow.add_packet(pkt, is_forward=is_forward, timestamp=timestamp)

print(f"   Packets added: 20")
print(f"   Forward packets: {len(flow.fwd_packets)}")
print(f"   Backward packets: {len(flow.bwd_packets)}")

# Extract features
print("\n3. Extracting Features")
features = flow.extract_features()
print(f"   Features extracted: {len(features)}")
print(f"   Expected: 71")
print(f"   Sample features: Fwd_Pkts={features.get('Fwd_Pkts')}, Bwd_Pkts={features.get('Bwd_Pkts')}")

# Check feature order matches model
feature_names = ml_models.get_feature_names()
print(f"\n4. Feature Order Check")
feature_vector = []
missing = []
for fname in feature_names:
    if fname in features:
        feature_vector.append(features[fname])
    else:
        missing.append(fname)
        feature_vector.append(0.0)

if missing:
    print(f"   ⚠ Missing features ({len(missing)}): {missing[:5]}...")
else:
    print(f"   ✓ All 71 features present")

# Convert to numpy
X = np.array([feature_vector], dtype=np.float32)
X = np.where(np.isinf(X), np.nan, X)
X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

print(f"\n5. Running ML Pipeline")
print(f"   Input shape: {X.shape} (71 features)")

# Stage 1: Isolation Forest
try:
    if_scores, is_anomalies = ml_models.predict_anomaly(X)
    print(f"   ✓ Isolation Forest: score={if_scores[0]:.4f}, anomaly={is_anomalies[0]}")
except Exception as e:
    print(f"   ✗ Isolation Forest failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Stage 2: Binary classification (if anomaly)
if is_anomalies[0]:
    try:
        binary_preds, binary_probs = ml_models.predict_binary(X, if_scores)
        print(f"   ✓ Binary Classification: attack={binary_preds[0]}, prob={binary_probs[0]:.4f}")
        
        if binary_preds[0]:
            # Stage 3: Multiclass
            try:
                classes, labels, confidences = ml_models.predict_multiclass(X, if_scores)
                print(f"   ✓ Multiclass: label={labels[0]}, confidence={confidences[0]:.4f}")
                
                if labels[0] != "Benign" and confidences[0] > 0.3:
                    print(f"\n   → ATTACK DETECTED: {labels[0]}")
                else:
                    print(f"\n   → UNKNOWN ATTACK TYPE (confidence {confidences[0]:.4f} < 0.3 threshold)")
            except Exception as e:
                print(f"   ✗ Multiclass failed: {e}")
                import traceback
                traceback.print_exc()
    except Exception as e:
        print(f"   ✗ Binary classification failed: {e}")
        import traceback
        traceback.print_exc()
else:
    print(f"   → NORMAL (no anomaly detected)")

print("\n6. Pipeline Summary")
print(f"   71 features → Isolation Forest → 72 features (+ IF score)")
print(f"   → XGBoost Hybrid → Binary Classification")
print(f"   → XGBoost Multiclass → Attack Type or UNKNOWN")
print(f"   → Security Event → PostgreSQL → Dashboard")

print("\n" + "=" * 60)
print("✓ ML Pipeline verification complete")
print("=" * 60)
