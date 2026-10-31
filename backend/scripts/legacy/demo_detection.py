"""
Demo: Simulate Real-Time Detection
Shows how a network flow would be processed through the ML pipeline
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.ml.models import get_ml_models, initialize_ml_models
import numpy as np

def demo_detection():
    """Demonstrate the complete detection pipeline"""
    print("=" * 80)
    print("SECURENET IDS - REAL-TIME DETECTION DEMO")
    print("=" * 80)
    
    # Initialize models
    print("\n[STARTUP] Loading trained ML models...")
    initialize_ml_models()
    ml = get_ml_models()
    
    print(f"OK Models loaded successfully")
    print(f"   - Isolation Forest: {ml.get_feature_count()} features")
    print(f"   - Attack types: {len(ml.get_attack_types())} classes")
    
    # Simulate 3 different network flows
    flows = [
        ("Normal Web Browsing", np.random.rand(1, 71) * 0.1),  # Small values = normal
        ("Suspicious Activity", np.random.rand(1, 71) * 10),   # Medium values
        ("Potential Attack", np.random.rand(1, 71) * 100),     # Large values
    ]
    
    for flow_name, features in flows:
        print("\n" + "=" * 80)
        print(f"ANALYZING: {flow_name}")
        print("=" * 80)
        
        # Stage 1: Isolation Forest
        print("\n[STAGE 1] Isolation Forest - Anomaly Detection")
        anom_scores, is_anoms = ml.predict_anomaly(features)
        anomaly_score = anom_scores[0]
        is_anomaly = is_anoms[0]
        
        print(f"  Anomaly Score: {anomaly_score:.4f}")
        print(f"  Is Anomaly: {is_anomaly}")
        print(f"  Status: {'ANOMALOUS' if is_anomaly else 'NORMAL'}")
        
        if not is_anomaly:
            print(f"  → RESULT: Normal traffic - no further action")
            continue
        
        # Stage 2a: Binary Classification
        print("\n[STAGE 2A] XGBoost Hybrid - Binary Classification")
        preds, probs = ml.predict_binary(features, anom_scores)
        is_attack = preds[0] == 1
        attack_prob = probs[0]
        
        print(f"  Prediction: {'ATTACK' if is_attack else 'NORMAL'}")
        print(f"  Attack Probability: {attack_prob:.4f}")
        print(f"  Threshold: 0.3")
        
        if not is_attack:
            print(f"  → RESULT: Anomaly but not an attack")
            continue
        
        # Stage 2b: Attack Type Classification
        print("\n[STAGE 2B] XGBoost Multiclass - Attack Type Classification")
        classes, labels, confs = ml.predict_multiclass(features, anom_scores)
        attack_type = labels[0]
        confidence = confs[0]
        
        print(f"  Predicted Class: {classes[0]}")
        print(f"  Attack Type: {attack_type}")
        print(f"  Confidence: {confidence:.4f}")
        
        # Determine severity
        if anomaly_score < -0.5:
            severity = "HIGH"
            color = "🔴"
        elif anomaly_score < -0.2:
            severity = "MEDIUM"
            color = "🟡"
        else:
            severity = "LOW"
            color = "🔵"
        
        print(f"\n[RESULT] {color} SECURITY EVENT DETECTED {color}")
        print(f"  Severity: {severity}")
        print(f"  Attack Type: {attack_type if confidence > 0.3 else 'UNKNOWN ATTACK TYPE'}")
        print(f"  Anomaly Score: {abs(anomaly_score):.4f}")
        print(f"  Confidence: {confidence:.2%}")
        
        if severity == "HIGH":
            print(f"  Action: BLOCKED (IP would be blocked via Windows Firewall)")
        else:
            print(f"  Action: LOGGED (Event recorded in database)")
    
    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    print("\nIn real operation:")
    print("1. Scapy captures live network packets")
    print("2. Packets grouped into flows (5-tuple)")
    print("3. 71 features extracted from each flow")
    print("4. Features fed through this exact ML pipeline")
    print("5. Security events created and saved to PostgreSQL")
    print("6. Dashboard updates in real-time via WebSocket")
    print("7. High severity threats automatically blocked")
    print("\nTo see it live:")
    print("1. Login to http://localhost:5174")
    print("2. Click 'IDS ON' button")
    print("3. Generate network traffic (browse web, run nmap, etc.)")
    print("4. Watch events appear in dashboard")
    print("=" * 80)

if __name__ == "__main__":
    demo_detection()
