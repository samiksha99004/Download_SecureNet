"""
Inject test detection to verify ML pipeline works
This simulates what would happen when real packets are captured
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.ml.models import get_ml_models, initialize_ml_models
from app.models.security_event import SecurityEvent, SeverityLevel, EventState, DetectionMode, ActionTaken, Protocol
from app.db.base import AsyncSessionLocal
from datetime import datetime
import numpy as np

async def inject_test_detection():
    """Create a test detection event"""
    print("=" * 70)
    print("INJECTING TEST DETECTION")
    print("=" * 70)
    
    # Initialize models
    print("\n[1] Loading ML models...")
    initialize_ml_models()
    ml = get_ml_models()
    print(f"OK Models loaded: {ml.get_feature_count()} features")
    
    # Create suspicious-looking features
    print("\n[2] Creating anomalous network flow features...")
    features = np.random.rand(1, 71) * 50  # Higher values = more suspicious
    
    # Run through ML pipeline
    print("\n[3] Running ML detection...")
    
    # Stage 1: Isolation Forest
    anom_scores, is_anoms = ml.predict_anomaly(features)
    anomaly_score = float(anom_scores[0])
    is_anomaly = bool(is_anoms[0])
    
    print(f"  Isolation Forest:")
    print(f"    Anomaly Score: {anomaly_score:.4f}")
    print(f"    Is Anomaly: {is_anomaly}")
    
    if not is_anomaly:
        print("\n  Not detected as anomaly - trying with more extreme values...")
        features = np.random.rand(1, 71) * 200
        anom_scores, is_anoms = ml.predict_anomaly(features)
        anomaly_score = float(anom_scores[0])
        is_anomaly = bool(is_anoms[0])
        print(f"    New Anomaly Score: {anomaly_score:.4f}")
        print(f"    Is Anomaly: {is_anomaly}")
    
    # Stage 2: Binary classification
    preds, probs = ml.predict_binary(features, anom_scores)
    is_attack = bool(preds[0])
    attack_prob = float(probs[0])
    
    print(f"\n  XGBoost Hybrid (Binary):")
    print(f"    Is Attack: {is_attack}")
    print(f"    Attack Probability: {attack_prob:.4f}")
    
    # Stage 3: Multiclass
    classes, labels, confs = ml.predict_multiclass(features, anom_scores)
    attack_type = labels[0]
    confidence = float(confs[0])
    
    print(f"\n  XGBoost Multiclass:")
    print(f"    Attack Type: {attack_type}")
    print(f"    Confidence: {confidence:.4f}")
    
    # Determine severity
    if anomaly_score < -0.5:
        severity = SeverityLevel.HIGH
    elif anomaly_score < -0.2:
        severity = SeverityLevel.MEDIUM
    else:
        severity = SeverityLevel.LOW
    
    print(f"\n[4] Creating security event...")
    print(f"  Severity: {severity.value}")
    print(f"  Attack Type: {attack_type if confidence > 0.3 else 'UNKNOWN'}")
    
    # Create event
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",  # Test attacker IP
        source_port=54321,
        destination_ip="10.0.0.50",  # Test target IP
        destination_port=80,
        protocol=Protocol.TCP,
        anomaly_score=abs(anomaly_score),
        severity=severity,
        attack_type=attack_type if (attack_type != "Benign" and confidence > 0.3) else None,
        confidence=confidence if confidence > 0.3 else None,
        mode=DetectionMode.PROTECT,
        state=EventState.ACTIVE,
        action_taken=ActionTaken.BLOCKED if severity == SeverityLevel.HIGH else ActionTaken.LOGGED,
        detection_reason=f"TEST: IF score={anomaly_score:.4f}, Binary prob={attack_prob:.4f}",
    )
    
    # Save to database
    print(f"\n[5] Saving to database...")
    async with AsyncSessionLocal() as db:
        db.add(event)
        await db.commit()
        await db.refresh(event)
        print(f"OK Event saved with ID: {event.id}")
    
    print("\n" + "=" * 70)
    print("TEST DETECTION INJECTED SUCCESSFULLY")
    print("=" * 70)
    print("\nCheck dashboard:")
    print("1. Refresh dashboard page")
    print("2. Should see event in 'Recent Events' table")
    print("3. KPI cards should show:")
    print(f"   - Active Flows: 1")
    print(f"   - High Severity: {1 if severity == SeverityLevel.HIGH else 0}")
    print(f"   - Blocked: {1 if severity == SeverityLevel.HIGH else 0}")
    print("4. IDS widget should show 'ABNORMAL' status")
    print("=" * 70)

if __name__ == "__main__":
    asyncio.run(inject_test_detection())
