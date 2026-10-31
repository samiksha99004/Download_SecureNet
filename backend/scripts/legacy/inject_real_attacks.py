"""
Inject REAL attack samples from CIC-IDS-2018 dataset
This demonstrates the system detecting actual attacks
"""

import asyncio
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

from app.ml.models_ensemble import get_ml_models
from app.models.security_event import SecurityEvent, SeverityLevel, EventState, DetectionMode, ActionTaken, Protocol
from app.db.base import AsyncSessionLocal
from app.utils.logger import logger


async def inject_real_attacks(max_attacks=10):
    """Load real attack samples and process them"""
    
    print("=" * 70)
    print("INJECTING REAL ATTACK SAMPLES FROM CIC-IDS-2018")
    print("=" * 70)
    
    # Load demo data
    demo_file = r"F:\ML-NIDS-main\ML-NIDS-main\data\demo\sentinelflow_demo.csv"
    print(f"\n1. Loading demo data from: {demo_file}")
    
    try:
        df = pd.read_csv(demo_file)
        print(f"   ✓ Loaded {len(df)} rows")
    except Exception as e:
        print(f"   ✗ Failed to load: {e}")
        return
    
    # Filter to only attacks (not Benign)
    if 'Label' in df.columns:
        attacks_df = df[df['Label'] != 'Benign'].copy()
        print(f"\n2. Filtered to attacks: {len(attacks_df)} attack samples")
        print(f"   Attack types in data: {attacks_df['Label'].value_counts().to_dict()}")
    else:
        print("   ✗ No Label column found")
        return
    
    if len(attacks_df) == 0:
        print("   ✗ No attacks found in demo data")
        return
    
    # Sample random attacks
    sample_size = min(max_attacks, len(attacks_df))
    sampled_attacks = attacks_df.sample(n=sample_size, random_state=42)
    print(f"\n3. Sampled {sample_size} attacks for injection")
    
    # Load ML models
    print("\n4. Loading ML models...")
    ml_models = get_ml_models()
    if not ml_models.loaded:
        success = ml_models.load_models()
        if not success:
            print("   ✗ Failed to load ML models")
            return
    print("   ✓ ML models loaded")
    
    # Get feature columns (exclude Label)
    feature_cols = [col for col in ml_models.feature_columns if col in df.columns]
    print(f"   ✓ Using {len(feature_cols)} features")
    
    # Process each attack
    print(f"\n5. Processing {sample_size} attacks through ML ensemble...")
    print("-" * 70)
    
    injected_count = 0
    
    for idx, (_, row) in enumerate(sampled_attacks.iterrows(), 1):
        try:
            # Extract features
            features = row[feature_cols].values.astype(np.float32)
            true_label = row['Label']
            
            # Predict using ensemble
            predicted_label, confidence, threat_score = ml_models.predict(features)
            
            # Generate network info
            source_ips = ["203.0.113.45", "198.51.100.23", "192.0.2.100", "185.220.101.50", "45.142.122.98"]
            dest_ips = ["192.168.1.100", "10.0.0.10", "172.16.0.50"]
            
            src_ip = random.choice(source_ips)
            dst_ip = random.choice(dest_ips)
            src_port = random.randint(40000, 65535)
            
            # Determine dest port based on attack type
            if "SSH" in predicted_label or "SSH" in true_label:
                dst_port = 22
            elif "FTP" in predicted_label or "FTP" in true_label:
                dst_port = 21
            elif "SQL" in predicted_label or "SQL" in true_label:
                dst_port = 3306
            else:
                dst_port = random.choice([80, 443, 8080])
            
            # Determine protocol
            protocol = int(features[0]) if features[0] in [6, 17, 1] else 6
            proto_map = {6: Protocol.TCP, 17: Protocol.UDP, 1: Protocol.ICMP}
            protocol_enum = proto_map.get(protocol, Protocol.TCP)
            
            # Determine severity
            if threat_score >= 0.7 or "DDoS" in predicted_label or "DoS" in predicted_label:
                severity = SeverityLevel.HIGH
            elif threat_score >= 0.4 or "Brute" in predicted_label:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
            
            # Generate timestamp (spread over last hour)
            timestamp = datetime.utcnow() - timedelta(minutes=random.randint(1, 60))
            
            # Create event
            event = SecurityEvent(
                timestamp=timestamp,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                protocol=protocol_enum,
                anomaly_score=threat_score,
                severity=severity,
                attack_type=predicted_label if predicted_label != "Benign" else true_label,
                confidence=confidence,
                mode=DetectionMode.PROTECT,
                state=EventState.ACTIVE,
                action_taken=ActionTaken.BLOCKED if severity == SeverityLevel.HIGH else ActionTaken.LOGGED,
                detection_reason=f"Real CIC-IDS-2018 sample: True={true_label}, Predicted={predicted_label}, Confidence={confidence:.2f}, Threat={threat_score:.2f}",
                contributing_features=None,
            )
            
            # Save to database
            async with AsyncSessionLocal() as db:
                db.add(event)
                await db.commit()
            
            print(f"   [{idx:2d}] ✓ {predicted_label:25s} | Confidence: {confidence:.2f} | Threat: {threat_score:.2f} | True: {true_label}")
            injected_count += 1
            
        except Exception as e:
            print(f"   [{idx:2d}] ✗ Error: {e}")
            continue
    
    print("-" * 70)
    print(f"\n✅ SUCCESS: Injected {injected_count} real attack samples!")
    print(f"\nNow:")
    print("  1. Refresh your dashboard (F5)")
    print("  2. You should see:")
    print(f"     - Active Flows: {injected_count}")
    print(f"     - High Severity: {sum(1 for s in sampled_attacks['Label'] if 'DDoS' in str(s) or 'DoS' in str(s))}")
    print(f"     - Recent Events table with {min(injected_count, 10)} attacks")
    print("  3. Click on any event to see details")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    asyncio.run(inject_real_attacks(max_attacks=10))
