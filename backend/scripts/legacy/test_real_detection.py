"""
Test Real-Time Detection with Actual Models
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.ml.models import get_ml_models, initialize_ml_models
import numpy as np

def test_models():
    """Test that models load and work"""
    print("=" * 70)
    print("TESTING REAL-TIME DETECTION WITH TRAINED MODELS")
    print("=" * 70)
    
    # Initialize models
    print("\n[1] Loading models from F:\\all_10_csv_manual...")
    success = initialize_ml_models()
    
    if not success:
        print("X FAILED: Could not load models")
        return False
    
    print("OK Models loaded successfully")
    
    # Get models instance
    ml = get_ml_models()
    
    # Check model info
    print("\n[2] Model Information:")
    info = ml.get_model_info()
    print(f"  Loaded: {info['loaded']}")
    print(f"  Feature count: {info['features']['count']}")
    print(f"  Attack types: {len(info['attack_types'])}")
    print(f"  Attack classes: {info['attack_types'][:5]}...")  # First 5
    print(f"  Isolation Forest: {info['isolation_forest']['status']}")
    print(f"  XGBoost Hybrid: {info['xgboost_hybrid']['status']}")
    print(f"  XGBoost Multiclass: {info['xgboost_multiclass']['status']}")
    print(f"  Threshold: {info['xgboost_hybrid']['threshold']}")
    
    # Test with dummy data
    print("\n[3] Testing detection pipeline with dummy data...")
    n_features = info['features']['count']
    print(f"  Creating dummy flow with {n_features} features...")
    
    # Create a dummy normal flow (all zeros or small values)
    dummy_features = np.random.rand(1, n_features) * 0.1
    
    print("\n[4] Stage 1: Isolation Forest (Anomaly Detection)...")
    try:
        anomaly_scores, is_anomalies = ml.predict_anomaly(dummy_features)
        print(f"  Anomaly Score: {anomaly_scores[0]:.4f}")
        print(f"  Is Anomaly: {is_anomalies[0]}")
        print("  OK Isolation Forest works")
    except Exception as e:
        print(f"  X FAILED: {e}")
        return False
    
    print("\n[5] Stage 2a: XGBoost Hybrid (Binary Classification)...")
    try:
        predictions, probabilities = ml.predict_binary(dummy_features, anomaly_scores)
        print(f"  Prediction: {'Attack' if predictions[0] == 1 else 'Normal'}")
        print(f"  Attack Probability: {probabilities[0]:.4f}")
        print("  OK XGBoost Hybrid works")
    except Exception as e:
        print(f"  X FAILED: {e}")
        return False
    
    print("\n[6] Stage 2b: XGBoost Multiclass (Attack Type Classification)...")
    try:
        classes, labels, confidences = ml.predict_multiclass(dummy_features, anomaly_scores)
        print(f"  Predicted Class: {classes[0]}")
        print(f"  Attack Type: {labels[0]}")
        print(f"  Confidence: {confidences[0]:.4f}")
        print("  OK XGBoost Multiclass works")
    except Exception as e:
        print(f"  X FAILED: {e}")
        return False
    
    # Test with anomalous data
    print("\n[7] Testing with anomalous-looking data...")
    anomalous_features = np.random.rand(1, n_features) * 100  # Large values
    
    try:
        anom_scores, is_anoms = ml.predict_anomaly(anomalous_features)
        preds, probs = ml.predict_binary(anomalous_features, anom_scores)
        classes, labels, confs = ml.predict_multiclass(anomalous_features, anom_scores)
        
        print(f"  Anomaly Score: {anom_scores[0]:.4f} (lower = more anomalous)")
        print(f"  Is Anomaly: {is_anoms[0]}")
        print(f"  Binary Prediction: {'Attack' if preds[0] == 1 else 'Normal'}")
        print(f"  Attack Probability: {probs[0]:.4f}")
        print(f"  Attack Type: {labels[0]}")
        print(f"  Confidence: {confs[0]:.4f}")
        print("  OK Anomalous detection works")
    except Exception as e:
        print(f"  X FAILED: {e}")
        return False
    
    print("\n" + "=" * 70)
    print("RESULT: ALL TESTS PASSED")
    print("=" * 70)
    print("OK Real-time detection is ready")
    print("OK All 3 stages working:")
    print("  1. Isolation Forest (anomaly detection)")
    print("  2. XGBoost Hybrid (binary: normal/attack)")
    print("  3. XGBoost Multiclass (attack type classification)")
    print("\nNext steps:")
    print("1. Turn IDS ON in frontend")
    print("2. System will capture real network packets")
    print("3. Extract 71 features from each flow")
    print("4. Run ML detection pipeline")
    print("5. Save detected events to database")
    print("6. Display in dashboard")
    print("=" * 70)
    
    return True

if __name__ == "__main__":
    success = test_models()
    exit(0 if success else 1)
