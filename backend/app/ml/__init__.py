"""
SecureNet ML / detection package

- features.py        CICIDS2018 flow features (CICFlowMeter-style)
- network_monitor.py Scapy capture → finished flows
- detector.py        optional Isolation Forest and/or XGBoost scoring
- protection.py      Protection mode firewall blocking
- ids_service.py     live detection loop (capture → detect → store → alert)
"""
