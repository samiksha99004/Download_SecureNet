# SecureNet detection pipeline

```
Scapy (AsyncSniffer) ─▶ NetworkMonitor ─▶ finished Flow ─▶ FlowRecord (71 CICIDS2018 features)
                                                              │  (thread → asyncio queue)
                                                              ▼
                                        IDSService.process_flow()
                     whitelist ─▶ Detector.analyze() ─▶ live_score (WebSocket)
                                        │ alert?
                                        ▼
                SecurityEvent (DB) ─▶ Protection (netsh / iptables) ─▶ alert (WebSocket, email)
```

## Models are optional
Set `ML_AUTOLOAD=true` in `backend/.env` (or call `POST /api/model/reload` as an admin)
and install `requirements-ml.txt`. The detector looks in `ML_MODELS_DIR` (default
`backend/models/`) for:

| File | Role |
|---|---|
| `isolation_forest_model.pkl` | Stage 1 — anomaly score `-score_samples(x)` compared with the threshold θ |
| `xgboost_multiclass_model.pkl` | Stage 2 — attack category (may take the IF score as an extra last feature) |
| `scaler.pkl` | Applied before both stages when its feature count matches |
| `label_encoder.pkl` | Maps XGBoost class indices to CICIDS2018 labels |
| `feature_columns.pkl` | Feature order (defaults to `features.FEATURE_COLUMNS`) |

Any subset works: IF only, XGBoost only, or both. With nothing loaded the IDS
captures and counts flows but does not score them.

## Capture requirements
* Windows: [Npcap](https://npcap.com) installed; backend run as Administrator.
* Linux: run as root (or grant `CAP_NET_RAW`, and `CAP_NET_ADMIN` for Protection mode).
