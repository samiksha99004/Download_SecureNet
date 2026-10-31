# Legacy scripts (archived — do not run)

These ad-hoc scripts were written during earlier development. Most of them:

* import modules that no longer exist (`app.ml.models`, `app.ml.models_ensemble`,
  the traffic simulators), or
* write **fake security events** into the real database (`inject_*`, `seed_database.py`,
  `traffic_simulator.py`), or
* delete data (`delete_all_test_data.py`, `delete_fake_events.py`).

They are kept only for reference. The maintained test-suite is `backend/tests/`
(`pytest` from the `backend` folder; it uses a temporary SQLite database).
