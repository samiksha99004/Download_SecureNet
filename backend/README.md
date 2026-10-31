# SecureNet Backend

FastAPI service for the SecureNet behavioural IDS: live packet capture →
CICIDS2018 flow features → optional Isolation Forest / XGBoost scoring →
PostgreSQL event history → REST + WebSocket for the dashboard.

See the repository-level `CLAUDE.md` for the full architecture and status.

## Setup (Windows, Python 3.11–3.14)

The easiest way is the root `SETUP.bat` (see the main README): it creates `.env` from `.env.example`
with a random `JWT_SECRET`, builds the venv, and creates/updates the database tables. By hand:

```powershell
.\setup.ps1                 # venv + core dependencies (same as the root SETUP.ps1)
.\setup.ps1 -WithML         # + scikit-learn / XGBoost for the trained models
# edit .env (DATABASE_URL, JWT_SECRET, EMAIL_ENABLED / SMTP_USER / SMTP_PASSWORD, ADMIN_EMAILS)
.\venv\Scripts\python.exe -m alembic upgrade head
.\venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```

* Accounts whose email is listed in `ADMIN_EMAILS` become **Admin**; everyone else is a **SecureNet User**.
  `python create_admin_user.py you@example.com` promotes / creates an admin.
* Emails are always really sent (no console fallback). Sign-up, **every sign-in** (password + emailed
  6-digit code), password changes and profile changes all need working SMTP; codes are valid for
  `OTP_EXPIRE_MINUTES` (5). `DATABASE_URL` must be a cloud PostgreSQL (e.g. Neon) database - local
  databases are refused.
* `python create_admin_user.py you@gmail.com` creates / promotes an admin directly (password prompted);
  signing in still needs the emailed code.
* **Alert emails**: set `EMAIL_ENABLED=true`, `SMTP_USER`, `SMTP_PASSWORD` (Gmail App Password) and
  `SMTP_FROM_EMAIL` in `.env`, restart, then use *Settings → Email Alerts → Send test email*.
  Alerts go to every active registered user (plus an optional extra address), batched every
  `ALERT_EMAIL_BATCH_SECONDS`.
* `DEBUG=true` enables the API docs at `/api/docs`.

## Models (optional)
`ML_AUTOLOAD=false` (default) runs the IDS without a model: traffic is captured
and counted but not scored. Put `isolation_forest_model.pkl` and/or
`xgboost_multiclass_model.pkl` (+ `scaler.pkl`, `label_encoder.pkl`,
`feature_columns.pkl`) in `models/`, then set `ML_AUTOLOAD=true` or call
`POST /api/model/reload` as an admin. See `app/ml/README.md`.

## Live capture
Windows: install [Npcap](https://npcap.com) and run the backend as Administrator.
Linux: run as root. Without this, starting the IDS returns a clear 503 error.

## Tests
```powershell
.\venv\Scripts\python.exe -m pytest     # temporary SQLite DB — never touches .env's database
```
