# SecureNet — Network Intrusion Detection System (IDS)

SecureNet is a live network intrusion detection system. It captures your computer's network
traffic, scores each flow with a hybrid **Isolation Forest + XGBoost** model, and shows the result
on a web dashboard — **NORMAL** or **ABNORMAL (attack detected)** — with per-attack details,
desktop/email alerts, reports, and an optional **Advanced Protection** mode that blocks an
attacker's IP at the Windows Firewall.

The database is **cloud-hosted (Neon PostgreSQL)**, so you log in with a username/email and
password and use the app from any machine that has the connection string.

---

## ⚠️ IMPORTANT — read this first (database & credentials)

This app connects to a **shared cloud database**. To log in to the owner's accounts, your copy
needs the owner's `DATABASE_URL` (which contains the database **password**), and — for OTP/alert
emails — an SMTP app password.

- **These secrets are NOT in this repository** (a `.env.example` template is provided instead).
- **Get the real `DATABASE_URL` (and email settings) privately from the project owner** and put
  them in your own `backend\.env`. **Never commit `.env` or post these values publicly** — anyone
  who has the `DATABASE_URL` can read, change, or delete the entire database and all accounts.
- If you just want your **own** separate instance, create a free database at https://neon.tech and
  use **your** connection string instead — but then you won't share the owner's accounts/data.

---

## What you need (prerequisites, Windows 10/11)

| Needed for | Software |
|---|---|
| Backend (required) | **Python 3.11–3.13** — https://www.python.org/downloads/ (tick "Add to PATH") |
| Dashboard build (required once) | **Node.js 20+** — https://nodejs.org (a prebuilt `frontend\dist` is included, but SETUP installs Node to run the dev server) |
| Live packet capture (required for real detection) | **Npcap** — https://npcap.com  ·  and run the app **as Administrator** |
| Accurate flow features (recommended) | **Java 8+** and **CICFlowMeter-4.0** (see "Accurate live capture" below) |

> You can also run it **dashboard-only** (log in, browse data, see settings) with just Python +
> the cloud database, without capture — handy for a quick demo.

---

## Setup (first time on a PC)

1. **Download / clone** this repository to a folder, e.g. `C:\SecureNetIDS`.
2. **Create your environment file:** copy `backend\.env.example` to `backend\.env`.
   Open `backend\.env` and fill in at least:
   - `DATABASE_URL` — the cloud connection string from the owner (or your own Neon DB).
   - `JWT_SECRET` — any long random string (32+ characters).
   - `ADMIN_EMAILS` — leave empty to let the first registered account become admin, or list admin emails.
   - For emails/OTP: set `EMAIL_ENABLED=true`, `SMTP_USER`, `SMTP_PASSWORD` (a Gmail **App Password**).
     If you leave `EMAIL_ENABLED=false`, sign-up that needs an emailed code won't work — use an
     account the owner already created.
3. **Run the installer:** double-click **`SETUP.bat`** (or run `SETUP.ps1` in PowerShell).
   It creates the Python virtual environment, installs the backend packages
   (`requirements.txt` + `requirements-ml.txt`), finds/installs Node, and installs the dashboard
   packages. Run it from the project folder.

---

## Run it

1. **Right-click `START_SECURENET.bat` → Run as administrator** (admin is needed for live capture
   and for Protection-mode firewall blocking).
2. It starts the backend (port 8000) and the dashboard (port 5173) and opens your browser at
   **http://localhost:5173**. (If those ports are busy it picks the next free one.)
3. **Log in** with the email + password the owner gave you (an OTP code may be emailed if email is on).
4. Press **ON** on the dashboard to start monitoring. The headline shows NORMAL / ABNORMAL and a
   live breakdown of traffic by class.

To stop: close the two server windows, or press OFF in the app.

Backend API docs (when `DEBUG=true`): **http://localhost:8000/docs**.

---

## Accurate live capture (recommended) — Java + CICFlowMeter-4.0

The model was trained on flows produced by the real **Java CICFlowMeter-4.0**. For correct
detection, feed it that same tool via the `live_ids\` pipeline instead of the built-in capture:

1. Install a **Java runtime** (JDK 8 or newer).
2. Get **CICFlowMeter-4.0** (build it from https://github.com/ahlashkari/CICFlowMeter or copy an
   existing `CICFlowMeter-4.0` distribution folder).
3. Edit **`live_ids\common.py`** and set the two Windows paths to YOUR locations:
   - `CONV_DIR` → your `...\CICFlowMeter-4.0` folder
   - `JAVA_EXE` → your `...\bin\java.exe` (or just `"java"` if Java is on PATH)
4. In `backend\.env`, uncomment and set the `CAPTURE_SOURCE=local_csv` block (the five `LIVE_*`
   lines) — point `LIVE_PROJECT_DIR` at this project folder and `LIVE_PYTHON` at
   `backend\venv\Scripts\python.exe`.
5. Start the app **as Administrator**. The capture + conversion run automatically in the background
   (no extra terminals).

Without this, leave `CAPTURE_SOURCE` unset and the app uses its simpler built-in scapy capture
(still needs Npcap + admin), which is less accurate on this particular model.

---

## What's in this download

```
backend\      FastAPI backend (app code, requirements, alembic migrations, the trained model in backend\models\)
frontend\     React/Vite dashboard (source + prebuilt dist\)
desktop\      Optional Electron wrapper (a native app window instead of the browser)
live_ids\     Live capture pipeline (WinDivert capture + CICFlowMeter conversion scripts)
model\        A copy of the trained model (local_model.pkl + classes.json)
scripts\      Helper scripts used by SETUP / START
SETUP.bat / SETUP.ps1            one-time installer
START_SECURENET.bat / .ps1       run the app
backend\.env.example             configuration template (copy to backend\.env)
```

Not included (you create/install these): `backend\.env` (your secrets), the Python `venv`,
`node_modules`, Java, CICFlowMeter-4.0, Npcap.

---

## Troubleshooting

- **"backend\.env is missing"** → copy `backend\.env.example` to `backend\.env` and fill it in.
- **Can't log in / database errors** → check `DATABASE_URL` is correct and the computer is online
  (Neon is cloud). Only cloud PostgreSQL is accepted.
- **No OTP email** → set `EMAIL_ENABLED=true` with a valid Gmail **App Password**, or use an
  account that already exists.
- **"Live capture could not start"** → you must run **as Administrator** and have **Npcap** installed.
- **Attacks detected on normal browsing (false alarms)** → the model is lab-trained; narrow what is
  captured or retrain on your own benign traffic (see project notes).
- **Dashboard shows "WAITING FOR TRAFFIC"** → normal right after turning ON until the first flows
  arrive; it clears once traffic is seen.

---

## Security reminders

- Never commit `backend\.env` or share your `DATABASE_URL` / email password publicly.
- Only run attacks/penetration tests against machines you own or are authorized to test.
- Advanced Protection blocks IPs at the Windows Firewall; it never blocks this PC's own addresses.
