"""
Pytest configuration and fixtures.

Tests run against a throw-away SQLite database - never the real Postgres/Neon
database from backend/.env. The environment is set BEFORE the app is imported.
"""

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="securenet-tests-"))
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["JWT_SECRET"] = "test-secret-key-that-is-long-enough-1234567890"
os.environ["ALLOW_LOCAL_DATABASE"] = "true"   # throw-away SQLite for tests only
os.environ["EMAIL_ENABLED"] = "false"
# never inherit the real .env account / mail settings
os.environ["ADMIN_EMAILS"] = ""
os.environ["SMTP_USER"] = ""
os.environ["SMTP_PASSWORD"] = ""
os.environ["ML_AUTOLOAD"] = "false"
os.environ["REPORTS_DIR"] = str(_TMP / "reports")
os.environ["FRONTEND_DIST"] = ""
# IDS on/off memory: temp files only, never the real Windows Startup folder; no desktop pop-ups
os.environ["IDS_STATE_FILE"] = str(_TMP / "ids-state.json")
os.environ["IDS_STARTUP_DIR"] = str(_TMP / "startup")
os.environ["DESKTOP_NOTIFICATIONS"] = "false"
os.environ["IDS_ON_AT_STARTUP"] = "false"   # tests start the IDS themselves
os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1,::1,test,testserver"

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.db.base import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app import models as _models  # noqa: E402,F401  (register all tables)


@pytest.fixture(autouse=True)
async def database():
    """Fresh schema for every test."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_caches():
    """Remembered users and cached dashboard answers belong to the previous test's database."""
    from app.api.dependencies import clear_user_cache
    from app.services.cache import invalidate
    clear_user_cache()
    invalidate()
    yield
    clear_user_cache()
    invalidate()


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Per-network-address limits are process-wide; start every test clean."""
    from app.utils.ratelimit import limiter
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def captured_otps(monkeypatch):
    """Capture OTP codes instead of emailing/logging them."""
    codes: dict[str, str] = {}

    async def fake_send(email: str, code: str) -> None:
        codes[email] = code

    monkeypatch.setattr("app.api.routes.auth.send_otp_email", fake_send)
    monkeypatch.setattr("app.api.routes.auth.send_password_reset_email", fake_send)
    monkeypatch.setattr("app.api.routes.auth.send_password_change_email", fake_send)
    monkeypatch.setattr("app.api.routes.auth.send_login_code_email", fake_send)

    async def fake_profile_send(email: str, code: str, summary: str) -> None:
        codes[email] = code

    monkeypatch.setattr("app.api.routes.auth.send_profile_change_email", fake_profile_send)
    return codes


async def register(client, captured_otps, email="admin@example.com", password="Passw0rd!", name="Admin",
                   phone="+919876543210"):
    """Full registration: details -> emailed code -> password. Returns the auth response JSON."""
    r = await client.post("/api/auth/signup", json={"fullName": name, "email": email, "phoneNumber": phone})
    assert r.status_code == 200, r.text
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": captured_otps[email]})
    assert r.status_code == 200, r.text
    token = r.json()["setupToken"]
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": token, "password": password, "confirmPassword": password})
    assert r.status_code == 200, r.text
    return r.json()


async def login(client, captured_otps, email, password):
    """Two-step sign-in: password -> emailed code. Returns the auth response JSON."""
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    r = await client.post("/api/auth/login/verify", json={
        "loginToken": r.json()["loginToken"], "otp": captured_otps[email.strip().lower()]})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
async def admin(client, captured_otps):
    """First registered user (becomes admin). Returns (auth json, headers)."""
    auth = await register(client, captured_otps)
    return auth, {"Authorization": f"Bearer {auth['tokens']['accessToken']}"}
