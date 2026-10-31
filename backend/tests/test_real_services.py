"""No local database and no faked emails."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.utils import email as email_mod


def _settings(**overrides):
    base = {"JWT_SECRET": "x" * 40, "ALLOW_LOCAL_DATABASE": False, "_env_file": None}
    return Settings(**{**base, **overrides})


@pytest.mark.parametrize("url", [
    "sqlite+aiosqlite:///securenet.db",
    "postgresql+asyncpg://u:p@localhost:5432/securenet",
    "postgresql+asyncpg://u:p@127.0.0.1/securenet",
])
def test_local_database_is_refused(url):
    with pytest.raises(ValidationError, match="local database"):
        _settings(DATABASE_URL=url)


@pytest.mark.parametrize("secret", ["short", "replace-with-a-long-random-string-at-least-32-characters"])
def test_example_or_short_jwt_secret_is_refused(secret):
    with pytest.raises(ValidationError, match="JWT_SECRET"):
        _settings(DATABASE_URL="postgresql+asyncpg://u:p@ep-x.aws.neon.tech/neondb?ssl=require", JWT_SECRET=secret)


def test_cloud_database_is_accepted_and_sender_defaults_to_smtp_user():
    s = _settings(DATABASE_URL="postgresql+asyncpg://u:p@ep-x.aws.neon.tech/neondb?ssl=require",
                  SMTP_USER="owner@gmail.com")
    assert s.SMTP_FROM_EMAIL == "owner@gmail.com"


@pytest.mark.parametrize("user,password,expected", [
    ("your-email@gmail.com", "abcdefghijklmnop", "misconfigured"),
    ("owner@gmail.com", "your-app-password", "misconfigured"),
    ("owner@gmail.com", "", "misconfigured"),
    ("owner@gmail.com", "abcdefghijklmnop", "enabled"),
])
def test_placeholder_credentials_are_detected(monkeypatch, user, password, expected):
    monkeypatch.setattr(settings, "EMAIL_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_USER", user)
    monkeypatch.setattr(settings, "SMTP_PASSWORD", password)
    assert email_mod.email_delivery_status() == expected


async def test_disabled_email_raises_instead_of_pretending(monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_ENABLED", False)
    with pytest.raises(email_mod.EmailDeliveryError, match="EMAIL_ENABLED"):
        await email_mod.send_otp_email("someone@gmail.com", "123456")


async def test_signup_without_email_setup_is_refused(client):
    r = await client.post("/api/auth/signup", json={
        "fullName": "Real Person", "email": "real.person@gmail.com", "phoneNumber": "+919876543210",
    })
    assert r.status_code == 503
    assert "can't send emails yet" in r.json()["message"] and ".env" not in r.json()["message"]
    # nothing half-created: no pending account, no code to verify
    r2 = await client.post("/api/auth/otp/verify", json={"email": "real.person@gmail.com", "otp": "123456"})
    assert r2.status_code == 400 and "No verification code" in r2.json()["message"]


async def test_code_email_design_and_subjects(monkeypatch):
    """Code emails: "[SecureNet] <purpose> verification code", one box per digit, selectable code, 5 minutes."""
    sent = []

    async def fake_send(recipients, subject, text, html, attachments=None, reply_to=None):
        sent.append((recipients, subject, text, html))

    monkeypatch.setattr(email_mod, "send_email", fake_send)
    await email_mod.send_login_code_email("a@example.com", "137296")
    await email_mod.send_otp_email("a@example.com", "000111")
    await email_mod.send_password_reset_email("a@example.com", "222333")
    await email_mod.send_password_change_email("a@example.com", "444555")
    await email_mod.send_profile_change_email("a@example.com", "666777", "name")
    subjects = [s for _, s, _, _ in sent]
    assert subjects == [
        "[SecureNet] Sign-in verification code", "[SecureNet] Sign-up verification code",
        "[SecureNet] Password reset verification code", "[SecureNet] Password change verification code",
        "[SecureNet] Profile change verification code",
    ]
    _, _, text, html = sent[0]
    assert "verification code is: 137296" in text and "5 minutes" in text
    assert "Code requested" in html and "5 minutes" in html
    assert "<a " not in html and "/code#" not in text          # no links: nothing to open, just the code
    assert "Your code" not in html and "Double-click" not in html   # only the digit boxes
    for digit in "137296":
        assert f'color:#1f2328">{digit}</div>' in html          # one box per digit
    assert html.count("137296") == 1                           # only in the hidden inbox preview line
