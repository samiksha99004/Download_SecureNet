"""Forgot password (email -> code -> new password) and admin-by-email roles."""

from tests.conftest import register


async def test_forgot_password_flow(client, captured_otps, monkeypatch):
    email = "reset.me@example.com"
    await register(client, captured_otps, email=email, password="OldPassw0rd")
    captured_otps.pop(email)

    r = await client.post("/api/auth/password/forgot", json={"email": email})
    assert r.status_code == 200 and "code has been sent" in r.json()["message"]
    code = captured_otps[email]

    wrong = "000000" if code != "000000" else "111111"
    r = await client.post("/api/auth/password/verify", json={"email": email, "otp": wrong})
    assert r.status_code == 400 and "attempt(s) remaining" in r.json()["message"]

    r = await client.post("/api/auth/password/verify", json={"email": email, "otp": code})
    assert r.status_code == 200, r.text
    token = r.json()["resetToken"]
    # a reset token is never an access token
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})).status_code == 401

    r = await client.post("/api/auth/password/reset", json={
        "resetToken": token, "password": "NewPassw0rd", "confirmPassword": "NewPassw0rd"})
    assert r.status_code == 200, r.text

    # single use: the same token no longer works once the password changed
    r = await client.post("/api/auth/password/reset", json={
        "resetToken": token, "password": "Another0ne1", "confirmPassword": "Another0ne1"})
    assert r.status_code == 400 and "expired or was already used" in r.json()["message"]

    assert (await client.post("/api/auth/login", json={"email": email, "password": "OldPassw0rd"})).status_code == 401
    assert (await client.post("/api/auth/login", json={"email": email, "password": "NewPassw0rd"})).status_code == 200


async def test_forgot_password_unknown_email_is_generic_and_sends_nothing(client, captured_otps):
    r = await client.post("/api/auth/password/forgot", json={"email": "nobody@example.com"})
    assert r.status_code == 200 and "If an account exists" in r.json()["message"]
    assert "nobody@example.com" not in captured_otps
    r = await client.post("/api/auth/password/verify", json={"email": "nobody@example.com", "otp": "123456"})
    assert r.status_code == 400


async def test_signup_code_cannot_reset_password_of_pending_account(client, captured_otps):
    await client.post("/api/auth/signup", json={"fullName": "Pen Ding", "email": "pending@example.com",
                                                "phoneNumber": "9876543210"})
    r = await client.post("/api/auth/password/verify",
                          json={"email": "pending@example.com", "otp": captured_otps["pending@example.com"]})
    assert r.status_code == 400


async def test_forgot_password_resend_cooldown(client, captured_otps):
    await register(client, captured_otps, email="cool@example.com")
    assert (await client.post("/api/auth/password/forgot", json={"email": "cool@example.com"})).status_code == 200
    r = await client.post("/api/auth/password/forgot", json={"email": "cool@example.com"})
    assert r.status_code == 429


async def test_admin_emails_decide_roles(client, captured_otps, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.ADMIN_EMAILS", " Boss@Example.com ")
    first = await register(client, captured_otps, email="first.user@example.com")
    assert first["user"]["role"] == "viewer"          # first account is NOT admin any more
    boss = await register(client, captured_otps, email="boss@example.com")
    assert boss["user"]["role"] == "admin"            # listed email (case/space-insensitive) is admin
