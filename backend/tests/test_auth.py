"""Authentication flow tests (details → emailed OTP → password → login → refresh)."""

from tests.conftest import register


async def test_first_user_is_admin_and_camelcase(client, captured_otps):
    auth = await register(client, captured_otps)
    user = auth["user"]
    assert user["role"] == "admin"
    assert user["fullName"] == "Admin"
    assert user["accountStatus"] == "active"
    assert user["createdAt"].endswith("Z")
    assert set(auth["tokens"]) == {"accessToken", "refreshToken", "expiresIn"}


async def test_second_user_is_viewer(client, captured_otps):
    await register(client, captured_otps)
    auth = await register(client, captured_otps, email="viewer@example.com", name="Viewer")
    assert auth["user"]["role"] == "viewer"


async def test_otp_resend_then_verify(client, captured_otps, monkeypatch):
    """Regression: a resend used to leave two OTP rows → HTTP 500 on verify."""
    email = "resend@example.com"
    r = await client.post("/api/auth/signup", json={"fullName": "Re Send", "email": email, "phoneNumber": "9876543210"})
    assert r.status_code == 200
    first = captured_otps[email]

    monkeypatch.setattr("app.core.config.settings.OTP_RESEND_COOLDOWN_SECONDS", 0)
    r = await client.post("/api/auth/otp/resend", json={"email": email})
    assert r.status_code == 200, r.text
    second = captured_otps[email]

    if first != second:
        r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": first})
        assert r.status_code == 400  # old code was invalidated
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": second})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == email and r.json()["setupToken"]


async def test_resend_unknown_email_is_generic(client):
    r = await client.post("/api/auth/otp/resend", json={"email": "nobody@example.com"})
    assert r.status_code == 200


async def test_login_errors_use_uniform_shape(client):
    r = await client.post("/api/auth/login", json={"email": "x@example.com", "password": "nope"})
    assert r.status_code == 401
    body = r.json()
    assert body == {"status": 401, "code": "UNAUTHORIZED", "message": "Invalid email or password"}


async def test_unknown_email_still_checks_a_password(client, admin, monkeypatch):
    """A wrong email does the same password work as a wrong password (no timing hint)."""
    from app.api.routes import auth as auth_routes

    checked = []
    real = auth_routes.verify_password
    monkeypatch.setattr(auth_routes, "verify_password", lambda pw, h: checked.append(h) or real(pw, h))
    for email in ("nobody@example.com", "admin@example.com"):
        r = await client.post("/api/auth/login", json={"email": email, "password": "Wrong1234"})
        assert r.status_code == 401
    assert len(checked) == 2 and all(h.startswith("$pbkdf2-sha256$") for h in checked)


async def test_validation_error_message(client):
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": "x" * 20, "password": "Passw0rd!", "confirmPassword": "different1"})
    assert r.status_code == 422
    assert "Passwords do not match" in r.json()["message"]


async def test_signup_rejects_bad_phone(client, captured_otps):
    r = await client.post("/api/auth/signup", json={"fullName": "Pho Ne", "email": "p@example.com", "phoneNumber": "12ab"})
    assert r.status_code == 422
    assert "phone number" in r.json()["message"]


async def test_full_registration_flow(client, captured_otps):
    """Details -> code -> password -> signed in; afterwards email + password works."""
    email = "new.user@example.com"
    r = await client.post("/api/auth/signup", json={
        "fullName": "  New User ", "email": email, "phoneNumber": "+91 98765-43210"})
    assert r.status_code == 200, r.text
    assert email in r.json()["message"]

    # Not usable before the password is set
    r = await client.post("/api/auth/login", json={"email": email, "password": "Passw0rd!"})
    assert r.status_code == 401

    wrong = "000000" if captured_otps[email] != "000000" else "111111"
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": wrong})
    assert r.status_code == 400 and "attempt(s) remaining" in r.json()["message"]

    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": captured_otps[email]})
    assert r.status_code == 200, r.text
    token = r.json()["setupToken"]

    # The setup token is not an access token
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})).status_code == 401

    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": token, "password": "short", "confirmPassword": "short"})
    assert r.status_code == 422
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": token, "password": "NewPassw0rd", "confirmPassword": "NewPassw0rd"})
    assert r.status_code == 200, r.text
    user = r.json()["user"]
    assert user["fullName"] == "New User" and user["phoneNumber"] == "+919876543210"
    assert user["accountStatus"] == "active" and user["role"] == "admin"  # first account

    # Token cannot be reused; the email cannot register again
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": token, "password": "Other0000", "confirmPassword": "Other0000"})
    assert r.status_code == 400
    r = await client.post("/api/auth/signup", json={"fullName": "Again", "email": email, "phoneNumber": "9876543210"})
    assert r.status_code == 400 and "already registered" in r.json()["message"]

    # Next time: email + password
    r = await client.post("/api/auth/login", json={"email": email, "password": "NewPassw0rd"})
    assert r.status_code == 200, r.text


async def test_access_token_cannot_complete_signup(client, admin, captured_otps):
    auth, _ = admin
    await client.post("/api/auth/signup", json={"fullName": "Pending", "email": "pend@example.com", "phoneNumber": "9876543210"})
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": auth["tokens"]["accessToken"], "password": "Passw0rd1", "confirmPassword": "Passw0rd1"})
    assert r.status_code == 400


async def test_login_lockout(client, captured_otps):
    await register(client, captured_otps, email="lock@example.com")
    for _ in range(5):
        r = await client.post("/api/auth/login", json={"email": "lock@example.com", "password": "wrong-pass1"})
        assert r.status_code == 401
    r = await client.post("/api/auth/login", json={"email": "lock@example.com", "password": "Passw0rd!"})
    assert r.status_code == 429


async def test_refresh_token_flow(client, admin):
    auth, headers = admin
    refresh = auth["tokens"]["refreshToken"]

    # A refresh token must NOT work as an access token
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401

    r = await client.post("/api/auth/refresh", json={"refreshToken": refresh})
    assert r.status_code == 200, r.text
    new_access = r.json()["tokens"]["accessToken"]
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_access}"})
    assert r.status_code == 200
    assert r.json()["email"] == "admin@example.com"


async def test_change_password_wrong_current_is_400(client, admin):
    _, headers = admin
    r = await client.post("/api/auth/change-password", headers=headers, json={
        "currentPassword": "bad", "newPassword": "NewPassw0rd", "confirmNewPassword": "NewPassw0rd"})
    assert r.status_code == 400  # not 401 (which would log the user out)


async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["ml"] == "not_loaded"
