"""QA pass: every authentication path — right / wrong / late / reused OTP, login,
lockout, tokens, password change and reset. (SQLite test DB, codes captured.)"""

from datetime import timedelta

from sqlalchemy import select, update

from app.core.security import create_access_token, create_signup_token, create_reset_token
from app.core.config import settings
from app.db.base import AsyncSessionLocal
from app.models.otp import OTP
from app.models.user import User
from app.utils.timeutil import utcnow
from tests.conftest import register

PHONE = "9876543210"


async def start_signup(client, email, name="Qa User"):
    r = await client.post("/api/auth/signup", json={"fullName": name, "email": email, "phoneNumber": PHONE})
    assert r.status_code == 200, r.text


async def age_latest_otp(email, minutes):
    """Pretend the latest code for `email` was issued `minutes` ago."""
    async with AsyncSessionLocal() as db:
        otp = (await db.execute(select(OTP).where(OTP.email == email).order_by(OTP.created_at.desc()))).scalars().first()
        otp.created_at = utcnow() - timedelta(minutes=minutes)
        otp.expires_at = otp.created_at + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
        await db.commit()


# ── OTP: right / wrong / late / reused ───────────────────────────────────────

async def test_right_otp_works(client, captured_otps):
    await start_signup(client, "right@example.com")
    r = await client.post("/api/auth/otp/verify", json={"email": "right@example.com", "otp": captured_otps["right@example.com"]})
    assert r.status_code == 200 and r.json()["verified"] is True and r.json()["setupToken"]


async def test_wrong_otp_counts_down_then_locks_the_code(client, captured_otps):
    email = "wrong@example.com"
    await start_signup(client, email)
    right = captured_otps[email]
    wrong = "000000" if right != "000000" else "111111"
    messages = []
    for _ in range(5):
        r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": wrong})
        assert r.status_code == 400
        messages.append(r.json()["message"])
    assert messages[0] == "Invalid code. 4 attempt(s) remaining."
    assert messages[-1] == "Maximum attempts exceeded. Please request a new code."
    # after 5 wrong tries even the right code no longer works
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": right})
    assert r.status_code == 400 and "request a new one" in r.json()["message"].lower()


async def test_late_otp_is_rejected(client, captured_otps):
    email = "late@example.com"
    await start_signup(client, email)
    await age_latest_otp(email, 6)                        # issued 6 min ago, valid for 5
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": captured_otps[email]})
    assert r.status_code == 400 and "expired" in r.json()["message"]


async def test_otp_just_before_expiry_still_works(client, captured_otps):
    email = "ontime@example.com"
    await start_signup(client, email)
    await age_latest_otp(email, 4)                        # 4 of 5 minutes used
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": captured_otps[email]})
    assert r.status_code == 200


async def test_codes_expire_after_five_minutes(client, captured_otps):
    assert settings.OTP_EXPIRE_MINUTES == 5
    email = "five@example.com"
    await start_signup(client, email)
    async with AsyncSessionLocal() as db:
        otp = (await db.execute(select(OTP).where(OTP.email == email))).scalars().first()
    assert abs((otp.expires_at - otp.created_at).total_seconds() - 300) < 5


async def test_otp_cannot_be_used_twice(client, captured_otps):
    email = "twice@example.com"
    await start_signup(client, email)
    code = captured_otps[email]
    assert (await client.post("/api/auth/otp/verify", json={"email": email, "otp": code})).status_code == 200
    r = await client.post("/api/auth/otp/verify", json={"email": email, "otp": code})
    assert r.status_code == 400


async def test_otp_format_is_validated(client, captured_otps):
    await start_signup(client, "format@example.com")
    for bad in ("12345", "1234567", "abcdef", "12 456"):
        r = await client.post("/api/auth/otp/verify", json={"email": "format@example.com", "otp": bad})
        assert r.status_code == 422, bad


async def test_resend_is_rate_limited_and_replaces_the_code(client, captured_otps, monkeypatch):
    email = "resend2@example.com"
    await start_signup(client, email)
    first = captured_otps[email]
    r = await client.post("/api/auth/otp/resend", json={"email": email})
    assert r.status_code == 429                           # within 60 s
    monkeypatch.setattr("app.core.config.settings.OTP_RESEND_COOLDOWN_SECONDS", 0)
    assert (await client.post("/api/auth/otp/resend", json={"email": email})).status_code == 200
    second = captured_otps[email]
    if first != second:
        assert (await client.post("/api/auth/otp/verify", json={"email": email, "otp": first})).status_code == 400
    assert (await client.post("/api/auth/otp/verify", json={"email": email, "otp": second})).status_code == 200


async def test_late_setup_token_is_rejected(client, captured_otps):
    email = "slow@example.com"
    await start_signup(client, email)
    from app.core.security import _encode, SIGNUP_TOKEN_TYPE
    expired = _encode({"sub": email}, SIGNUP_TOKEN_TYPE, timedelta(minutes=-1))
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": expired, "password": "Passw0rd99", "confirmPassword": "Passw0rd99"})
    assert r.status_code == 400 and "expired" in r.json()["message"]


async def test_signup_token_for_other_email_cannot_take_over_an_account(client, admin):
    auth, _ = admin
    token = create_signup_token(auth["user"]["email"])     # account already active
    r = await client.post("/api/auth/signup/complete", json={
        "setupToken": token, "password": "Hijack123", "confirmPassword": "Hijack123"})
    assert r.status_code == 400


# ── Login ────────────────────────────────────────────────────────────────────

async def test_login_right_wrong_and_unknown(client, captured_otps):
    await register(client, captured_otps, email="login@example.com", password="GoodPass1")
    ok = await client.post("/api/auth/login", json={"email": "LOGIN@example.com ", "password": "GoodPass1"})
    assert ok.status_code == 200                          # email is case/space-insensitive
    bad = await client.post("/api/auth/login", json={"email": "login@example.com", "password": "WrongPass1"})
    unknown = await client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "WrongPass1"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json()["message"] == unknown.json()["message"] == "Invalid email or password"   # no user enumeration


async def test_unfinished_registration_cannot_log_in(client, captured_otps):
    await start_signup(client, "halfway@example.com")
    r = await client.post("/api/auth/login", json={"email": "halfway@example.com", "password": "Anything1"})
    assert r.status_code == 401


async def test_lockout_and_unlock(client, captured_otps):
    await register(client, captured_otps, email="lock2@example.com", password="GoodPass1")
    for _ in range(5):
        await client.post("/api/auth/login", json={"email": "lock2@example.com", "password": "nope-nope1"})
    r = await client.post("/api/auth/login", json={"email": "lock2@example.com", "password": "GoodPass1"})
    assert r.status_code == 429 and "Try again in" in r.json()["message"]
    async with AsyncSessionLocal() as db:                  # 15 minutes later
        await db.execute(update(User).where(User.email == "lock2@example.com").values(locked_until=utcnow() - timedelta(seconds=1)))
        await db.commit()
    assert (await client.post("/api/auth/login", json={"email": "lock2@example.com", "password": "GoodPass1"})).status_code == 200


# ── Tokens ───────────────────────────────────────────────────────────────────

async def test_expired_tampered_and_foreign_tokens_are_rejected(client, admin):
    auth, headers = admin
    user_id = auth["user"]["id"]
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 200

    expired = create_access_token({"sub": user_id}, expires_delta=timedelta(seconds=-5))
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})).status_code == 401

    token = auth["tokens"]["accessToken"]
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered}"})).status_code == 401

    from jose import jwt
    foreign = jwt.encode({"sub": user_id, "type": "access"}, "some-other-secret-0123456789abcdef", algorithm="HS256")
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {foreign}"})).status_code == 401

    reset = create_reset_token(auth["user"]["email"], None)
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {reset}"})).status_code == 401
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_token_of_deleted_user_stops_working(client, captured_otps):
    auth = await register(client, captured_otps, email="gone@example.com")
    headers = {"Authorization": f"Bearer {auth['tokens']['accessToken']}"}
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == "gone@example.com"))).scalar_one()
        await db.delete(user)
        await db.commit()
    # refreshing the session checks the database at once
    r = await client.post("/api/auth/refresh", json={"refreshToken": auth["tokens"]["refreshToken"]})
    assert r.status_code == 401
    # an access token keeps working only until the remembered copy expires (USER_CACHE_SECONDS)
    from app.api.dependencies import USER_CACHE_SECONDS, clear_user_cache
    assert USER_CACHE_SECONDS <= 60
    clear_user_cache()                                   # = those seconds have passed
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 401


# ── Password change / reset ─────────────────────────────────────────────────

async def test_change_password(client, captured_otps):
    auth = await register(client, captured_otps, email="change@example.com", password="OldPass11")
    headers = {"Authorization": f"Bearer {auth['tokens']['accessToken']}"}
    r = await client.post("/api/auth/change-password", headers=headers, json={
        "currentPassword": "WrongOld1", "newPassword": "NewPass22", "confirmNewPassword": "NewPass22"})
    assert r.status_code == 400
    await age_latest_otp("change@example.com", 2)  # sign-up code no longer blocks a new code
    r = await client.post("/api/auth/change-password", headers=headers, json={
        "currentPassword": "OldPass11", "newPassword": "OldPass11", "confirmNewPassword": "OldPass11"})
    assert r.status_code == 400 and "differ" in r.json()["message"]
    r = await client.post("/api/auth/change-password", headers=headers, json={
        "currentPassword": "OldPass11", "newPassword": "NewPass22", "confirmNewPassword": "NewPass22"})
    assert r.status_code == 200, r.text
    started = r.json()
    assert started["sentTo"].startswith("ch") and "*" in started["sentTo"]
    token, code = started["changeToken"], captured_otps["change@example.com"]

    # nothing changed yet: the emailed code is the second factor
    assert (await client.post("/api/auth/login", json={"email": "change@example.com", "password": "OldPass11"})).status_code == 200
    confirm = "/api/auth/change-password/confirm"
    wrong = "000000" if code != "000000" else "111111"
    r = await client.post(confirm, headers=headers, json={"changeToken": token, "otp": wrong, "newPassword": "NewPass22"})
    assert r.status_code == 400 and "attempt" in r.json()["message"]
    # the token is bound to the new password chosen in step 1
    r = await client.post(confirm, headers=headers, json={"changeToken": token, "otp": code, "newPassword": "Other333"})
    assert r.status_code == 400 and "expired" in r.json()["message"]
    # another user can't use it
    other = await register(client, captured_otps, email="other@example.com")
    r = await client.post(confirm, headers={"Authorization": f"Bearer {other['tokens']['accessToken']}"},
                          json={"changeToken": token, "otp": code, "newPassword": "NewPass22"})
    assert r.status_code == 400
    # and a profile/reset token is not a password-change token
    r = await client.post(confirm, headers=headers, json={"changeToken": auth["tokens"]["accessToken"], "otp": code,
                                                          "newPassword": "NewPass22"})
    assert r.status_code == 400

    r = await client.post(confirm, headers=headers, json={"changeToken": token, "otp": code, "newPassword": "NewPass22"})
    assert r.status_code == 200, r.text
    assert (await client.post("/api/auth/login", json={"email": "change@example.com", "password": "OldPass11"})).status_code == 401
    assert (await client.post("/api/auth/login", json={"email": "change@example.com", "password": "NewPass22"})).status_code == 200
    # single use: the token died with the old password, the code was consumed
    r = await client.post(confirm, headers=headers, json={"changeToken": token, "otp": code, "newPassword": "NewPass22"})
    assert r.status_code == 400


async def test_late_reset_code_is_rejected(client, captured_otps):
    email = "latereset@example.com"
    await register(client, captured_otps, email=email)
    await age_latest_otp(email, 0)  # make sure the sign-up code is not outstanding
    async with AsyncSessionLocal() as db:
        await db.execute(update(OTP).where(OTP.email == email).values(is_used=True))
        await db.commit()
    assert (await client.post("/api/auth/password/forgot", json={"email": email})).status_code == 200
    await age_latest_otp(email, 6)
    r = await client.post("/api/auth/password/verify", json={"email": email, "otp": captured_otps[email]})
    assert r.status_code == 400 and "expired" in r.json()["message"]


# ── Input hardening ─────────────────────────────────────────────────────────

async def test_hostile_query_inputs_are_harmless(client, admin):
    _, headers = admin
    for search in ("' OR 1=1 --", "%", "_", "\\", "<script>alert(1)</script>", "x" * 500):
        r = await client.get("/api/events", params={"search": search}, headers=headers)
        assert r.status_code in (200, 422), (search, r.status_code)
        if r.status_code == 200:
            assert r.json()["total"] == 0
    r = await client.get("/api/events", params={"pageSize": 100000}, headers=headers)
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        assert r.json()["pageSize"] <= 200
    r = await client.get("/api/events", params={"sortBy": "password_hash; DROP TABLE users"}, headers=headers)
    assert r.status_code == 400                           # unknown sort field refused, nothing executed
    assert (await client.get("/api/events", headers=headers)).status_code == 200
