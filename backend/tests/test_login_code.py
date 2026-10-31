"""Two-step sign-in: email + password, then a 6-digit code emailed to the account (valid 5 minutes)."""

from datetime import timedelta

from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.models.otp import OTP
from app.utils.email import EmailDeliveryError
from app.utils.timeutil import utcnow
from tests.conftest import login, register

EMAIL, PW = "two.step@example.com", "GoodPass1"


async def _age_codes(email, minutes):
    async with AsyncSessionLocal() as db:
        for otp in (await db.execute(select(OTP).where(OTP.email == email))).scalars():
            otp.created_at -= timedelta(minutes=minutes)
            otp.expires_at -= timedelta(minutes=minutes)
        await db.commit()


async def _password_step(client, email=EMAIL, password=PW):
    return await client.post("/api/auth/login", json={"email": email, "password": password})


async def test_password_alone_does_not_sign_in(client, captured_otps):
    await register(client, captured_otps, email=EMAIL, password=PW)
    await _age_codes(EMAIL, 2)                       # sign-up code is old news
    r = await _password_step(client)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"loginToken", "sentTo", "message"}      # no session tokens yet
    assert body["sentTo"] == "tw******@example.com"
    # the sign-in token is not a session
    me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['loginToken']}"})
    assert me.status_code == 401

    code = captured_otps[EMAIL]
    wrong = "000000" if code != "000000" else "111111"
    r = await client.post("/api/auth/login/verify", json={"loginToken": body["loginToken"], "otp": wrong})
    assert r.status_code == 400 and "4 attempt(s) remaining" in r.json()["message"]

    r = await client.post("/api/auth/login/verify", json={"loginToken": body["loginToken"], "otp": code})
    assert r.status_code == 200, r.text
    tokens = r.json()["tokens"]
    me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['accessToken']}"})
    assert me.status_code == 200 and me.json()["email"] == EMAIL

    # the code is used up
    r = await client.post("/api/auth/login/verify", json={"loginToken": body["loginToken"], "otp": code})
    assert r.status_code == 400


async def test_wrong_password_sends_no_code(client, captured_otps):
    await register(client, captured_otps, email=EMAIL, password=PW)
    captured_otps.clear()
    r = await _password_step(client, password="WrongPass1")
    assert r.status_code == 401 and EMAIL not in captured_otps


async def test_code_expires_after_five_minutes_and_resend_works(client, captured_otps):
    await register(client, captured_otps, email=EMAIL, password=PW)
    await _age_codes(EMAIL, 2)
    token = (await _password_step(client)).json()["loginToken"]
    old = captured_otps[EMAIL]
    await _age_codes(EMAIL, 6)                       # 6 minutes later
    r = await client.post("/api/auth/login/verify", json={"loginToken": token, "otp": old})
    assert r.status_code == 400 and "expired" in r.json()["message"]

    r = await client.post("/api/auth/login/resend", json={"loginToken": token})
    assert r.status_code == 200 and "tw******@example.com" in r.json()["message"]
    new = captured_otps[EMAIL]
    r = await client.post("/api/auth/login/resend", json={"loginToken": token})
    assert r.status_code == 429                      # one new code per minute
    r = await client.post("/api/auth/login/verify", json={"loginToken": token, "otp": new})
    assert r.status_code == 200


async def test_signing_in_again_right_away_reuses_the_code(client, captured_otps):
    await register(client, captured_otps, email=EMAIL, password=PW)
    await _age_codes(EMAIL, 2)
    first = (await _password_step(client)).json()
    code = captured_otps[EMAIL]
    captured_otps.clear()
    second = (await _password_step(client)).json()   # pressed "Sign in" twice / came back
    assert EMAIL not in captured_otps and "just sent" in second["message"]
    r = await client.post("/api/auth/login/verify", json={"loginToken": second["loginToken"], "otp": code})
    assert r.status_code == 200 and first["loginToken"]


async def test_sign_in_token_dies_when_the_password_changes(client, captured_otps):
    await register(client, captured_otps, email=EMAIL, password=PW)
    await _age_codes(EMAIL, 2)
    token = (await _password_step(client)).json()["loginToken"]
    # the owner resets the password meanwhile
    await _age_codes(EMAIL, 2)
    await client.post("/api/auth/password/forgot", json={"email": EMAIL})
    reset = (await client.post("/api/auth/password/verify", json={"email": EMAIL, "otp": captured_otps[EMAIL]})).json()
    await client.post("/api/auth/password/reset", json={"resetToken": reset["resetToken"], "password": "OtherPass2",
                                                        "confirmPassword": "OtherPass2"})
    r = await client.post("/api/auth/login/resend", json={"loginToken": token})
    assert r.status_code == 400 and "expired" in r.json()["message"]
    auth = await login(client, captured_otps, EMAIL, "OtherPass2")
    assert auth["user"]["email"] == EMAIL


async def test_garbage_or_other_tokens_are_refused(client, captured_otps):
    auth = await register(client, captured_otps, email=EMAIL, password=PW)
    for token in ("not-a-real-token", auth["tokens"]["accessToken"], auth["tokens"]["refreshToken"]):
        r = await client.post("/api/auth/login/verify", json={"loginToken": token, "otp": "123456"})
        assert r.status_code in (400, 422)


async def test_no_email_means_no_sign_in(client, captured_otps, monkeypatch):
    await register(client, captured_otps, email=EMAIL, password=PW)
    await _age_codes(EMAIL, 2)

    async def broken(email, code):
        raise EmailDeliveryError("smtp down")

    monkeypatch.setattr("app.api.routes.auth.send_login_code_email", broken)
    r = await _password_step(client)
    assert r.status_code == 503 and "tokens" not in r.json()
    async with AsyncSessionLocal() as db:        # nothing half-issued
        codes = (await db.execute(select(OTP).where(OTP.email == EMAIL, OTP.created_at > utcnow() - timedelta(minutes=1)))).scalars().all()
    assert codes == []
