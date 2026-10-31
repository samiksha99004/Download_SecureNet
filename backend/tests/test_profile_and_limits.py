"""Users change their own details (each change confirmed by an emailed code) and
per-network-address limits (issue #7)."""

from tests.conftest import register


async def signed_in(client, captured_otps, email, name="Asha Rao", phone="+919876543210", password="GoodPass1"):
    auth = await register(client, captured_otps, email=email, name=name, phone=phone, password=password)
    return {"Authorization": f"Bearer {auth['tokens']['accessToken']}"}


# ── Profile changes ──────────────────────────────────────────────────────────

async def test_change_name_and_phone_needs_the_emailed_code(client, captured_otps):
    headers = await signed_in(client, captured_otps, "asha@example.com")
    captured_otps.clear()
    r = await client.post("/api/auth/profile/change", headers=headers,
                          json={"fullName": "Asha R. Rao", "phoneNumber": "+91 90000 22222"})
    assert r.status_code == 200, r.text
    started = r.json()
    assert started["sentTo"] == "as**@example.com" and "6-digit code" in started["message"]
    assert "asha@example.com" in captured_otps                         # code went to the current email

    # nothing changes before the code is entered
    me = (await client.get("/api/auth/me", headers=headers)).json()
    assert me["fullName"] == "Asha Rao" and me["phoneNumber"] == "+919876543210"

    code = captured_otps["asha@example.com"]
    wrong = "000000" if code != "000000" else "111111"
    r = await client.post("/api/auth/profile/confirm", headers=headers,
                          json={"changeToken": started["changeToken"], "otp": wrong})
    assert r.status_code == 400 and "attempt(s) remaining" in r.json()["message"]

    r = await client.post("/api/auth/profile/confirm", headers=headers,
                          json={"changeToken": started["changeToken"], "otp": code})
    assert r.status_code == 200, r.text
    assert r.json()["fullName"] == "Asha R. Rao" and r.json()["phoneNumber"] == "+919000022222"

    # the same code / token cannot be used again
    r = await client.post("/api/auth/profile/confirm", headers=headers,
                          json={"changeToken": started["changeToken"], "otp": code})
    assert r.status_code == 400


async def test_change_email_sends_code_to_new_address_and_notifies_old(client, captured_otps, monkeypatch):
    notices = []

    async def fake_send(recipients, subject, text, html, attachments=None, reply_to=None):
        notices.append((list(recipients), subject))

    monkeypatch.setattr("app.api.routes.auth.send_email", fake_send)
    headers = await signed_in(client, captured_otps, "old.mail@example.com", password="GoodPass1")
    captured_otps.clear()
    r = await client.post("/api/auth/profile/change", headers=headers, json={"email": "New.Mail@Example.com"})
    assert r.status_code == 200
    assert list(captured_otps) == ["new.mail@example.com"]           # proves the new address is theirs
    r = await client.post("/api/auth/profile/confirm", headers=headers, json={
        "changeToken": r.json()["changeToken"], "otp": captured_otps["new.mail@example.com"]})
    assert r.status_code == 200 and r.json()["email"] == "new.mail@example.com"
    assert notices == [(["old.mail@example.com"], "SecureNet - Your email address was changed")]
    # sign in with the new email from now on
    assert (await client.post("/api/auth/login", json={"email": "old.mail@example.com", "password": "GoodPass1"})).status_code == 401
    assert (await client.post("/api/auth/login", json={"email": "new.mail@example.com", "password": "GoodPass1"})).status_code == 200


async def test_profile_change_rules(client, captured_otps):
    headers = await signed_in(client, captured_otps, "first@example.com")
    await register(client, captured_otps, email="taken@example.com")

    r = await client.post("/api/auth/profile/change", headers=headers, json={"fullName": "Asha Rao"})
    assert r.status_code == 400 and "Nothing to change" in r.json()["message"]
    r = await client.post("/api/auth/profile/change", headers=headers, json={"email": "taken@example.com"})
    assert r.status_code == 400 and "already used" in r.json()["message"]
    r = await client.post("/api/auth/profile/change", headers=headers, json={"phoneNumber": "12ab"})
    assert r.status_code == 422
    r = await client.post("/api/auth/profile/change", headers=headers, json={"fullName": "A"})
    assert r.status_code == 422
    assert (await client.post("/api/auth/profile/change", json={"fullName": "Someone"})).status_code == 401


async def test_change_token_belongs_to_one_user(client, captured_otps):
    alice = await signed_in(client, captured_otps, "alice@example.com")
    bob = await signed_in(client, captured_otps, "bob@example.com", name="Bob Kumar")
    r = await client.post("/api/auth/profile/change", headers=alice, json={"fullName": "Alice New"})
    token = r.json()["changeToken"]
    r = await client.post("/api/auth/profile/confirm", headers=bob,
                          json={"changeToken": token, "otp": captured_otps["alice@example.com"]})
    assert r.status_code == 400 and "expired" in r.json()["message"]


# ── Issue #7: limits per network address ────────────────────────────────────

async def test_failed_sign_ins_are_limited_per_network_address(client, captured_otps):
    await register(client, captured_otps, email="victim@example.com", password="GoodPass1")
    # 20 wrong passwords spread over many accounts (each account alone stays under its own lockout)
    for i in range(20):
        r = await client.post("/api/auth/login", json={"email": f"guess{i % 4}@example.com", "password": "Wrong1234"})
        assert r.status_code == 401
    r = await client.post("/api/auth/login", json={"email": "victim@example.com", "password": "GoodPass1"})
    assert r.status_code == 429 and "from this network" in r.json()["message"]


async def test_code_emails_are_limited_per_network_address(client, captured_otps):
    for i in range(15):
        r = await client.post("/api/auth/signup", json={"fullName": "Spam Bot", "email": f"s{i}@example.com",
                                                        "phoneNumber": "9876543210"})
        assert r.status_code == 200, (i, r.text)
    r = await client.post("/api/auth/signup", json={"fullName": "Spam Bot", "email": "s99@example.com",
                                                    "phoneNumber": "9876543210"})
    assert r.status_code == 429 and "verification emails" in r.json()["message"]


async def test_wrong_codes_are_limited_per_network_address(client, captured_otps, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.OTP_MAX_ATTEMPTS", 1000)   # isolate the network limit
    await client.post("/api/auth/signup", json={"fullName": "Guess Er", "email": "g@example.com", "phoneNumber": "9876543210"})
    right = captured_otps["g@example.com"]
    wrong = "000000" if right != "000000" else "111111"
    for _ in range(30):
        assert (await client.post("/api/auth/otp/verify", json={"email": "g@example.com", "otp": wrong})).status_code == 400
    r = await client.post("/api/auth/otp/verify", json={"email": "g@example.com", "otp": right})
    assert r.status_code == 429 and "wrong codes" in r.json()["message"]
