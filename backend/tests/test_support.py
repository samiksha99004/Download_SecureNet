"""Support page "Contact us": admin edits, every user reads, admin email as fallback."""

from tests.conftest import register


async def test_contact_details(client, admin, captured_otps, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.ADMIN_EMAILS", "boss@example.com")
    _, admin_headers = admin
    user = await register(client, captured_otps, email="user@example.com")
    user_headers = {"Authorization": f"Bearer {user['tokens']['accessToken']}"}

    # nothing set yet: only the admin email is shown
    r = await client.get("/api/support/contact", headers=user_headers)
    assert r.status_code == 200
    assert r.json() == {"website": None, "phone": None, "email": "boss@example.com", "address": None}

    r = await client.put("/api/settings/system", headers=admin_headers, json={
        "contactWebsite": "www.securenet.example.org", "contactPhone": "+91 824 123 4567",
        "contactEmail": "help@example.org", "contactAddress": "Admin office, Block A"})
    assert r.status_code == 200, r.text
    assert r.json()["contactWebsite"] == "https://www.securenet.example.org"

    r = await client.get("/api/support/contact", headers=user_headers)
    assert r.json() == {"website": "https://www.securenet.example.org", "phone": "+91 824 123 4567",
                        "email": "help@example.org", "address": "Admin office, Block A"}

    # public: the sign-in page reads the website before anyone is signed in
    assert (await client.get("/api/support/contact")).json()["website"] == "https://www.securenet.example.org"

    # clearing a field removes it
    await client.put("/api/settings/system", headers=admin_headers, json={"contactPhone": ""})
    assert (await client.get("/api/support/contact", headers=user_headers)).json()["phone"] is None

    # validation + only the admin may edit
    bad = await client.put("/api/settings/system", headers=admin_headers, json={"contactPhone": "call me"})
    assert bad.status_code == 422
    denied = await client.put("/api/settings/system", headers=user_headers, json={"contactPhone": "12345678"})
    assert denied.status_code == 403


async def test_send_us_a_message(client, admin, captured_otps, monkeypatch):
    import app.api.routes.support as support
    from app.utils.email import EmailDeliveryError
    from app.utils.ratelimit import limiter
    from sqlalchemy import func, select
    from app.db.base import AsyncSessionLocal
    from app.models.support import SupportMessage

    monkeypatch.setattr("app.core.config.settings.ADMIN_EMAILS", "boss@example.com")
    sent = []

    async def fake_send(recipients, subject, text, html, attachments=None, reply_to=None):
        sent.append({"to": list(recipients), "subject": subject, "text": text, "html": html, "reply_to": reply_to})

    monkeypatch.setattr(support, "send_email", fake_send)
    user = await register(client, captured_otps, email="asha@example.com", name="Asha Rao", phone="+919876543210")
    headers = {"Authorization": f"Bearer {user['tokens']['accessToken']}"}

    # sign-in required, and the text is validated
    assert (await client.post("/api/support/message", json={"subject": "Hi", "message": "x" * 20})).status_code == 401
    r = await client.post("/api/support/message", headers=headers, json={"subject": "Hi", "message": "short"})
    assert r.status_code == 422

    r = await client.post("/api/support/message", headers=headers, json={
        "subject": "Strange alert\nat night", "message": "I got an alert at 2 AM <script>x</script>, is this normal?"})
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "Your message has been sent. We will reply to you by email."   # no address shown

    to_admin, copy = sent
    assert to_admin["to"] == ["boss@example.com"] and to_admin["reply_to"] == "asha@example.com"
    assert to_admin["subject"] == "[SecureNet Support] Strange alert at night"
    assert "Asha Rao <asha@example.com>" in to_admin["text"] and "+919876543210" in to_admin["text"]
    assert "<script>" not in to_admin["html"] and "&lt;script&gt;" in to_admin["html"]
    assert copy["to"] == ["asha@example.com"] and copy["reply_to"] == "boss@example.com"

    # the message is stored
    async with AsyncSessionLocal() as db:
        stored = (await db.execute(select(SupportMessage))).scalars().all()
    assert [(m.sender_email, m.recipient, m.subject) for m in stored] == [
        ("asha@example.com", "boss@example.com", "Strange alert at night")]

    # one message per minute — and the limit survives a restart (limits come from the database)
    limiter.reset()
    r = await client.post("/api/support/message", headers=headers, json={"subject": "Again", "message": "Another message here"})
    assert r.status_code == 429 and "Please wait" in r.json()["message"]

    # delivery failure -> plain message, nothing stored or counted (fresh user)
    other = await register(client, captured_otps, email="ravi@example.com", name="Ravi K")
    other_headers = {"Authorization": f"Bearer {other['tokens']['accessToken']}"}

    async def failing_send(*args, **kwargs):
        raise EmailDeliveryError("smtp down")

    monkeypatch.setattr(support, "send_email", failing_send)
    r = await client.post("/api/support/message", headers=other_headers, json={"subject": "Help", "message": "Please call me back"})
    assert r.status_code == 503 and "smtp" not in r.json()["message"].lower()
    async with AsyncSessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(SupportMessage)
                                  .where(SupportMessage.sender_email == "ravi@example.com"))).scalar()
    assert count == 0
