"""Setup check (run by SETUP.ps1 from backend/): configuration, cloud database, tables, email delivery.

1. connects to the database in backend/.env (clear message when it is still the example value)
2. creates / updates the tables (`alembic upgrade head`) — on a new, empty database this builds
   the whole schema; on an up-to-date one it changes nothing
3. reports the number of accounts and whether emails (sign-in codes, alerts) can be sent
Never prints secrets.
"""

import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.chdir(BACKEND)

from sqlalchemy import text  # noqa: E402

from app.core.config import settings  # noqa: E402  (exits with a readable message if .env is incomplete)
from app.db.base import engine  # noqa: E402
from app.utils.email import email_delivery_status  # noqa: E402

EMAIL_STATUS = {
    "enabled": "configured - confirm with Settings > Email Alerts > Send test email",
    "disabled": "TURNED OFF - set EMAIL_ENABLED=true in backend/.env. Sign-up and sign-in send codes by email, "
                "so nobody can sign in until email works.",
    "misconfigured": "NOT CONFIGURED - put a real Gmail address + App Password (SMTP_USER / SMTP_PASSWORD) in "
                     "backend/.env. Sign-up and sign-in send codes by email.",
}

host = urlsplit(settings.DATABASE_URL).hostname
if "USER:PASSWORD@HOST" in settings.DATABASE_URL:
    sys.exit("Database: DATABASE_URL in backend/.env is still the example value.\n"
             "Create a free PostgreSQL database at https://neon.tech, copy its connection string and put it in "
             "backend/.env as postgresql+asyncpg://...?ssl=require (see README.md, step 3).")


async def check_connection() -> None:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("select 1"))
    except Exception as exc:  # noqa: BLE001 - report any connection problem plainly
        sys.exit(f"Database: cannot connect to {host}: {exc.__class__.__name__}: {exc}\n"
                 "Check the internet connection and DATABASE_URL in backend/.env.")
    finally:
        await engine.dispose()
    print(f"Database: connected to {host}")


async def count_users() -> int:
    try:
        async with engine.connect() as conn:
            return (await conn.execute(text("select count(*) from users"))).scalar() or 0
    finally:
        await engine.dispose()


def upgrade_tables() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    try:
        command.upgrade(cfg, "head")
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Database: creating/updating the tables failed: {exc.__class__.__name__}: {exc}")
    print("Database: tables are up to date")


asyncio.run(check_connection())
upgrade_tables()
users = asyncio.run(count_users())
print(f"Database: {users} registered account(s)" +
      ("" if users else " - the first account you create becomes the admin (or the one in ADMIN_EMAILS)"))
print("Email:", EMAIL_STATUS[email_delivery_status()])
