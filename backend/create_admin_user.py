"""
Create (or promote) an admin account.

Usage (from the backend folder, with the venv active):
    python create_admin_user.py you@example.com "Your Name"
    python create_admin_user.py existing@example.com          # promote existing user

The password is prompted for (never hard-coded). Existing users keep their
password and are promoted to admin + activated.
"""

import asyncio
import getpass
import sys

from sqlalchemy import func, select

from app.core.security import hash_password, validate_password_strength
from app.db.base import AsyncSessionLocal
from app.models.user import AccountStatus, AuthProvider, User, UserRole


async def main(email: str, full_name: str) -> None:
    email = email.strip().lower()
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
        if user:
            user.role = UserRole.ADMIN
            user.account_status = AccountStatus.ACTIVE
            await db.commit()
            print(f"Promoted existing user {email} to admin.")
            return

        password = getpass.getpass("New admin password: ")
        ok, error = validate_password_strength(password)
        if not ok:
            sys.exit(f"Password rejected: {error}")
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match.")

        db.add(User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            account_status=AccountStatus.ACTIVE,
            auth_provider=AuthProvider.LOCAL,
        ))
        await db.commit()
        print(f"Created admin user {email}.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "Administrator"))
