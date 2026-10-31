"""
SecureNet Backend — API Dependencies

Reusable dependencies for FastAPI endpoints: authentication and role checks.
"""

import asyncio
import time
import uuid
from typing import Dict, Optional, Tuple

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.db.base import AsyncSessionLocal, get_db
from app.models.user import AccountStatus, User, UserRole

# auto_error=False so a missing header yields our own 401 (not a bare 403)
security = HTTPBearer(auto_error=False)


# The signed-in user is remembered for a minute, so most requests need no
# database round trip at all (the cloud database is ~300 ms away). Routes treat
# `current_user` as read-only and re-load the row when they change it; every
# such change calls forget_user(). After a minute the remembered copy is still
# used once while the account is re-checked in the background, so a suspended
# or deleted account stops working within USER_CACHE_SECONDS plus one request.
USER_CACHE_SECONDS = 60
STALE_USER_SECONDS = 600          # after this long unused, wait for a fresh lookup
_user_cache: Dict[uuid.UUID, Tuple[float, User]] = {}
_user_loading: Dict[uuid.UUID, "asyncio.Task[Optional[User]]"] = {}


def remember_user(user: User) -> None:
    """Keep this (just signed-in) account in memory so the next pages need no lookup."""
    if user is not None and user.account_status == AccountStatus.ACTIVE:
        _user_cache[user.id] = (time.monotonic() + USER_CACHE_SECONDS, user)


async def _load_user(user_id: uuid.UUID) -> Optional[User]:
    try:
        async with AsyncSessionLocal() as db:
            user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user is None or user.account_status != AccountStatus.ACTIVE:
            _user_cache.pop(user_id, None)
            return None
        remember_user(user)
        return user
    finally:
        _user_loading.pop(user_id, None)


def forget_user(user_id) -> None:
    """Drop the remembered copy of this account (call after changing it)."""
    from app.services.cache import invalidate   # late import: cache → logger → config only
    try:
        _user_cache.pop(uuid.UUID(str(user_id)), None)
    except ValueError:
        pass
    invalidate("settings:recipients")            # the alert-email recipient list may have changed


def clear_user_cache() -> None:
    _user_cache.clear()


async def user_from_token(token: Optional[str], db: AsyncSession) -> Optional[User]:
    """Resolve an access token to an active user (None if invalid)."""
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except (TypeError, ValueError):
        return None
    # the dashboard asks for ~9 things at once: they all share one lookup
    task = _user_loading.get(user_id)
    if task is None or task.done():
        task = None
    cached = _user_cache.get(user_id)
    if cached:
        expires, user = cached
        now = time.monotonic()
        if expires > now:
            return user
        if now - expires < STALE_USER_SECONDS:
            # answer now, re-check the account in the background (a deleted or
            # suspended account is refused from the next request on)
            if task is None:
                _user_loading[user_id] = asyncio.ensure_future(_load_user(user_id))
            return user
    if task is None:
        task = asyncio.ensure_future(_load_user(user_id))
        _user_loading[user_id] = task
    return await asyncio.shield(task)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """The authenticated user for this request (401 otherwise)."""
    token = credentials.credentials if credentials else None
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await user_from_token(token, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(*allowed_roles: UserRole):
    """Dependency factory for role-based authorization."""

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the SecureNet admin can do this.",
            )
        return current_user

    return role_checker


# Two roles: the admin configures SecureNet; every other account is a
# "SecureNet user" (monitor, turn the IDS on/off, alerts, reports). The legacy
# ANALYST / VIEWER values are both treated as SecureNet users.
require_admin = require_role(UserRole.ADMIN)
