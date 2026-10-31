"""
SecureNet Backend — Security Utilities

Password hashing, JWT token generation/validation, and other
security-related functions.
"""

import hashlib
import hmac
from datetime import timedelta
from typing import Optional, Dict, Any

import bcrypt
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.utils.timeutil import utcnow

# New passwords use PBKDF2-SHA256 (no 72-byte limit). Legacy bcrypt hashes
# ("$2a$/$2b$/$2y$") are verified directly with the `bcrypt` package because
# passlib's bcrypt backend is incompatible with bcrypt >= 4.1.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"])

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"
# Issued after the emailed OTP is verified; only lets the holder set the
# password of that pending registration (never usable as an access token).
SIGNUP_TOKEN_TYPE = "signup"
SIGNUP_TOKEN_MINUTES = 15
# Issued after a password-reset code is verified; only lets the holder set a new
# password once (it is bound to the current password hash).
RESET_TOKEN_TYPE = "reset"
# Carries a requested profile change until the emailed code confirms it.
PROFILE_TOKEN_TYPE = "profile"
# Carries a requested password change until the emailed code confirms it.
PASSWORD_CHANGE_TOKEN_TYPE = "password"
# Issued after the right email + password; only lets the holder finish signing
# in with the emailed code (never an access token).
LOGIN_TOKEN_TYPE = "login"
# proves the admin asked to turn Advanced Protection ON; the emailed code completes it
PROTECT_TOKEN_TYPE = "protect"


def hash_password(password: str) -> str:
    """Hash a plaintext password using PBKDF2-SHA256."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored password hash."""
    if not hashed_password:
        return False
    try:
        if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        return False


def _encode(data: Dict[str, Any], token_type: str, expires_delta: timedelta) -> str:
    now = utcnow()
    payload = {**data, "exp": now + expires_delta, "iat": now, "type": token_type}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a short-lived JWT access token."""
    return _encode(
        data,
        ACCESS_TOKEN_TYPE,
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a long-lived JWT refresh token."""
    return _encode(data, REFRESH_TOKEN_TYPE, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))


def create_signup_token(email: str) -> str:
    """Short-lived token proving `email` was verified by OTP (for setting the password)."""
    return _encode({"sub": email}, SIGNUP_TOKEN_TYPE, timedelta(minutes=SIGNUP_TOKEN_MINUTES))


def password_fingerprint(password_hash: Optional[str]) -> str:
    """Short digest of the stored hash: a reset token stops working once the password changes."""
    return hashlib.sha256((password_hash or "").encode("utf-8")).hexdigest()[:16]


def create_reset_token(email: str, password_hash: Optional[str]) -> str:
    """Short-lived token proving `email` was verified by OTP (for choosing a new password)."""
    return _encode({"sub": email, "pwv": password_fingerprint(password_hash)}, RESET_TOKEN_TYPE,
                   timedelta(minutes=SIGNUP_TOKEN_MINUTES))


def create_profile_token(user_id: str, changes: Dict[str, str], code_email: str) -> str:
    """Short-lived token holding a profile change that still needs its emailed code."""
    return _encode({"sub": user_id, "changes": changes, "code_email": code_email}, PROFILE_TOKEN_TYPE,
                   timedelta(minutes=SIGNUP_TOKEN_MINUTES))


def new_password_digest(new_password: str) -> str:
    """Keyed digest of a requested new password (the password itself never goes into a token)."""
    return hmac.new(settings.JWT_SECRET.encode("utf-8"), new_password.encode("utf-8"), hashlib.sha256).hexdigest()


def create_password_change_token(user_id: str, password_hash: Optional[str], new_password: str) -> str:
    """Short-lived token for a password change that still needs its emailed code.

    Bound to the user, to the current password (works once — useless after any
    password change) and to the new password chosen in step 1.
    """
    return _encode({"sub": user_id, "pwv": password_fingerprint(password_hash),
                    "npw": new_password_digest(new_password)},
                   PASSWORD_CHANGE_TOKEN_TYPE, timedelta(minutes=SIGNUP_TOKEN_MINUTES))


def create_login_token(user_id: str, password_hash: Optional[str]) -> str:
    """Short-lived proof that the password was right; the emailed code completes the sign-in.
    Bound to the current password, so it dies if the password changes meanwhile."""
    return _encode({"sub": user_id, "pwv": password_fingerprint(password_hash)}, LOGIN_TOKEN_TYPE,
                   timedelta(minutes=SIGNUP_TOKEN_MINUTES))


def create_protect_token(user_id: str, enabled: bool) -> str:
    """Short-lived proof that this user asked to change Advanced Protection; the emailed code confirms it.
    `enabled` (the target on/off state) is carried in the token so it can't be tampered with."""
    return _encode({"sub": user_id, "en": bool(enabled)}, PROTECT_TOKEN_TYPE,
                   timedelta(minutes=SIGNUP_TOKEN_MINUTES))


def decode_token(token: str, expected_type: str = ACCESS_TOKEN_TYPE) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT token of the expected type.

    Returns the payload, or None when the token is invalid, expired, or of a
    different type (a refresh token can never be used as an access token).
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None
    if payload.get("type") != expected_type:
        return None
    return payload


def validate_password_strength(password: str) -> tuple[bool, Optional[str]]:
    """Validate password meets minimum security requirements."""
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(char.isalpha() for char in password):
        return False, "Password must contain at least one letter"
    return True, None
