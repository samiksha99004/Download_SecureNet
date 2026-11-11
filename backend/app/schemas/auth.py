"""
SecureNet Backend — Authentication Schemas

Pydantic models for auth request/response validation.
These match the frontend TypeScript interfaces (camelCase on the wire).
"""

from typing import Optional

from pydantic import EmailStr, Field, field_validator, model_validator

from app.models.user import UserRole, AccountStatus, AuthProvider
from app.schemas.base import CamelModel, IdStr, UtcDatetime


# ── User Schema ───────────────────────────────────────────────────────────────

class UserResponse(CamelModel):
    """User data returned to frontend"""
    id: IdStr
    email: str
    full_name: str
    role: UserRole
    account_status: AccountStatus
    auth_provider: AuthProvider
    created_at: UtcDatetime
    last_login_at: Optional[UtcDatetime] = None
    avatar_url: Optional[str] = None
    email_alerts: bool = True


class UserPreferencesUpdate(CamelModel):
    """Personal settings stored with the account."""
    email_alerts: bool


# ── Auth Requests ─────────────────────────────────────────────────────────────

class LoginRequest(CamelModel):
    """Login credentials"""
    email: EmailStr
    password: str = Field(..., min_length=1)


class SignupRequest(CamelModel):
    """Step 1 of registration: who you are. A code is emailed to `email`."""
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr

    @field_validator("full_name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Full name must be at least 2 characters")
        return value


class CompleteSignupRequest(CamelModel):
    """Step 3 of registration: choose the password (after the OTP was verified)."""
    setup_token: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class OtpVerifyRequest(CamelModel):
    """OTP verification"""
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class ForgotPasswordRequest(CamelModel):
    """Forgot password step 1: email a code to this address (if it has an account)."""
    email: EmailStr


class ResetPasswordRequest(CamelModel):
    """Forgot password step 3: choose the new password."""
    reset_token: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class OtpResendRequest(CamelModel):
    """Request OTP resend"""
    email: EmailStr


class RefreshRequest(CamelModel):
    """Exchange a refresh token for a new token pair"""
    refresh_token: str = Field(..., min_length=10)


class ProfileChangeRequest(CamelModel):
    """Change your own details; only fields that differ are changed (after an emailed code)."""
    full_name: Optional[str] = Field(None, max_length=255)
    email: Optional[EmailStr] = None

    @field_validator("full_name")
    @classmethod
    def _name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Full name must be at least 2 characters")
        return value


class ProfileChangeStarted(CamelModel):
    """A code was emailed; send it back with `change_token` to apply the change."""
    change_token: str
    sent_to: str
    message: str


class ProfileChangeConfirm(CamelModel):
    change_token: str = Field(..., min_length=10)
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class LoginChallenge(CamelModel):
    """Right email + password: a sign-in code was emailed; send it back with `login_token`."""
    login_token: str
    sent_to: str
    message: str


class LoginVerifyRequest(CamelModel):
    login_token: str = Field(..., min_length=10)
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class LoginResendRequest(CamelModel):
    login_token: str = Field(..., min_length=10)


class LogoutConfirm(CamelModel):
    """Logging out needs the account password, so an attacker on an open session
    cannot sign out to stop detection/protection."""
    password: str = Field(..., min_length=1)


class ChangePasswordRequest(CamelModel):
    """Step 1 of a password change: checked, then a code is emailed to the registered address."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)
    confirm_new_password: str = Field(..., min_length=8)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("Passwords do not match")
        return self


class ChangePasswordConfirm(CamelModel):
    """Step 2: the emailed code (plus the same new password) applies the change."""
    change_token: str = Field(..., min_length=10)
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    new_password: str = Field(..., min_length=8)


# ── Auth Responses ────────────────────────────────────────────────────────────

class AuthTokens(CamelModel):
    """JWT tokens"""
    access_token: str
    refresh_token: str
    expires_in: int  # seconds


class AuthResponse(CamelModel):
    """Successful authentication response"""
    user: UserResponse
    tokens: AuthTokens


class PasswordResetVerifyResponse(CamelModel):
    """Forgot password step 2: the code was correct; `reset_token` allows setting a new password."""
    verified: bool
    email: str
    reset_token: str


class OtpVerifyResponse(CamelModel):
    """Step 2 of registration: the code was correct. `setup_token` lets the
    client set the password (valid for a few minutes, single account)."""
    verified: bool
    email: str
    setup_token: str
