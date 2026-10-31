"""
SecureNet Backend — Authentication Routes

Handles user registration, login, OTP verification, and token management.
"""

import asyncio
import hmac
import secrets
import string
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import forget_user, get_current_user, remember_user
from app.core.config import settings
from app.core.security import (
    LOGIN_TOKEN_TYPE,
    PASSWORD_CHANGE_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    PROFILE_TOKEN_TYPE,
    RESET_TOKEN_TYPE,
    SIGNUP_TOKEN_TYPE,
    create_access_token,
    create_login_token,
    create_password_change_token,
    create_profile_token,
    create_refresh_token,
    create_reset_token,
    create_signup_token,
    decode_token,
    new_password_digest,
    password_fingerprint,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.db.base import get_db
from app.models.otp import OTP
from app.models.user import AccountStatus, AuthProvider, User, UserRole
from app.schemas.auth import (
    AuthResponse,
    AuthTokens,
    ChangePasswordConfirm,
    ChangePasswordRequest,
    CompleteSignupRequest,
    ForgotPasswordRequest,
    LoginChallenge,
    LoginRequest,
    LoginResendRequest,
    LoginVerifyRequest,
    OtpResendRequest,
    OtpVerifyRequest,
    OtpVerifyResponse,
    PasswordResetVerifyResponse,
    ProfileChangeConfirm,
    ProfileChangeRequest,
    ProfileChangeStarted,
    RefreshRequest,
    ResetPasswordRequest,
    SignupRequest,
    UserPreferencesUpdate,
    UserResponse,
)
from app.schemas.common import MessageResponse
from app.utils.email import (
    EmailDeliveryError,
    email_delivery_status,
    send_email,
    send_login_code_email,
    send_otp_email,
    send_password_change_email,
    send_password_reset_email,
    send_profile_change_email,
)
from app.utils import ratelimit
from app.utils.logger import logger
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/auth", tags=["Authentication"])

GENERIC_RESEND_MESSAGE = "If this email has a pending registration, a new code has been sent."
GENERIC_RESET_MESSAGE = "If an account exists for this email, a verification code has been sent to it."
# Checked when an email has no account, so a wrong email takes as long as a
# wrong password and the response time doesn't reveal who is registered.
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))


def generate_otp(length: int = 6) -> str:
    """Generate a random numeric OTP"""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def normalize_email(email: str) -> str:
    return email.strip().lower()


def create_auth_response(user: User) -> AuthResponse:
    """Create authentication response with a fresh token pair"""
    remember_user(user)   # the dashboard that opens next needs no user lookup
    return AuthResponse(
        user=UserResponse.model_validate(user),
        tokens=AuthTokens(
            access_token=create_access_token(data={"sub": str(user.id)}),
            refresh_token=create_refresh_token(data={"sub": str(user.id)}),
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        ),
    )


async def _latest_otp(db: AsyncSession, email: str, unused_only: bool) -> OTP | None:
    query = select(OTP).where(OTP.email == email)
    if unused_only:
        query = query.where(OTP.is_used.is_(False))
    result = await db.execute(query.order_by(OTP.created_at.desc()).limit(1))
    return result.scalars().first()


async def _issue_otp(db: AsyncSession, email: str) -> str:
    """Invalidate any outstanding OTPs for `email` and create a new one."""
    await db.execute(
        update(OTP).where(OTP.email == email, OTP.is_used.is_(False)).values(is_used=True, used_at=utcnow())
    )
    code = generate_otp(settings.OTP_LENGTH)
    db.add(OTP(email=email, otp_code=code))
    return code


async def _consume_otp(db: AsyncSession, email: str, code: str, http: Request | None = None) -> None:
    """Check `code` against the latest unused OTP for `email` and mark it used.

    Raises 400 with a user-facing message when there is no code, it expired,
    it is wrong (attempts are counted and committed) or attempts ran out.
    """
    ratelimit.enforce("code-fail", http)
    otp = await _latest_otp(db, email, unused_only=True)
    if not otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No verification code found. Please request a new one.")
    if not otp.is_valid():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Verification code has expired or exceeded maximum attempts. Request a new one.")

    otp.attempts += 1
    if not secrets.compare_digest(otp.otp_code, code):
        ratelimit.record("code-fail", http)
        await db.commit()
        remaining = settings.OTP_MAX_ATTEMPTS - otp.attempts
        if remaining <= 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Maximum attempts exceeded. Please request a new code.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid code. {remaining} attempt(s) remaining.")
    otp.is_used = True
    otp.used_at = utcnow()


async def _check_resend_cooldown(db: AsyncSession, email: str) -> None:
    """At most one new code per cooldown while the previous one is still outstanding."""
    last_otp = await _latest_otp(db, email, unused_only=True)
    if last_otp:
        elapsed = (utcnow() - last_otp.created_at).total_seconds()
        if elapsed < settings.OTP_RESEND_COOLDOWN_SECONDS:
            remaining = int(settings.OTP_RESEND_COOLDOWN_SECONDS - elapsed) + 1
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                detail=f"Please wait {remaining} seconds before requesting a new code")


def _role_for_new_account(email: str, active_users: int) -> UserRole:
    """ADMIN_EMAILS decides admins; without it the first account becomes admin."""
    if settings.admin_emails:
        return UserRole.ADMIN if email in settings.admin_emails else UserRole.VIEWER
    return UserRole.ADMIN if active_users == 0 else UserRole.VIEWER


def _email_failure_detail() -> str:
    # The technical reason is logged; users get a plain message.
    if email_delivery_status() != "enabled":
        return ("SecureNet can't send emails yet, so the verification code could not be sent. "
                "Please contact the SecureNet admin.")
    return "We could not send the verification email right now. Please try again in a few minutes."


@router.post("/signup", response_model=MessageResponse)
async def signup(request: SignupRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Registration step 1: full name, email and phone number -> a code is emailed.

    Steps 2-3 are /otp/verify (code) and /signup/complete (password). The
    account only becomes usable once the password is set.
    """
    email = normalize_email(request.email)
    existing = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if existing and existing.account_status != AccountStatus.PENDING_VERIFICATION:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This email is already registered. Please sign in.")

    if existing:
        # Unfinished registration: refresh the details and send a new code.
        existing.full_name = request.full_name
        existing.phone_number = request.phone_number
        existing.password_hash = None
    else:
        db.add(User(
            email=email,
            full_name=request.full_name,
            phone_number=request.phone_number,
            password_hash=None,
            role=UserRole.VIEWER,  # decided when the account is completed
            account_status=AccountStatus.PENDING_VERIFICATION,
            auth_provider=AuthProvider.LOCAL,
        ))

    ratelimit.enforce("code-send", http)
    otp_code = await _issue_otp(db, email)
    try:
        await send_otp_email(email, otp_code)
    except EmailDeliveryError as exc:
        await db.rollback()
        logger.error(f"Signup email failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
    await db.commit()
    ratelimit.record("code-send", http)
    logger.info(f"Registration started, code emailed to: {email}")
    return MessageResponse(message=f"A verification code has been sent to {email}.")


@router.post("/signup/complete", response_model=AuthResponse)
async def complete_signup(request: CompleteSignupRequest, db: AsyncSession = Depends(get_db)):
    """Registration step 3: set the password; the account is created and signed in.

    Emails listed in ADMIN_EMAILS become admin, everyone else a normal user
    (viewer). Without ADMIN_EMAILS the first account becomes the admin.
    """
    payload = decode_token(request.setup_token, expected_type=SIGNUP_TOKEN_TYPE)
    if not payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This link has expired. Please start the registration again.")
    email = normalize_email(str(payload.get("sub", "")))
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if user is None or user.account_status != AccountStatus.PENDING_VERIFICATION:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This registration is already complete. Please sign in.")

    is_valid, error_msg = validate_password_strength(request.password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    active_users = (await db.execute(
        select(func.count()).select_from(User).where(User.account_status == AccountStatus.ACTIVE)
    )).scalar() or 0
    user.role = _role_for_new_account(email, active_users)
    user.password_hash = hash_password(request.password)
    user.account_status = AccountStatus.ACTIVE
    user.failed_login_attempts = 0
    user.last_login_at = utcnow()
    await db.commit()
    forget_user(user.id)                          # new account: alert recipients changed
    logger.info(f"Account created: {email} ({user.role.value})")
    return create_auth_response(user)


@router.post("/login", response_model=LoginChallenge)
async def login(request: LoginRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Sign-in step 1: email + password (temporary lockout after repeated failures).

    The right password is not enough: a 6-digit code is emailed to the account
    and /login/verify finishes the sign-in (two-factor sign-in).
    """
    ratelimit.enforce("login-fail", http)
    email = normalize_email(request.email)
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user or not user.password_hash:
        await asyncio.to_thread(verify_password, request.password, _DUMMY_PASSWORD_HASH)
        ratelimit.record("login-fail", http)
        raise invalid

    now = utcnow()
    if user.locked_until and user.locked_until > now:
        minutes = max(1, int((user.locked_until - now).total_seconds() // 60) + 1)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {minutes} minute(s).",
        )

    if not await asyncio.to_thread(verify_password, request.password, user.password_hash):
        ratelimit.record("login-fail", http)
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
            logger.warning(f"Account locked after repeated failures: {email}")
        await db.commit()
        raise invalid

    if user.account_status == AccountStatus.PENDING_VERIFICATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration not finished. Please create your account again to get a new code.",
        )
    if user.account_status == AccountStatus.SUSPENDED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is suspended")

    user.failed_login_attempts = 0
    user.locked_until = None
    code_email = normalize_email(user.email)
    latest = await _latest_otp(db, code_email, unused_only=True)
    just_sent = (latest is not None and latest.is_valid()
                 and (now - latest.created_at).total_seconds() < settings.OTP_RESEND_COOLDOWN_SECONDS)
    if just_sent:
        # signing in again straight away: the code emailed a moment ago still works
        message = f"We just sent a 6-digit code to {_mask(code_email)}. Enter it to finish signing in."
    else:
        ratelimit.enforce("code-send", http)
        otp_code = await _issue_otp(db, code_email)
        try:
            await send_login_code_email(code_email, otp_code)
        except EmailDeliveryError as exc:
            await db.rollback()
            logger.error(f"Sign-in code for {email} could not be sent: {exc}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
        ratelimit.record("code-send", http)
        message = f"We sent a 6-digit code to {_mask(code_email)}. Enter it to finish signing in."
    await db.commit()
    logger.info(f"Password accepted, sign-in code step for: {email}")
    return LoginChallenge(
        login_token=create_login_token(str(user.id), user.password_hash),
        sent_to=_mask(code_email),
        message=message,
    )


async def _user_from_login_token(db: AsyncSession, token: str) -> User:
    """The account a sign-in token belongs to (400 when expired, used or the password changed)."""
    expired = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This sign-in has expired. Please sign in again.")
    payload = decode_token(token, expected_type=LOGIN_TOKEN_TYPE)
    if not payload:
        raise expired
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except (TypeError, ValueError):
        raise expired
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if (user is None or user.account_status != AccountStatus.ACTIVE
            or payload.get("pwv") != password_fingerprint(user.password_hash)):
        raise expired
    return user


@router.post("/login/verify", response_model=AuthResponse)
async def verify_login(request: LoginVerifyRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Sign-in step 2: the emailed code; returns the session tokens."""
    user = await _user_from_login_token(db, request.login_token)
    await _consume_otp(db, normalize_email(user.email), request.otp, http)
    user.last_login_at = utcnow()
    await db.commit()
    logger.info(f"User logged in (code confirmed): {user.email}")
    return create_auth_response(user)


@router.post("/login/resend", response_model=MessageResponse)
async def resend_login_code(request: LoginResendRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Email a new sign-in code (the password step was already passed)."""
    user = await _user_from_login_token(db, request.login_token)
    code_email = normalize_email(user.email)
    await _check_resend_cooldown(db, code_email)
    ratelimit.enforce("code-send", http)
    otp_code = await _issue_otp(db, code_email)
    try:
        await send_login_code_email(code_email, otp_code)
    except EmailDeliveryError as exc:
        await db.rollback()
        logger.error(f"Sign-in code resend for {code_email} failed: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
    await db.commit()
    ratelimit.record("code-send", http)
    return MessageResponse(message=f"A new code has been sent to {_mask(code_email)}.")


@router.post("/otp/verify", response_model=OtpVerifyResponse)
async def verify_otp(request: OtpVerifyRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Registration step 2: check the emailed code; returns a short-lived token for
    setting the password (the account is not active yet)."""
    email = normalize_email(request.email)
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if user is not None and user.account_status != AccountStatus.PENDING_VERIFICATION:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This email is already registered. Please sign in.")

    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No verification code found. Please request a new one.")
    await _consume_otp(db, email, request.otp, http)
    await db.commit()
    logger.info(f"Email verified by code: {email}")
    return OtpVerifyResponse(verified=True, email=email, setup_token=create_signup_token(email))


@router.post("/otp/resend", response_model=MessageResponse)
async def resend_otp(request: OtpResendRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Resend a verification code (only for pending accounts; response is generic)."""
    email = normalize_email(request.email)
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if user is None or user.account_status != AccountStatus.PENDING_VERIFICATION:
        return MessageResponse(message=GENERIC_RESEND_MESSAGE)

    await _check_resend_cooldown(db, email)
    ratelimit.enforce("code-send", http)
    otp_code = await _issue_otp(db, email)
    try:
        await send_otp_email(email, otp_code)
    except EmailDeliveryError as exc:
        await db.rollback()
        logger.error(f"OTP resend failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
    await db.commit()
    ratelimit.record("code-send", http)
    logger.info(f"OTP resent to: {email}")
    return MessageResponse(message=GENERIC_RESEND_MESSAGE)


# ── Forgot password: email -> code -> new password ───────────────────────────

@router.post("/password/forgot", response_model=MessageResponse)
async def forgot_password(request: ForgotPasswordRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Step 1: email a reset code (same answer whether or not the account exists)."""
    email = normalize_email(request.email)
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if user is None or user.account_status != AccountStatus.ACTIVE:
        return MessageResponse(message=GENERIC_RESET_MESSAGE)

    await _check_resend_cooldown(db, email)
    ratelimit.enforce("code-send", http)
    otp_code = await _issue_otp(db, email)
    try:
        await send_password_reset_email(email, otp_code)
    except EmailDeliveryError as exc:
        await db.rollback()
        logger.error(f"Password reset email failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
    await db.commit()
    ratelimit.record("code-send", http)
    logger.info(f"Password reset code sent to: {email}")
    return MessageResponse(message=GENERIC_RESET_MESSAGE)


@router.post("/password/verify", response_model=PasswordResetVerifyResponse)
async def verify_password_reset(request: OtpVerifyRequest, http: Request, db: AsyncSession = Depends(get_db)):
    """Step 2: check the emailed code; returns a short-lived token for the new password."""
    email = normalize_email(request.email)
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if user is None or user.account_status != AccountStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No verification code found. Please request a new one.")
    await _consume_otp(db, email, request.otp, http)
    await db.commit()
    logger.info(f"Password reset code verified: {email}")
    return PasswordResetVerifyResponse(verified=True, email=email,
                                       reset_token=create_reset_token(email, user.password_hash))


@router.post("/password/reset", response_model=MessageResponse)
async def reset_password(request: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Step 3: set the new password (the token works once), then sign in with it."""
    payload = decode_token(request.reset_token, expected_type=RESET_TOKEN_TYPE)
    expired = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This reset link has expired or was already used. Please start again.")
    if not payload:
        raise expired
    email = normalize_email(str(payload.get("sub", "")))
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    if (user is None or user.account_status != AccountStatus.ACTIVE
            or payload.get("pwv") != password_fingerprint(user.password_hash)):
        raise expired

    is_valid, error_msg = validate_password_strength(request.password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    user.password_hash = hash_password(request.password)
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    forget_user(user.id)
    logger.info(f"Password reset completed: {email}")
    return MessageResponse(message="Your password has been changed. Sign in with your new password.")


@router.post("/refresh", response_model=AuthResponse)
async def refresh_tokens(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a valid refresh token for a new access/refresh token pair."""
    payload = decode_token(request.refresh_token, expected_type=REFRESH_TOKEN_TYPE)
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                 detail="Session expired. Please sign in again.")
    if not payload:
        raise unauthorized
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except (TypeError, ValueError):
        raise unauthorized
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or user.account_status != AccountStatus.ACTIVE:
        raise unauthorized
    return create_auth_response(user)


@router.post("/logout", response_model=MessageResponse)
async def logout(current_user: User = Depends(get_current_user)):
    """Logout (tokens are discarded client-side)."""
    logger.info(f"User logged out: {current_user.email}")
    return MessageResponse(message="Logged out successfully")


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user's profile"""
    return UserResponse.model_validate(current_user)


@router.put("/me/preferences", response_model=UserResponse)
async def update_preferences(
    request: UserPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Personal settings: attack alert emails on/off (sign-in and confirmation codes are always sent)."""
    user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one()
    user.email_alerts = request.email_alerts
    await db.commit()
    await db.refresh(user)
    forget_user(user.id)
    logger.info(f"Alert emails {'on' if user.email_alerts else 'off'} for {user.email}")
    return UserResponse.model_validate(user)


# ── Change your own details (name / phone / email) — confirmed by an emailed code ──

PROFILE_FIELDS = {"full_name": "name", "phone_number": "phone number", "email": "email address"}


def _mask(email: str) -> str:
    name, _, domain = email.partition("@")
    return f"{name[:2]}{'*' * max(1, len(name) - 2)}@{domain}"


@router.post("/profile/change", response_model=ProfileChangeStarted)
async def request_profile_change(
    request: ProfileChangeRequest,
    http: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Step 1: say what to change; a code goes to your email (to the NEW email if it changes)."""
    changes: dict[str, str] = {}
    if request.full_name is not None and request.full_name != current_user.full_name:
        changes["full_name"] = request.full_name
    if request.phone_number is not None and request.phone_number != (current_user.phone_number or ""):
        changes["phone_number"] = request.phone_number
    if request.email is not None:
        new_email = normalize_email(request.email)
        if new_email != normalize_email(current_user.email):
            taken = (await db.execute(select(User).where(func.lower(User.email) == new_email))).scalar_one_or_none()
            if taken:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="This email is already used by another account.")
            changes["email"] = new_email
    if not changes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nothing to change — your details are the same.")

    code_email = changes.get("email", normalize_email(current_user.email))
    await _check_resend_cooldown(db, code_email)
    ratelimit.enforce("code-send", http)
    otp_code = await _issue_otp(db, code_email)
    summary = " and ".join(PROFILE_FIELDS[f] for f in changes)
    try:
        await send_profile_change_email(code_email, otp_code, summary)
    except EmailDeliveryError as exc:
        await db.rollback()
        logger.error(f"Profile change code for {current_user.email} failed: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
    await db.commit()
    ratelimit.record("code-send", http)
    logger.info(f"Profile change requested by {current_user.email}: {sorted(changes)}")
    return ProfileChangeStarted(
        change_token=create_profile_token(str(current_user.id), changes, code_email),
        sent_to=_mask(code_email),
        message=f"We sent a 6-digit code to {_mask(code_email)}. Enter it to confirm the change.",
    )


@router.post("/profile/confirm", response_model=UserResponse)
async def confirm_profile_change(
    request: ProfileChangeConfirm,
    http: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Step 2: the emailed code applies the change."""
    payload = decode_token(request.change_token, expected_type=PROFILE_TOKEN_TYPE)
    if not payload or payload.get("sub") != str(current_user.id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This change request has expired. Please start again.")
    changes: dict = payload.get("changes") or {}
    code_email = str(payload.get("code_email", ""))
    await _consume_otp(db, code_email, request.otp, http)

    user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one()
    old_email = user.email
    if "email" in changes:
        taken = (await db.execute(
            select(User).where(func.lower(User.email) == changes["email"], User.id != user.id)
        )).scalar_one_or_none()
        if taken:
            await db.commit()  # keep the used code used
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="This email is already used by another account.")
    for field in ("full_name", "phone_number", "email"):
        if field in changes:
            setattr(user, field, changes[field])
    await db.commit()
    await db.refresh(user)
    forget_user(user.id)
    logger.info(f"Profile changed for {old_email}: {sorted(changes)}")

    if "email" in changes:  # tell the old address (best effort)
        text = (f"The email address of your {settings.APP_NAME} account was changed from {old_email} "
                f"to {user.email}. If you did not do this, contact the {settings.APP_NAME} admin.")
        try:
            await send_email([old_email], f"{settings.APP_NAME} - Your email address was changed", text,
                             f"<html><body style='font-family:Arial,sans-serif'><p>{text}</p></body></html>")
        except EmailDeliveryError as exc:
            logger.warning(f"Email-change notice to {old_email} failed: {exc}")
    return UserResponse.model_validate(user)


@router.put("/profile", response_model=UserResponse)
async def update_profile(
    request: ProfileChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update name / phone / email directly — the input is validated and saved at once
    (no emailed code). The schema already checks the phone/email format ("verify"),
    and a changed email is still checked for uniqueness. The old address is notified."""
    changes: dict[str, str] = {}
    if request.full_name is not None and request.full_name != current_user.full_name:
        changes["full_name"] = request.full_name
    if request.phone_number is not None and request.phone_number != (current_user.phone_number or ""):
        changes["phone_number"] = request.phone_number
    if request.email is not None:
        new_email = normalize_email(request.email)
        if new_email != normalize_email(current_user.email):
            changes["email"] = new_email
    if not changes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Nothing to change — your details are the same.")

    user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one()
    old_email = user.email
    if "email" in changes:
        taken = (await db.execute(
            select(User).where(func.lower(User.email) == changes["email"], User.id != user.id)
        )).scalar_one_or_none()
        if taken:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="This email is already used by another account.")
    for field in ("full_name", "phone_number", "email"):
        if field in changes:
            setattr(user, field, changes[field])
    await db.commit()
    await db.refresh(user)
    forget_user(user.id)
    logger.info(f"Profile updated for {old_email}: {sorted(changes)}")

    if "email" in changes:  # tell the old address (best effort)
        text = (f"The email address of your {settings.APP_NAME} account was changed from {old_email} "
                f"to {user.email}. If you did not do this, contact the {settings.APP_NAME} admin.")
        try:
            await send_email([old_email], f"{settings.APP_NAME} - Your email address was changed", text,
                             f"<html><body style='font-family:Arial,sans-serif'><p>{text}</p></body></html>")
        except EmailDeliveryError as exc:
            logger.warning(f"Email-change notice to {old_email} failed: {exc}")
    return UserResponse.model_validate(user)


# ── Change password (signed in) — current password + a code emailed to the registered address ──

@router.post("/change-password", response_model=ProfileChangeStarted)
async def change_password(
    request: ChangePasswordRequest,
    http: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Step 1: check the current and new password, then email a code to the registered address.

    Nothing changes until the code is confirmed (/change-password/confirm), so a
    stolen session alone cannot take over the account.
    """
    if current_user.auth_provider != AuthProvider.LOCAL:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Cannot change password for {current_user.auth_provider.value} accounts")
    ratelimit.enforce("login-fail", http)
    if not await asyncio.to_thread(verify_password, request.current_password, current_user.password_hash or ""):
        ratelimit.record("login-fail", http)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    is_valid, error_msg = validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)
    if request.new_password == request.current_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="New password must differ from your current password.")

    code_email = normalize_email(current_user.email)
    await _check_resend_cooldown(db, code_email)
    ratelimit.enforce("code-send", http)
    otp_code = await _issue_otp(db, code_email)
    try:
        await send_password_change_email(code_email, otp_code)
    except EmailDeliveryError as exc:
        await db.rollback()
        logger.error(f"Password change code for {current_user.email} failed: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_email_failure_detail())
    await db.commit()
    ratelimit.record("code-send", http)
    logger.info(f"Password change requested by {current_user.email}")
    return ProfileChangeStarted(
        change_token=create_password_change_token(str(current_user.id), current_user.password_hash,
                                                  request.new_password),
        sent_to=_mask(code_email),
        message=f"We sent a 6-digit code to {_mask(code_email)}. Enter it to confirm your new password.",
    )


@router.post("/change-password/confirm", response_model=MessageResponse)
async def confirm_password_change(
    request: ChangePasswordConfirm,
    http: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Step 2: the emailed code sets the new password chosen in step 1 (the token works once)."""
    payload = decode_token(request.change_token, expected_type=PASSWORD_CHANGE_TOKEN_TYPE)
    if (not payload or payload.get("sub") != str(current_user.id)
            or payload.get("pwv") != password_fingerprint(current_user.password_hash)
            or not hmac.compare_digest(str(payload.get("npw", "")), new_password_digest(request.new_password))):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This password change has expired. Please start again.")
    await _consume_otp(db, normalize_email(current_user.email), request.otp, http)

    user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one()
    user.password_hash = await asyncio.to_thread(hash_password, request.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = utcnow()
    await db.commit()
    forget_user(user.id)
    logger.info(f"Password changed (code confirmed) for: {user.email}")
    return MessageResponse(message="Your password has been changed.")
