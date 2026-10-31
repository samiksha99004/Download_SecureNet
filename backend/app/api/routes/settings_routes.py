"""
SecureNet Backend — Settings Routes

Detection, protection, notification and system settings plus the whitelist.
Anyone signed in can read settings; only the admin can change them.
Every change is pushed to the running IDS immediately.
"""

from typing import Type, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.api.dependencies import get_current_user, require_admin
from app.core.security import PROTECT_TOKEN_TYPE, create_protect_token, decode_token
from app.db.base import AsyncSessionLocal, get_db
from app.ml.ids_service import get_ids_service
from app.utils.email import _send_code
from app.models.settings import (
    DetectionSettings,
    NotificationSettings,
    ProtectionMode,
    ProtectionSettings,
    SystemSettings,
    WhitelistEntry,
)
from app.models.user import User
from app.schemas.common import MessageResponse
from app.schemas.settings import (
    AdvancedProtectionChallenge,
    AdvancedProtectionConfirm,
    AdvancedProtectionResponse,
    AdvancedProtectionUpdate,
    AllSettingsResponse,
    CreateWhitelistEntryRequest,
    DetectionSettingsResponse,
    DetectionSettingsUpdate,
    NotificationSettingsResponse,
    NotificationSettingsUpdate,
    ProtectionSettingsResponse,
    ProtectionSettingsUpdate,
    SystemSettingsResponse,
    SystemSettingsUpdate,
    WhitelistEntryResponse,
)
from app.services.cache import cached, settings_changed
from app.utils.logger import logger
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/settings", tags=["Settings"])

M = TypeVar("M")


async def get_or_create(db: AsyncSession, model: Type[M]) -> M:
    """Fetch the single settings row, creating it with defaults if missing."""
    row = (await db.execute(select(model).order_by(model.updated_at).limit(1))).scalars().first()
    if row is None:
        row = model()
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


async def _apply_update(db: AsyncSession, model, updates, user: User):
    row = await get_or_create(db, model)
    for field, value in updates.model_dump(exclude_unset=True).items():
        if value is None and not model.__table__.columns[field].nullable:
            continue
        setattr(row, field, value)
    row.updated_at = utcnow()
    row.updated_by = user.id
    await db.commit()
    await db.refresh(row)
    settings_changed()
    await get_ids_service().reload_config()
    logger.info(f"{model.__tablename__} updated by {user.email}")
    return row


@router.get("", response_model=AllSettingsResponse)
async def get_all_settings(current_user: User = Depends(get_current_user)):
    return await cached_all_settings()


async def cached_all_settings() -> AllSettingsResponse:
    return await cached("settings:all", _load_all_settings, ttl=300)


async def _load_all_settings() -> AllSettingsResponse:
    async with AsyncSessionLocal() as db:
        return AllSettingsResponse(
            detection=DetectionSettingsResponse.model_validate(await get_or_create(db, DetectionSettings)),
            protection=ProtectionSettingsResponse.model_validate(await get_or_create(db, ProtectionSettings)),
            notifications=NotificationSettingsResponse.model_validate(await get_or_create(db, NotificationSettings)),
            system=SystemSettingsResponse.model_validate(await get_or_create(db, SystemSettings)),
        )


@router.get("/detection", response_model=DetectionSettingsResponse)
async def get_detection_settings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await cached_detection_settings()


async def _load_detection_settings() -> DetectionSettingsResponse:
    async with AsyncSessionLocal() as db:
        return DetectionSettingsResponse.model_validate(await get_or_create(db, DetectionSettings))


async def cached_detection_settings() -> DetectionSettingsResponse:
    return await cached("settings:detection", _load_detection_settings, ttl=300)


@router.put("/detection", response_model=DetectionSettingsResponse)
async def update_detection_settings(
    updates: DetectionSettingsUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    return DetectionSettingsResponse.model_validate(await _apply_update(db, DetectionSettings, updates, current_user))


@router.get("/protection", response_model=ProtectionSettingsResponse)
async def get_protection_settings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return ProtectionSettingsResponse.model_validate(await get_or_create(db, ProtectionSettings))


@router.put("/protection", response_model=ProtectionSettingsResponse)
async def update_protection_settings(
    updates: ProtectionSettingsUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    row = await _apply_update(db, ProtectionSettings, updates, current_user)
    ids = get_ids_service()
    if updates.mode is not None and ids.enabled:
        await ids.set_mode(updates.mode.value)
        await ids.broadcast_status()
    return ProtectionSettingsResponse.model_validate(row)


# ── Advanced Protection (one switch) ───────────────────────────────────────────
# ON  ⇒ protection mode "protect" + auto-block high/medium attackers.
# OFF ⇒ "monitor" (normal IDS: detect and alert only, no blocking).

_ADVANCED_SEVERITIES = ["high", "medium"]


def _advanced_enabled(row: ProtectionSettings) -> bool:
    return row.mode == ProtectionMode.PROTECT and bool(row.auto_block)


def _mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    masked = (name[0] + "***") if name else "***"
    return f"{masked}@{domain}" if domain else masked


async def _set_advanced(db: AsyncSession, enabled: bool, user: User) -> ProtectionSettings:
    """Flip the protection mode and apply it to the running IDS at once."""
    row = await get_or_create(db, ProtectionSettings)
    if enabled:
        row.mode = ProtectionMode.PROTECT
        row.auto_block = True
        row.auto_block_severities = list(_ADVANCED_SEVERITIES)
    else:
        row.mode = ProtectionMode.MONITOR
        row.auto_block = False
    row.updated_at = utcnow()
    row.updated_by = user.id
    await db.commit()
    await db.refresh(row)
    settings_changed()

    ids = get_ids_service()
    await ids.reload_config()
    if ids.enabled:                       # apply to the running IDS right away
        await ids.set_mode(row.mode.value)
        await ids.broadcast_status()
    logger.info(f"Advanced Protection {'ENABLED' if enabled else 'disabled'} by {user.email}")
    return row


@router.get("/advanced-protection", response_model=AdvancedProtectionResponse)
async def get_advanced_protection(current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        row = await get_or_create(db, ProtectionSettings)
        return AdvancedProtectionResponse(enabled=_advanced_enabled(row))


@router.put("/advanced-protection", response_model=AdvancedProtectionResponse)
async def set_advanced_protection(
    updates: AdvancedProtectionUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Turn Advanced Protection ON directly — no code. Turning it OFF needs the emailed-code
    flow below, so an attacker who got in can't just switch protection off."""
    if not updates.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Turning Advanced Protection off needs email confirmation — request a code first.",
        )
    row = await _set_advanced(db, True, current_user)
    return AdvancedProtectionResponse(enabled=_advanced_enabled(row))


@router.post("/advanced-protection/request-code", response_model=AdvancedProtectionChallenge)
async def request_advanced_protection_code(
    updates: AdvancedProtectionUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Emails a 6-digit code to confirm turning protection OFF (turning it ON is instant and
    needs no code). The target state is carried in the token the response returns."""
    if updates.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Turning Advanced Protection on does not need a code — use the switch directly.",
        )
    from app.api.routes.auth import _issue_otp, _check_resend_cooldown  # reuse the OTP machinery
    email = current_user.email.strip().lower()
    action = "off"
    await _check_resend_cooldown(db, email)
    code = await _issue_otp(db, email)
    await db.commit()
    try:
        await _send_code(email, code, "Advanced Protection",
                         f"Enter it in Settings → Advanced Protection to turn protection {action}.")
    except Exception as exc:  # delivery failed — don't leave the user waiting on a code that never comes
        logger.error(f"Advanced Protection code email failed: {exc}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="We could not send the confirmation email right now. Please try again.")
    return AdvancedProtectionChallenge(
        confirm_token=create_protect_token(str(current_user.id), updates.enabled),
        sent_to=_mask_email(email),
        message=f"Enter the code we emailed you to turn Advanced Protection {action}.",
    )


@router.post("/advanced-protection/confirm", response_model=AdvancedProtectionResponse)
async def confirm_advanced_protection(
    payload: AdvancedProtectionConfirm,
    http: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm with the emailed code → protection changes to the state asked for (on or off)."""
    from app.api.routes.auth import _consume_otp
    data = decode_token(payload.token, PROTECT_TOKEN_TYPE)
    if not data or data.get("sub") != str(current_user.id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This confirmation has expired. Please request a new code.")
    enabled = bool(data.get("en"))
    await _consume_otp(db, current_user.email.strip().lower(), payload.otp, http)
    await db.commit()
    row = await _set_advanced(db, enabled, current_user)
    return AdvancedProtectionResponse(enabled=_advanced_enabled(row))


@router.get("/notifications", response_model=NotificationSettingsResponse)
async def get_notification_settings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return NotificationSettingsResponse.model_validate(await get_or_create(db, NotificationSettings))


@router.put("/notifications", response_model=NotificationSettingsResponse)
async def update_notification_settings(
    updates: NotificationSettingsUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    return NotificationSettingsResponse.model_validate(
        await _apply_update(db, NotificationSettings, updates, current_user)
    )


@router.get("/system", response_model=SystemSettingsResponse)
async def get_system_settings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return SystemSettingsResponse.model_validate(await get_or_create(db, SystemSettings))


@router.put("/system", response_model=SystemSettingsResponse)
async def update_system_settings(
    updates: SystemSettingsUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    return SystemSettingsResponse.model_validate(await _apply_update(db, SystemSettings, updates, current_user))


# ── Whitelist Management ──────────────────────────────────────────────────────

@router.get("/whitelist", response_model=list[WhitelistEntryResponse])
async def get_whitelist(current_user: User = Depends(get_current_user)):
    return await cached_whitelist()


async def cached_whitelist() -> list[WhitelistEntryResponse]:
    return await cached("settings:whitelist", _load_whitelist, ttl=300)


async def _load_whitelist() -> list[WhitelistEntryResponse]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(WhitelistEntry).where(WhitelistEntry.active.is_(True)).order_by(WhitelistEntry.created_at.desc())
        )
        return [WhitelistEntryResponse.model_validate(entry) for entry in result.scalars().all()]


@router.post("/whitelist", response_model=WhitelistEntryResponse)
async def add_whitelist_entry(
    request: CreateWhitelistEntryRequest,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = (await db.execute(
        select(WhitelistEntry).where(
            WhitelistEntry.type == request.type,
            WhitelistEntry.value == request.value,
            WhitelistEntry.active.is_(True),
        ).limit(1)
    )).scalars().first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This whitelist entry already exists")

    entry = WhitelistEntry(
        type=request.type,
        value=request.value,
        description=request.description,
        created_by=current_user.id,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    settings_changed()
    await get_ids_service().reload_config()
    logger.info(f"Whitelist entry added by {current_user.email}: {request.type.value}:{request.value}")
    return WhitelistEntryResponse.model_validate(entry)


@router.delete("/whitelist/{entry_id}", response_model=MessageResponse)
async def remove_whitelist_entry(
    entry_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    try:
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid entry ID format")

    entry = (await db.execute(select(WhitelistEntry).where(WhitelistEntry.id == entry_uuid))).scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Whitelist entry not found")

    entry.active = False  # soft delete (keeps the audit trail)
    await db.commit()
    settings_changed()
    await get_ids_service().reload_config()
    logger.info(f"Whitelist entry removed by {current_user.email}: {entry.type.value}:{entry.value}")
    return MessageResponse(message="Whitelist entry removed successfully")
