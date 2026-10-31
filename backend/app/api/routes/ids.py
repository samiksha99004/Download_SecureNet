"""
SecureNet Backend — IDS Control Routes

Turn the IDS OFF / ON and choose Detection ("monitor") or Protection
("protect") mode.
"""

from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import get_current_user
from app.ml.ids_service import get_ids_service
from app.ml.network_monitor import CaptureUnavailable
from app.models.user import User
from app.schemas.base import CamelModel
from app.services.autostart import remember_ids_state
from app.utils.logger import logger

router = APIRouter(prefix="/ids", tags=["IDS Control"])


class IDSStatusResponse(CamelModel):
    """IDS status information"""
    enabled: bool
    mode: str
    ml_loaded: bool
    detector: str
    threshold: Optional[float] = None    # the stage-1 threshold in use right now
    capture_active: bool
    capture_error: Optional[str] = None
    packets_processed: int
    flows_analyzed: int
    active_flows: int
    anomalies_detected: int
    attacks_detected: int
    blocked_ips: int
    rule_hits: int = 0                    # behavioural-rule alerts since the IDS was turned on
    uptime_seconds: int
    alerts_not_stored: int = 0           # attack-storm incidents counted but not stored
    verdicts: Optional["VerdictSummary"] = None


class GuessRow(CamelModel):
    """Table 2 row: how many flagged flows stage 2 thought were this class."""
    label: str
    flows: int
    cancelled: bool = False              # "Benign": stage 2 cancelled the alarm


class RecentRow(CamelModel):
    """One class in the rolling-window live breakdown (CLI-style): its share right now."""
    label: str
    flows: int
    pct: float


class TrendPoint(CamelModel):
    """One point in the attack-% trend chart (t = epoch seconds, pct = attacks % of recent flows)."""
    t: int
    pct: float


class VerdictSummary(CamelModel):
    """Table 1 / Table 2 / final verdict since the IDS was turned on."""
    scored: int
    normal: int
    abnormal: int
    guesses: List[GuessRow] = []
    final_normal: int
    final_abnormal: int
    # rolling-window live breakdown (what the CLI printed each refresh)
    recent: List[RecentRow] = []
    recent_total: int = 0
    recent_abnormal_pct: float = 0.0
    trend: List[TrendPoint] = []   # attack-% history for the dashboard trend chart


IDSStatusResponse.model_rebuild()


class IDSControlRequest(CamelModel):
    """Turn the IDS on/off; optionally choose the mode."""
    enabled: bool
    mode: Optional[Literal["monitor", "protect"]] = None


@router.get("/status", response_model=IDSStatusResponse)
async def get_ids_status(current_user: User = Depends(get_current_user)):
    """Current IDS status"""
    return IDSStatusResponse(**get_ids_service().get_status())


@router.post("/control", response_model=IDSStatusResponse)
async def control_ids(request: IDSControlRequest, current_user: User = Depends(get_current_user)):
    """Turn the IDS ON or OFF (any signed-in user; its settings stay admin-only).

    ON = capture, detect, alert and email; OFF = stopped. The mode follows the
    Advanced Protection switch (Settings → Advanced Protection): OFF ⇒ "monitor"
    (detection only), ON ⇒ "protect" (detect and auto-block attackers). When the
    request does not name a mode the IDS uses the saved Advanced Protection choice.
    The choice is remembered: if the computer is shut down while the IDS is ON,
    it turns itself back on at the next start (services/autostart.py).
    """
    ids = get_ids_service()
    if request.enabled:
        try:
            if ids.enabled:
                # already running: match the saved Advanced Protection choice (or the request)
                await ids.reload_config()
                desired = request.mode or ids.config.default_mode.value
                if ids.mode.value != desired:
                    await ids.set_mode(desired)
                    await ids.broadcast_status()
            else:
                await ids.start(request.mode)   # None ⇒ start() uses the saved mode (reload_config)
                ids.started_by = {"name": current_user.full_name, "email": current_user.email,
                                  "phone": current_user.phone_number, "role": current_user.role.value}
                logger.info(f"IDS started by {current_user.email} (mode={ids.mode.value})")
                await remember_ids_state(True, ids.started_by)
        except CaptureUnavailable as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    else:
        if ids.enabled:
            await ids.stop()
            ids.started_by = None
            logger.info(f"IDS stopped by {current_user.email}")
        # also when it wasn't running (e.g. it could not restart after a reboot):
        # OFF means "don't turn it on at the next start"
        await remember_ids_state(False)
    return IDSStatusResponse(**ids.get_status())
