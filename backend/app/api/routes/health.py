"""
SecureNet Backend — Health Check Route
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.base import get_db
from app.ml.ids_service import get_ids_service

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Database connectivity plus IDS / model state.

    Overall status is "ok" whenever the database is reachable — running
    without a model is a supported configuration, not a fault.
    """
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    ids_status = get_ids_service().get_status()
    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "database": db_status,
        "ml": "loaded" if ids_status["ml_loaded"] else "not_loaded",
        "detector": ids_status["detector"],
        "ids": "running" if ids_status["enabled"] else "stopped",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }
