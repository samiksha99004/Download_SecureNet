"""
SecureNet Backend — Security Events Routes

Security event queries (filter / sort / paginate), export, and state changes.
"""

import asyncio
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, require_admin
from app.db.base import AsyncSessionLocal, get_db
from app.models.security_event import EventState, SecurityEvent
from app.models.user import User
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.security import SecurityEventResponse
from app.services import exporters
from app.services.cache import cached, events_changed
from app.services.event_query import EventFilters, combine, sort_clause
from app.utils.logger import logger
from app.utils.timeutil import utcnow

router = APIRouter(prefix="/events", tags=["Security Events"])

EXPORT_LIMIT = 50_000
MAX_PAGE = 1_000_000  # far beyond any real history; stops offsets the database can't hold


def convert_event_to_response(event: SecurityEvent) -> SecurityEventResponse:
    return SecurityEventResponse.model_validate(event)


def _filters(
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),
    attackType: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
) -> EventFilters:
    return EventFilters(search, severity, state, mode, attackType, protocol, from_date, to_date)


@router.get("", response_model=PaginatedResponse[SecurityEventResponse])
async def get_events(
    page: int = Query(1, ge=1, le=MAX_PAGE),
    pageSize: int = Query(20, ge=1, le=100),
    sortBy: str = Query("timestamp"),
    sortOrder: str = Query("desc", pattern="^(asc|desc)$"),
    filters: EventFilters = Depends(_filters),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated list of security events with filtering and sorting (cached until events change)."""
    where = combine(filters.conditions())          # validates the filters (400 on bad values)
    order = sort_clause(sortBy, sortOrder)
    key = "events:list:" + "|".join(map(str, (page, pageSize, sortBy, sortOrder, *vars(filters).values())))

    async def load() -> PaginatedResponse[SecurityEventResponse]:
        async with AsyncSessionLocal() as db:
            count_q = select(func.count()).select_from(SecurityEvent)
            query = select(SecurityEvent)
            if where is not None:
                count_q = count_q.where(where)
                query = query.where(where)
            total = (await db.execute(count_q)).scalar() or 0
            query = query.order_by(order, SecurityEvent.id).limit(pageSize).offset((page - 1) * pageSize)
            events = (await db.execute(query)).scalars().all()
        return PaginatedResponse[SecurityEventResponse](
            data=[convert_event_to_response(e) for e in events],
            total=total,
            page=page,
            page_size=pageSize,
            total_pages=(total + pageSize - 1) // pageSize,
        )

    return await cached(key, load, ttl=300)


@router.get("/export")
async def export_events(
    format: str = Query("csv", pattern="^(csv|pdf|json)$"),
    sortBy: str = Query("timestamp"),
    sortOrder: str = Query("desc", pattern="^(asc|desc)$"),
    filters: EventFilters = Depends(_filters),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export the events matching the current filters (max 50,000 rows)."""
    query = select(SecurityEvent)
    if (where := combine(filters.conditions())) is not None:
        query = query.where(where)
    query = query.order_by(sort_clause(sortBy, sortOrder)).limit(EXPORT_LIMIT)
    events = (await db.execute(query)).scalars().all()

    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    if format == "csv":
        body, media = await asyncio.to_thread(exporters.to_csv, events), "text/csv"
    elif format == "json":
        body, media = await asyncio.to_thread(exporters.to_json, events), "application/json"
    else:
        body = await asyncio.to_thread(exporters.to_pdf, events, "SecureNet — Security Events Export",
                                       f"Exported {stamp} UTC by {current_user.email}")
        media = "application/pdf"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="securenet-events-{stamp}.{format}"'},
    )


async def _get_event(db: AsyncSession, event_id: str) -> SecurityEvent:
    try:
        event_uuid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid event ID format")
    event = (await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_uuid))).scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_event_by_id(
    event_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single security event by ID"""
    return convert_event_to_response(await _get_event(db, event_id))


async def _set_state(db: AsyncSession, event_id: str, state: EventState, user: User) -> None:
    event = await _get_event(db, event_id)
    now = utcnow()
    event.state = state
    event.resolved_at = now
    event.resolved_by = user.id
    event.updated_at = now
    await db.commit()
    events_changed()
    logger.info(f"Event {event_id} → {state.value} by {user.email}")


@router.post("/{event_id}/resolve", response_model=MessageResponse)
async def resolve_event(
    event_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Mark an event as resolved (admin)."""
    await _set_state(db, event_id, EventState.RESOLVED, current_user)
    return MessageResponse(message="Event marked as resolved")


@router.post("/{event_id}/false-positive", response_model=MessageResponse)
async def mark_false_positive(
    event_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Mark an event as a false positive (admin)."""
    await _set_state(db, event_id, EventState.FALSE_POSITIVE, current_user)
    return MessageResponse(message="Event marked as false positive")
