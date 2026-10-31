"""
SecureNet Backend — Database Base Configuration

The cloud database is far away (~300 ms per round trip from India to Neon
us-east-2) and a new connection costs ~5 round trips, so:
  * connections are opened at startup (warm_up) instead of on the first page;
  * a connection is replaced only when it sat idle for 4 minutes (Neon closes
    idle ones when its compute suspends after 5 minutes) — busy connections
    are kept, instead of reconnecting every 4 minutes;
  * while SecureNet is in use (IDS on, dashboard open or a request in the last
    5 minutes) the pooled connections are pinged every 2 minutes, so Neon never
    suspends and nobody waits for its ~5 s cold start. When nobody uses it,
    the pings stop and Neon may sleep (no compute used).
"""

import asyncio
import time

from sqlalchemy import event, exc, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

from app.core.config import settings

IDLE_REPLACE_SECONDS = 240
KEEPALIVE_SECONDS = 120
ACTIVE_WINDOW_SECONDS = 300
WARM_CONNECTIONS = 4

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
_engine_kwargs = {"echo": settings.DEBUG}
if not _is_sqlite:
    # SQLite (used by the test-suite) does not accept queue-pool sizing.
    # No "pre-ping": it would add a round trip to every request.
    _engine_kwargs.update(
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=False,
        pool_recycle=3600,
    )

# Create async engine
engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)

_last_activity = 0.0


def mark_activity() -> None:
    """A request used the database (keeps the keep-awake pings running)."""
    global _last_activity
    _last_activity = time.monotonic()


if not _is_sqlite:
    @event.listens_for(engine.sync_engine, "checkin")
    def _remember_last_use(dbapi_connection, record):
        record.info["last_used"] = time.monotonic()

    @event.listens_for(engine.sync_engine, "checkout")
    def _replace_idle_connection(dbapi_connection, record, proxy):
        last = record.info.get("last_used")
        if last is not None and time.monotonic() - last > IDLE_REPLACE_SECONDS:
            # probably closed by the server meanwhile: the pool opens a fresh one
            raise exc.DisconnectionError("idle connection replaced")


async def warm_up(connections: int = WARM_CONNECTIONS) -> None:
    """Open (or refresh) a few pooled connections in parallel and teach each one
    SecureNet's column types: the first query that returns a custom type (role,
    severity, ...) on a connection costs ~3 s of lookups against the far-away
    database, so it is done here instead of on somebody's first page."""
    from sqlalchemy import select

    from app.models.security_event import SecurityEvent
    from app.models.settings import DetectionSettings
    from app.models.user import User

    async def ping() -> None:
        async with AsyncSessionLocal() as session:
            for model in (User, SecurityEvent, DetectionSettings):
                await session.execute(select(model).limit(1))

    await asyncio.gather(*(ping() for _ in range(connections)), return_exceptions=True)


async def keep_awake(in_use) -> None:
    """Background task: ping the database every KEEPALIVE_SECONDS while `in_use()` or
    a request came in during the last ACTIVE_WINDOW_SECONDS."""
    if _is_sqlite:
        return
    await warm_up()
    while True:
        await asyncio.sleep(KEEPALIVE_SECONDS)
        if in_use() or time.monotonic() - _last_activity < ACTIVE_WINDOW_SECONDS:
            await warm_up()

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Base class for all models
Base = declarative_base()


async def get_db():
    """Dependency for getting async database sessions"""
    mark_activity()
    async with AsyncSessionLocal() as session:
        yield session
