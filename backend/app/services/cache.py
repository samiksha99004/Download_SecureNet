"""
SecureNet — small in-memory cache for dashboard reads

The cloud database is ~300 ms per round trip away, so repeating the same
dashboard queries on every page and every 15-second refresh made SecureNet
slow. Answers are kept in memory:

  * "events:*" keys — dropped when an event is stored or its state changes
    (events_changed(), called by the IDS and the resolve / false-positive
    routes) and then re-loaded in the background straight away, so the next
    page already finds them ready;
  * "settings:*" keys — dropped when settings change (settings_changed());
  * an entry older than its TTL is still answered immediately while a fresh
    copy loads in the background (a second backend sharing the database is
    therefore at most one refresh behind);
  * requests that arrive together share one database load.

Loaders must open their own database session (they may run after the request
that started them has finished).
"""

import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, List, Tuple

from app.utils.logger import logger

Loader = Callable[[], Awaitable[Any]]
DEFAULT_TTL_SECONDS = 30
PRIME_DELAY_SECONDS = 0.3        # a burst of events triggers one background reload

_store: Dict[str, Tuple[int, float, Any]] = {}
_loading: Dict[str, "asyncio.Task[Any]"] = {}
_generation = 0
_primers: List[Loader] = []
_prime_task: "asyncio.Task[None] | None" = None


def invalidate(prefix: str = "") -> None:
    """Forget cached entries whose key starts with `prefix` ("" = everything)."""
    global _generation
    _generation += 1          # loads already running when this happens are not stored
    for key in [k for k in _store if k.startswith(prefix)]:
        del _store[key]


def events_changed() -> None:
    invalidate("events:")
    _prime_soon()


def settings_changed() -> None:
    invalidate("settings:")


def _load(key: str, loader: Loader, ttl: float) -> "asyncio.Task[Any]":
    """Start (or join) the one load of `key` that is in progress."""
    task = _loading.get(key)
    if task is not None and not task.done():
        return task
    generation = _generation

    async def run() -> Any:
        try:
            value = await loader()
            if generation == _generation:
                _store[key] = (generation, time.monotonic() + ttl, value)
            return value
        finally:
            _loading.pop(key, None)

    task = asyncio.ensure_future(run())
    _loading[key] = task
    return task


def _log_failure(task: "asyncio.Task[Any]") -> None:
    if not task.cancelled() and task.exception() is not None:
        logger.warning(f"Background cache refresh failed: {task.exception()}")


async def cached(key: str, loader: Loader, ttl: float = DEFAULT_TTL_SECONDS) -> Any:
    """Cached value for `key`; loads it when missing, refreshes it in the background when old."""
    hit = _store.get(key)
    if hit and hit[0] == _generation:
        if hit[1] <= time.monotonic():
            _load(key, loader, ttl).add_done_callback(_log_failure)   # serve now, refresh behind
        return hit[2]
    return await asyncio.shield(_load(key, loader, ttl))


# ── priming: load the dashboard answers before anyone asks ────────────────────

def set_primers(primers: List[Loader]) -> None:
    """Loaders run at startup and after every events change (set by main.py's lifespan)."""
    _primers[:] = primers


async def prime() -> None:
    results = await asyncio.gather(*(p() for p in _primers), return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            logger.warning(f"Preparing dashboard data failed: {result}")


def _prime_soon() -> None:
    global _prime_task
    if not _primers or (_prime_task is not None and not _prime_task.done()):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    async def later() -> None:
        await asyncio.sleep(PRIME_DELAY_SECONDS)
        await prime()

    _prime_task = loop.create_task(later())
