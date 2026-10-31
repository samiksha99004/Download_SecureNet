"""
SecureNet Backend — Main Application

FastAPI entry point: CORS, uniform error responses, route registration,
the authenticated live WebSocket, and (optionally) the built frontend.
"""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import auth, dashboard, events, health, ids, model, notifications, reports, settings_routes, support
from app.core.config import settings
from app.core.hardening import HardeningMiddleware, spa_csp
from app.db.base import AsyncSessionLocal, keep_awake, mark_activity, warm_up
from app.services import cache
from app.ml.ids_service import get_ids_service
from app.services.autostart import resume_after_restart
from app.services.notifier import get_notifier
from app.utils.logger import logger
from app.websocket.manager import manager

MAX_LIVE_CONNECTIONS = 100     # dashboards open at once (one browser tab = one connection)

ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    422: "VALIDATION_ERROR",
    429: "TOO_MANY_REQUESTS",
    500: "INTERNAL_ERROR",
    502: "BAD_GATEWAY",
    503: "SERVICE_UNAVAILABLE",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"{settings.APP_NAME} v{settings.APP_VERSION} starting (env={settings.ENVIRONMENT})")
    ids_service = get_ids_service()
    await ids_service.initialize()
    await get_notifier().start()
    # IDS was ON when SecureNet last stopped (e.g. computer shut down)? Turn it back on.
    resume = asyncio.create_task(resume_after_restart(), name="ids-resume")
    # open database connections now, prepare the dashboard answers before the first page,
    # and keep the cloud database awake while SecureNet is in use
    cache.set_primers([
        dashboard.cached_summary, dashboard.cached_protocols, dashboard.cached_top_sources,
        notifications.cached_feed, settings_routes.cached_detection_settings, support.cached_contact,
        reports.cached_daily_local, settings_routes.cached_all_settings, settings_routes.cached_whitelist,
        notifications.cached_recipients,
    ])
    prepare = asyncio.create_task(_prepare(), name="prepare-dashboard")
    awake = asyncio.create_task(
        keep_awake(lambda: ids_service.enabled or bool(manager.active_connections)), name="db-keep-awake")
    yield
    logger.info(f"{settings.APP_NAME} shutting down...")
    cache.set_primers([])
    for task in (resume, prepare, awake):
        task.cancel()
    await asyncio.gather(resume, prepare, awake, return_exceptions=True)
    await ids_service.stop()  # the saved ON/OFF choice is kept for the next start
    await get_notifier().stop()


async def _prepare() -> None:
    await warm_up()
    await cache.prime()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Network-Based Behavioural Intrusion Detection System",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# Added last = runs first: unknown hosts, foreign WebSocket origins and oversized bodies are
# refused before anything else runs; every answer gets the security headers.
_spa_dir = settings.resolve_path(settings.FRONTEND_DIST) if settings.FRONTEND_DIST else None
app.add_middleware(
    HardeningMiddleware,
    allowed_hosts=settings.allowed_hosts_list,
    allowed_origins=settings.cors_origins_list,
    spa_policy=spa_csp(_spa_dir / "index.html") if _spa_dir else None,
)


# ── Uniform error responses: {status, code, message, details?} ───────────────

def error_response(status_code: int, message: str, details=None, headers=None) -> JSONResponse:
    body = {"status": status_code, "code": ERROR_CODES.get(status_code, "ERROR"), "message": message}
    if details:
        body["details"] = details
    return JSONResponse(status_code=status_code, content=body, headers=headers)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return error_response(exc.status_code, message, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    details: dict = {}
    for error in exc.errors():
        loc = [str(part) for part in error.get("loc", ()) if part not in ("body", "query", "path")]
        field = ".".join(loc) or "request"
        msg = str(error.get("msg", "Invalid value")).removeprefix("Value error, ")
        details.setdefault(field, []).append(msg)
    first_field, first_msgs = next(iter(details.items()), ("request", ["Invalid request"]))
    message = first_msgs[0] if first_field == "request" else f"{first_field}: {first_msgs[0]}"
    return error_response(422, message, details)


@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(request: Request, exc: SQLAlchemyError):
    logger.error(f"Database error on {request.url.path}: {exc}")
    return error_response(500, "Something went wrong while saving or loading data. Please try again.")


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error on {request.url.path}: {exc}", exc_info=True)
    return error_response(500, str(exc) if settings.DEBUG else "Something went wrong. Please try again.")


# ── Routes ────────────────────────────────────────────────────────────────────

for router in (auth, events, dashboard, settings_routes, model, reports, ids, notifications, support):
    app.include_router(router.router, prefix="/api")
app.include_router(health.router)


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """Real-time stream (live_score / alert / system_status).

    Authenticate with the access token: ws://host/ws/live?token=<accessToken>
    """
    from app.api.dependencies import user_from_token

    token = websocket.query_params.get("token")
    mark_activity()
    async with AsyncSessionLocal() as db:
        user = await user_from_token(token, db)
    if user is None:
        # Accept first, then close with 1008: a close before the handshake reaches
        # the browser as a plain 1006 "connection failed", and the dashboard could
        # not tell an expired token (refresh it) from a network problem (retry).
        await websocket.accept()
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired session")
        return

    if len(manager.active_connections) >= MAX_LIVE_CONNECTIONS:
        await websocket.accept()
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER, reason="Too many live connections")
        return
    await manager.connect(websocket)
    try:
        await get_ids_service().broadcast_status()
        while True:
            message = await websocket.receive_json()
            if isinstance(message, dict) and message.get("type") == "ping":
                await websocket.send_json({"type": "pong", "timestamp": None, "payload": {}})
    except (WebSocketDisconnect, RuntimeError, ValueError):
        pass
    finally:
        manager.disconnect(websocket)


# ── Optional: serve the built frontend (Electron / single-port deployments) ──

_frontend_dist = settings.resolve_path(settings.FRONTEND_DIST) if settings.FRONTEND_DIST else None
if _frontend_dist and (_frontend_dist / "index.html").is_file():
    app.mount("/assets", StaticFiles(directory=_frontend_dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """Serve static files, falling back to index.html for client-side routes."""
        if full_path.startswith(("api/", "ws/")):
            return error_response(404, "Not Found")
        candidate = (_frontend_dist / full_path).resolve()
        if full_path and candidate.is_file() and Path(_frontend_dist) in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_frontend_dist / "index.html")
else:
    @app.get("/")
    async def root():
        return {"name": settings.APP_NAME, "version": settings.APP_VERSION, "status": "running"}
