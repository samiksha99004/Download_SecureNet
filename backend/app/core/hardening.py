"""
SecureNet — protecting the app itself

SecureNet watches the network, so it is itself a target. These ASGI middlewares
close the ways a hostile web page or a flood could attack it:

* **Host check** — only requests addressed to this computer (localhost / 127.0.0.1 /
  ::1 or ALLOWED_HOSTS) are answered. Stops DNS-rebinding: a malicious site pointing
  its own name at 127.0.0.1 to read the local API from a victim's browser.
* **Origin check for the WebSocket** — browsers don't apply CORS to WebSockets, so a
  page from another origin is refused explicitly.
* **Request size limit** — bodies over MAX_REQUEST_BYTES are refused (413) before they
  are read into memory.
* **Security headers** — no framing (clickjacking), no MIME sniffing, no referrer,
  responses with account data are never cached, and a strict Content-Security-Policy.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

from app.utils.logger import logger

MAX_REQUEST_BYTES = 1_000_000       # largest real request (a support message) is ~6 KB

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

COMMON_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
]


def _host_only(value: str) -> str:
    """'localhost:8000' → 'localhost', '[::1]:8000' → '::1' (lower case)."""
    value = value.strip().lower()
    if value.startswith("["):
        return value[1:value.find("]")] if "]" in value else value
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def _json_error(status: int, code: str, message: str) -> bytes:
    return json.dumps({"status": status, "code": code, "message": message}).encode()


async def _send_error(send, status: int, code: str, message: str) -> None:
    body = _json_error(status, code, message)
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                            *COMMON_HEADERS, (b"content-security-policy", API_CSP.encode()),
                            (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": body})


def spa_csp(index_html: Optional[Path], api_origins: Iterable[str] = ()) -> str:
    """CSP for the built dashboard: only its own files, its inline boot scripts (by hash),
    Google Fonts and the local API / live feed."""
    hashes: List[str] = []
    if index_html is not None and index_html.is_file():
        html = index_html.read_text(encoding="utf-8")
        for script in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.S | re.I):
            digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
            hashes.append(f"'sha256-{digest}'")
        # inline handlers such as the fonts' onload="this.media='all'" (allowed by exact hash only)
        handlers = re.findall(r"\son[a-z]+=\"([^\"]*)\"", html, flags=re.I)
        for handler in handlers:
            digest = base64.b64encode(hashlib.sha256(handler.encode("utf-8")).digest()).decode()
            hashes.append(f"'sha256-{digest}'")
        if handlers:
            hashes.insert(0, "'unsafe-hashes'")
    connect = ["'self'", "ws://localhost:*", "ws://127.0.0.1:*", "http://localhost:*", "http://127.0.0.1:*",
               *api_origins]
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' " + " ".join(hashes),
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' data: https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "connect-src " + " ".join(connect),
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ])


class HardeningMiddleware:
    """Host check, WebSocket origin check, body size limit and security headers in one pass."""

    def __init__(self, app, allowed_hosts: Iterable[str], allowed_origins: Iterable[str],
                 spa_policy: Optional[str] = None, max_body: int = MAX_REQUEST_BYTES) -> None:
        self.app = app
        hosts = {_host_only(h) for h in allowed_hosts if h.strip()}
        self.any_host = "*" in hosts
        self.allowed_hosts = hosts
        self.allowed_origins = {o.strip().rstrip("/").lower() for o in allowed_origins if o.strip()}
        self.spa_policy = spa_policy
        self.max_body = max_body

    def _header(self, scope, name: bytes) -> Optional[str]:
        for key, value in scope.get("headers") or []:
            if key == name:
                return value.decode("latin-1")
        return None

    def _host_ok(self, scope) -> bool:
        if self.any_host:
            return True
        host = self._header(scope, b"host")
        return host is not None and _host_only(host) in self.allowed_hosts

    def _origin_ok(self, scope) -> bool:
        origin = self._header(scope, b"origin")
        if origin is None:          # not a browser (e.g. tests, scripts on this computer)
            return True
        origin = origin.strip().rstrip("/").lower()
        if origin in self.allowed_origins:
            return True
        # the dashboard served by this backend itself (Electron / single port)
        parts = urlsplit(origin)
        host = self._header(scope, b"host")
        return bool(host) and parts.netloc == host.strip().lower()

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        if not self._host_ok(scope):
            logger.warning(f"Refused request for unknown host {self._header(scope, b'host')!r} "
                           f"({scope.get('path')}) — possible DNS rebinding")
            if kind == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            return await _send_error(send, 400, "BAD_REQUEST", "Unknown host")

        if kind == "websocket":
            if not self._origin_ok(scope):
                logger.warning(f"Refused live feed from foreign origin {self._header(scope, b'origin')!r}")
                await send({"type": "websocket.close", "code": 1008})
                return
            return await self.app(scope, receive, send)

        length = self._header(scope, b"content-length")
        if length is not None:
            try:
                too_big = int(length) > self.max_body
            except ValueError:
                return await _send_error(send, 400, "BAD_REQUEST", "Invalid Content-Length")
            if too_big:
                return await _send_error(send, 413, "PAYLOAD_TOO_LARGE", "The request is too large.")

        else:
            # no length given (chunked upload): read up to the limit here, then replay it
            chunks, size, more = [], 0, True
            while more:
                message = await receive()
                if message["type"] != "http.request":
                    return              # client went away
                chunks.append(message.get("body", b""))
                size += len(chunks[-1])
                if size > self.max_body:
                    return await _send_error(send, 413, "PAYLOAD_TOO_LARGE", "The request is too large.")
                more = message.get("more_body", False)
            body, replayed = b"".join(chunks), False

            async def replay():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            receive = replay

        path = scope.get("path", "")
        # "/" is the dashboard itself when a built frontend is served (Electron opens it there)
        is_api = path.startswith("/api") or path == "/health" or (path == "/" and not self.spa_policy)
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])]
                present = {k.lower() for k, _ in headers}
                headers += [h for h in COMMON_HEADERS if h[0] not in present]
                policy = API_CSP if is_api or not self.spa_policy else self.spa_policy
                if b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", policy.encode()))
                if is_api and b"cache-control" not in present:
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
