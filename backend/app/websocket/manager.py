"""
SecureNet Backend — WebSocket Connection Manager

Broadcasts real-time messages to authenticated dashboard clients:
  live_score     – anomaly score of a scored flow (throttled)
  alert          – a stored security event
  system_status  – IDS state changes / heartbeat
"""

import asyncio
from typing import Dict, Optional

from fastapi import WebSocket

from app.utils.logger import logger
from app.utils.timeutil import to_iso_z, utcnow

SEND_TIMEOUT_SECONDS = 5


class ConnectionManager:
    """Manages active WebSocket connections, each tagged with the signed-in account (user id)
    so per-account alerts reach only their owner."""

    def __init__(self) -> None:
        # connection -> owner user id (str). None = unknown (very old client).
        self.active_connections: Dict[WebSocket, Optional[str]] = {}

    async def connect(self, websocket: WebSocket, user_id: Optional[str] = None) -> None:
        await websocket.accept()
        self.active_connections[websocket] = str(user_id) if user_id else None
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            del self.active_connections[websocket]
            logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def _send(self, connection: WebSocket, message: dict) -> bool:
        try:
            await asyncio.wait_for(connection.send_json(message), timeout=SEND_TIMEOUT_SECONDS)
            return True
        except Exception:
            return False

    async def broadcast(self, message: dict, owner_id: Optional[str] = None) -> None:
        # owner_id set => deliver only to that account's connections (per-account alerts);
        # None => everyone (live score, system status — the live capture is the same for all).
        if owner_id is not None:
            owner_id = str(owner_id)
            connections = [c for c, uid in self.active_connections.items() if uid == owner_id]
        else:
            connections = list(self.active_connections)
        if not connections:
            return
        results = await asyncio.gather(*(self._send(c, message) for c in connections))
        for connection, ok in zip(connections, results):
            if not ok:
                self.disconnect(connection)

    async def _typed(self, msg_type: str, payload: dict, owner_id: Optional[str] = None) -> None:
        await self.broadcast({"type": msg_type, "timestamp": to_iso_z(utcnow()), "payload": payload}, owner_id)

    async def send_live_score(self, payload: dict) -> None:
        await self._typed("live_score", payload)

    async def send_alert(self, payload: dict, owner_id: Optional[str] = None) -> None:
        """A stored-event / attack alert. When `owner_id` is given it reaches only that account."""
        await self._typed("alert", payload, owner_id)

    async def send_system_status(self, payload: dict) -> None:
        await self._typed("system_status", payload)


# Global connection manager instance
manager = ConnectionManager()
