"""
SecureNet Backend — WebSocket Connection Manager

Broadcasts real-time messages to authenticated dashboard clients:
  live_score     – anomaly score of a scored flow (throttled)
  alert          – a stored security event
  system_status  – IDS state changes / heartbeat
"""

import asyncio
from typing import Set

from fastapi import WebSocket

from app.utils.logger import logger
from app.utils.timeutil import to_iso_z, utcnow

SEND_TIMEOUT_SECONDS = 5


class ConnectionManager:
    """Manages active WebSocket connections"""

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.discard(websocket)
            logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def _send(self, connection: WebSocket, message: dict) -> bool:
        try:
            await asyncio.wait_for(connection.send_json(message), timeout=SEND_TIMEOUT_SECONDS)
            return True
        except Exception:
            return False

    async def broadcast(self, message: dict) -> None:
        connections = list(self.active_connections)
        if not connections:
            return
        results = await asyncio.gather(*(self._send(c, message) for c in connections))
        for connection, ok in zip(connections, results):
            if not ok:
                self.disconnect(connection)

    async def _typed(self, msg_type: str, payload: dict) -> None:
        await self.broadcast({"type": msg_type, "timestamp": to_iso_z(utcnow()), "payload": payload})

    async def send_live_score(self, payload: dict) -> None:
        await self._typed("live_score", payload)

    async def send_alert(self, payload: dict) -> None:
        await self._typed("alert", payload)

    async def send_system_status(self, payload: dict) -> None:
        await self._typed("system_status", payload)


# Global connection manager instance
manager = ConnectionManager()
