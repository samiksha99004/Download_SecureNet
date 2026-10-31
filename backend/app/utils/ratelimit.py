"""
SecureNet Backend — per-network-address rate limits

Sliding-window counters keyed by (bucket, client IP), on top of the per-account
limits (login lockout, OTP attempts, resend cooldown). They stop one machine
from guessing passwords/codes across many accounts or flooding inboxes with
code emails. Kept in memory: a restart clears them, which needs access to the
server itself, so it does not help an attacker.
"""

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from fastapi import HTTPException, Request, status

# bucket -> (max events, window in seconds, message)
LIMITS: Dict[str, Tuple[int, int, str]] = {
    "login-fail": (20, 15 * 60, "Too many sign-in attempts from this network."),
    "code-fail": (30, 15 * 60, "Too many wrong codes from this network."),
    "code-send": (15, 15 * 60, "Too many verification emails requested from this network."),
    "support": (20, 24 * 3600, "Too many messages sent from this network today."),
}


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: Tuple[str, str], window: int, now: float) -> Deque[float]:
        hits = self._hits[key]
        while hits and now - hits[0] >= window:
            hits.popleft()
        return hits

    def retry_after(self, bucket: str, ip: str) -> Optional[int]:
        """Seconds until another event is allowed, or None if allowed now."""
        limit, window, _ = LIMITS[bucket]
        now = time.monotonic()
        with self._lock:
            hits = self._prune((bucket, ip), window, now)
            if len(hits) >= limit:
                return int(window - (now - hits[0])) + 1
        return None

    def add(self, bucket: str, ip: str) -> None:
        with self._lock:
            self._hits[(bucket, ip)].append(time.monotonic())

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Optional[Request]) -> str:
    if request is None or request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def enforce(bucket: str, request: Optional[Request]) -> None:
    """Raise 429 with a plain message when this network address hit the limit."""
    wait = limiter.retry_after(bucket, client_ip(request))
    if wait is not None:
        minutes = max(1, (wait + 59) // 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"{LIMITS[bucket][2]} Please try again in {minutes} minute(s).",
        )


def record(bucket: str, request: Optional[Request]) -> None:
    limiter.add(bucket, client_ip(request))
