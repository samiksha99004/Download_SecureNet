"""
SecureNet — Protection mode (automatic IP blocking)

Adds a temporary inbound block rule for an offending source IP:
  * Windows : netsh advfirewall   (needs an elevated/Administrator backend)
  * Linux   : iptables            (needs root / CAP_NET_ADMIN)

Rules are tracked in memory, removed when they expire, and all removed when
the IDS stops, so no stale firewall rules are left behind. Loopback,
link-local, multicast and this host's own addresses are never blocked.
"""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import socket
import subprocess
import time
from typing import Dict, Tuple

from app.core.config import settings
from app.utils.logger import logger

RULE_PREFIX = "SecureNet_Block_"


def _own_addresses() -> set[str]:
    """Every IP this computer has — these must NEVER be blocked, or the IDS would cut off
    its own host. psutil is the primary source; a socket lookup is a fallback so the host's
    own address is still protected even if psutil is unavailable. Loopback always included."""
    addrs: set[str] = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        import psutil
        for iface in psutil.net_if_addrs().values():
            for a in iface:
                if a.address:
                    addrs.add(a.address.split("%")[0])
    except Exception as exc:
        logger.warning(f"Could not enumerate own addresses via psutil: {exc}")
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            addrs.add(info[4][0].split("%")[0])
        addrs.add(socket.gethostbyname(host))
    except Exception:
        pass
    return addrs


def _config_never_block() -> set[str]:
    raw = getattr(settings, "PROTECTION_NEVER_BLOCK", "") or ""
    return {p.strip() for p in raw.split(",") if p.strip()}


def _run(cmd: list[str]) -> Tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output.strip()


class FirewallBlocker:
    def __init__(self) -> None:
        self.system = platform.system()
        self.blocked: Dict[str, float] = {}  # ip -> expiry (epoch seconds)
        self._lock = asyncio.Lock()
        self._safe: set[str] = set()         # this host's own IPs + config never-block (cached)
        self._safe_at: float = 0.0

    @property
    def supported(self) -> bool:
        return self.system in ("Windows", "Linux")

    def safe_addresses(self) -> set[str]:
        """This host's own IPs (+ the configured never-block list), refreshed at most once a minute
        so `is_protected` can run on every flow without re-scanning the interfaces each time."""
        now = time.time()
        if not self._safe or now - self._safe_at > 60:
            self._safe = _own_addresses() | _config_never_block()
            self._safe_at = now
        return self._safe

    def is_protected(self, ip: str) -> bool:
        """Addresses that must NEVER be blocked: loopback/link-local/multicast, this PC's own
        IPs, and anything in PROTECTION_NEVER_BLOCK. (The attacking VM is not among these, so it
        is still blocked; the host itself can never be cut off.)"""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return True
        return ip in self.safe_addresses()

    def _block_cmd(self, ip: str) -> list[str]:
        if self.system == "Windows":
            return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}{ip}",
                    "dir=in", "action=block", f"remoteip={ip}"]
        return ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"{RULE_PREFIX}{ip}"]

    def _unblock_cmd(self, ip: str) -> list[str]:
        if self.system == "Windows":
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}{ip}"]
        return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"{RULE_PREFIX}{ip}"]

    async def block(self, ip: str, duration_seconds: int, max_blocked: int) -> Tuple[bool, str]:
        """Block `ip`. Returns (blocked, human-readable reason)."""
        if not self.supported:
            return False, f"Automatic blocking is not supported on {self.system}"
        if self.is_protected(ip):
            return False, f"{ip} is a protected address (loopback/local/this host)"
        async with self._lock:
            if ip in self.blocked:
                self.blocked[ip] = time.time() + duration_seconds
                return True, f"{ip} already blocked (block extended)"
            if len(self.blocked) >= max_blocked:
                return False, f"Block limit reached ({max_blocked} IPs)"
            ok, output = await asyncio.to_thread(_run, self._block_cmd(str(ipaddress.ip_address(ip))))
            if not ok:
                logger.warning(f"Failed to block {ip}: {output}")
                return False, "Firewall command failed (backend must run as Administrator/root)"
            self.blocked[ip] = time.time() + duration_seconds
            logger.info(f"Blocked {ip} for {duration_seconds}s")
            return True, f"Blocked {ip} for {duration_seconds}s"

    async def unblock(self, ip: str) -> None:
        async with self._lock:
            if self.blocked.pop(ip, None) is None:
                return
        ok, output = await asyncio.to_thread(_run, self._unblock_cmd(ip))
        if ok:
            logger.info(f"Unblocked {ip}")
        else:
            logger.warning(f"Failed to unblock {ip}: {output}")

    async def unblock_expired(self) -> None:
        now = time.time()
        for ip in [ip for ip, expiry in self.blocked.items() if expiry <= now]:
            await self.unblock(ip)

    async def unblock_all(self) -> None:
        for ip in list(self.blocked):
            await self.unblock(ip)
