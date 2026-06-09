"""
OS detection via TTL analysis (ping-based, no root required).

TTL heuristic (accounts for up to ~5 hops of erosion):
  TTL  1–64   → Linux / Unix / macOS / Android
  TTL 65–128  → Windows
  TTL 129–255 → Network device (Cisco, Juniper, etc.)

Confidence is always "low" because NAT, tunnels, and routing can erode
the TTL arbitrarily.  A second, scapy-based TCP fingerprint pass (future
work) would raise confidence to "medium".
"""

import asyncio
import re
import subprocess
import sys
from typing import Optional

from .models import OSGuess


_TTL_RE = re.compile(r"ttl[=\s]+(\d+)", re.IGNORECASE)


def _os_from_ttl(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    return "Network Device (Cisco/Juniper)"


def _parse_ping_output(text: str) -> Optional[int]:
    m = _TTL_RE.search(text)
    return int(m.group(1)) if m else None


async def detect_os(host: str, timeout: float = 5.0) -> Optional[OSGuess]:
    """
    Ping *host* once and infer the OS family from the TTL in the reply.

    Returns an OSGuess or None if the host didn't respond.
    """
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        # Run blocking subprocess in a thread to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        result: subprocess.CompletedProcess = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 2,
            ),
        )
        output = result.stdout + result.stderr
        ttl = _parse_ping_output(output)
        if ttl is not None:
            return OSGuess(
                family=_os_from_ttl(ttl),
                ttl=ttl,
                confidence="low",
                method="ttl",
            )
    except Exception:
        pass
    return None
