"""
SYN (half-open) scanner using scapy.

Requirements:
  - scapy installed  (pip install scapy)
  - root / administrator privileges
  - Windows: Npcap installed  (https://npcap.com)

Import of this module succeeds even when scapy is absent; calling syn_scan()
will raise ScanNotAvailableError in that case.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .models import PortResult, PortState


class ScanNotAvailableError(RuntimeError):
    """Raised when scapy or root privileges are unavailable."""


def _syn_port(host: str, port: int, timeout: float) -> PortResult:
    """
    Blocking SYN scan of a single port.
    Must be run in a thread, not the event loop.
    """
    from scapy.all import IP, TCP, sr1, conf  # type: ignore
    conf.verb = 0

    t0 = time.monotonic()
    pkt = IP(dst=host) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    latency = (time.monotonic() - t0) * 1000

    if resp is None:
        return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags & 0x12 == 0x12:  # SYN-ACK
            # Send RST to cleanly close the half-open connection
            rst = IP(dst=host) / TCP(dport=port, flags="R", seq=resp[TCP].ack)
            sr1(rst, timeout=1, verbose=0)
            return PortResult(
                port=port,
                protocol="tcp",
                state=PortState.OPEN,
                latency=round(latency, 2),
            )
        if flags & 0x14 == 0x14:  # RST-ACK
            return PortResult(port=port, protocol="tcp", state=PortState.CLOSED)

    return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)


async def syn_scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    callback: Optional[Callable[[PortResult], None]] = None,
) -> list[PortResult]:
    """
    SYN scan *ports* on *host*.

    Raises ScanNotAvailableError if scapy is missing or process lacks root.
    """
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        raise ScanNotAvailableError(
            "scapy is not installed. Run: pip install scapy"
        )

    from .utils import is_root
    if not is_root():
        raise ScanNotAvailableError(
            "SYN scan requires root/administrator privileges."
        )

    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(concurrency)

    async def _probe(port: int) -> PortResult:
        async with sem:
            result = await loop.run_in_executor(
                None, _syn_port, host, port, timeout
            )
        if callback:
            callback(result)
        return result

    results = await asyncio.gather(*[_probe(p) for p in ports])
    return list(results)
