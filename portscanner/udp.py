"""
UDP scanner using scapy.

Requirements:
  - scapy installed  (pip install scapy)
  - root / administrator privileges
  - Windows: Npcap installed  (https://npcap.com)

UDP scanning is inherently slow and ambiguous.
  - No response     → "open|filtered"  (packet may have been dropped)
  - ICMP port-unreachable (type 3, code 3) → "closed"
  - ICMP admin-prohibited (type 3, code 1/2/9/10/13) → "filtered"
  - UDP response    → "open"
"""

import asyncio
import time
from typing import Callable, Optional

from .models import PortResult, PortState
from .syn import ScanNotAvailableError


def _udp_port(host: str, port: int, timeout: float) -> PortResult:
    """Blocking UDP probe of a single port."""
    from scapy.all import IP, UDP, ICMP, sr1, conf  # type: ignore
    conf.verb = 0

    t0 = time.monotonic()
    pkt = IP(dst=host) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    latency = (time.monotonic() - t0) * 1000

    if resp is None:
        return PortResult(
            port=port, protocol="udp", state=PortState.OPEN_FILTERED
        )

    if resp.haslayer(UDP):
        return PortResult(
            port=port, protocol="udp", state=PortState.OPEN, latency=round(latency, 2)
        )

    if resp.haslayer(ICMP):
        icmp_type = int(resp[ICMP].type)
        icmp_code = int(resp[ICMP].code)
        if icmp_type == 3:
            if icmp_code == 3:
                return PortResult(port=port, protocol="udp", state=PortState.CLOSED)
            if icmp_code in (1, 2, 9, 10, 13):
                return PortResult(port=port, protocol="udp", state=PortState.FILTERED)

    return PortResult(port=port, protocol="udp", state=PortState.OPEN_FILTERED)


async def udp_scan(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    concurrency: int = 50,
    callback: Optional[Callable[[PortResult], None]] = None,
) -> list[PortResult]:
    """
    UDP scan *ports* on *host*.

    Note: UDP scanning is slower than TCP; use a shorter port list.
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
            "UDP scan requires root/administrator privileges."
        )

    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(concurrency)

    async def _probe(port: int) -> PortResult:
        async with sem:
            result = await loop.run_in_executor(
                None, _udp_port, host, port, timeout
            )
        if callback:
            callback(result)
        return result

    results = await asyncio.gather(*[_probe(p) for p in ports])
    return list(results)
