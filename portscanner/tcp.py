"""
Async TCP connect scanner.

Uses asyncio with a semaphore-based concurrency gate.
No root privileges required — standard socket connections only.
"""

import asyncio
import time
from typing import Callable, Optional

from .models import PortResult, PortState


async def _scan_port(
    host: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
) -> PortResult:
    """Attempt a TCP connect to *host*:*port* and return a PortResult."""
    async with sem:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            latency = (time.monotonic() - t0) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortResult(
                port=port,
                protocol="tcp",
                state=PortState.OPEN,
                latency=round(latency, 2),
            )
        except asyncio.TimeoutError:
            return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)
        except ConnectionRefusedError:
            return PortResult(port=port, protocol="tcp", state=PortState.CLOSED)
        except OSError:
            # Network unreachable, host unreachable, etc.
            return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)


async def tcp_scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 500,
    inter_probe: float = 0.0,
    callback: Optional[Callable[[PortResult], None]] = None,
) -> list[PortResult]:
    """
    Scan *ports* on *host* using async TCP connect.

    Args:
        host:        Target IP or hostname.
        ports:       List of port numbers to scan.
        timeout:     Per-port connect timeout in seconds.
        concurrency: Maximum simultaneous connections (semaphore size).
        inter_probe: Delay (seconds) between launching each probe.
        callback:    Called with each PortResult as it completes.

    Returns:
        List of PortResult objects (one per port, in completion order).
    """
    sem = asyncio.Semaphore(concurrency)

    async def _probe(port: int) -> PortResult:
        result = await _scan_port(host, port, timeout, sem)
        if callback:
            callback(result)
        return result

    if inter_probe > 0:
        # Throttled launch — build tasks one by one with a small delay.
        tasks = []
        for port in ports:
            tasks.append(asyncio.create_task(_probe(port)))
            await asyncio.sleep(inter_probe)
        results = await asyncio.gather(*tasks)
    else:
        results = await asyncio.gather(*[_probe(p) for p in ports])

    return list(results)
