"""
Async banner grabbing and service/version fingerprinting.

Strategy per service:
  - Read-first  (SSH, FTP, SMTP, POP3, MySQL, VNC): connect and immediately read.
  - Probe-first (HTTP, Redis, IMAP): send a probe, then read.
  - TLS ports   (443, 465, 636, 993, 995, 8443, …): wrap in SSL before probe/read.
"""

import asyncio
import ssl
from typing import Optional

from .models import PortResult, PortState
from .services import (
    SSL_PORTS,
    detect_version,
    get_probe,
    get_service_name,
)

# Maximum bytes to read per banner
_MAX_BANNER = 1024


async def grab_banner(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> tuple[str, str, str]:
    """
    Connect to *host*:*port*, send any required probe, and read the banner.

    Returns:
        (banner, service, version)
        All three may be empty strings if the attempt fails or times out.
    """
    service = get_service_name(port)
    probe = get_probe(service)  # None = read-first; b"..." = send first
    use_tls = port in SSL_PORTS

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

        # Send probe if required
        if probe:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read banner
        try:
            raw = await asyncio.wait_for(reader.read(_MAX_BANNER), timeout=timeout)
            banner = raw.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            banner = ""

        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    except Exception:
        return "", service, ""

    # Version detection
    det_service, det_version = detect_version(banner) if banner else ("", "")
    final_service = det_service or service
    return banner[:512], final_service, det_version


async def enrich_results(
    host: str,
    results: list[PortResult],
    timeout: float = 3.0,
    concurrency: int = 50,
) -> None:
    """
    In-place banner enrichment for a list of open TCP PortResults.

    Modifies each result's .banner, .service, and .version fields.
    """
    open_tcp = [r for r in results if r.state == PortState.OPEN and r.protocol == "tcp"]
    if not open_tcp:
        return

    sem = asyncio.Semaphore(concurrency)

    async def _enrich(result: PortResult) -> None:
        async with sem:
            banner, service, version = await grab_banner(host, result.port, timeout)
        result.banner  = banner
        result.service = service or result.service
        result.version = version

    await asyncio.gather(*[_enrich(r) for r in open_tcp])
