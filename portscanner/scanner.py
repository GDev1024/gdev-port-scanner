"""
ScanEngine — the central orchestrator.

Coordinates target expansion, TCP/SYN/UDP scanning, banner grabbing,
and OS detection into a single ScanResult.
"""

import asyncio
from datetime import datetime
from typing import Callable, Optional

from .banner import enrich_results
from .models import HostResult, PortResult, PortState, ScanResult
from .os_detect import detect_os
from .services import get_service_name
from .tcp import tcp_scan
from .timing import TimingProfile, get_timing
from .utils import expand_targets


class ScanEngine:
    """
    High-level scan coordinator.

    Example::

        engine = ScanEngine()
        result = asyncio.run(engine.scan(
            targets=["192.168.1.1"],
            ports=list(range(1, 1001)),
            scan_type="tcp",
            timing=3,
            service_detection=True,
            os_detection=True,
        ))
    """

    def __init__(self, verbose: bool = False, no_ping: bool = False) -> None:
        self.verbose  = verbose
        self.no_ping  = no_ping
        self._on_port: Optional[Callable[[str, PortResult], None]] = None

    def on_port_found(self, callback: Callable[[str, PortResult], None]) -> None:
        """Register a callback invoked for every completed port result."""
        self._on_port = callback

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        targets: list[str],
        ports: list[int],
        scan_type: str = "tcp",
        timing: int = 3,
        service_detection: bool = False,
        os_detection: bool = False,
        progress_callback: Optional[Callable[[], None]] = None,
    ) -> ScanResult:
        """
        Scan *targets* on *ports*.

        Args:
            targets:           Raw target strings (IP, hostname, CIDR).
            ports:             Sorted list of port numbers.
            scan_type:         "tcp" | "syn" | "udp"
            timing:            0–5 timing template index.
            service_detection: Grab banners and fingerprint services.
            os_detection:      Attempt OS detection via TTL.
            progress_callback: Called after each port completes (for UI updates).

        Returns:
            A ScanResult containing one HostResult per resolved host.
        """
        profile = get_timing(timing)
        result = ScanResult(
            scan_type  = scan_type,
            timing     = str(timing),
            scan_start = datetime.now(),
        )

        # Expand all targets into (ip, hostname) pairs
        host_pairs: list[tuple[str, str, str]] = []  # (original, ip, hostname)
        for target in targets:
            try:
                for ip, hostname in expand_targets(target):
                    host_pairs.append((target, ip, hostname))
            except ValueError as exc:
                # Non-fatal: report and continue
                from .output import console
                console.print(f"[yellow]Warning:[/yellow] {exc}")

        # Scan each host
        tasks = [
            self._scan_host(
                original     = orig,
                ip           = ip,
                hostname     = hostname,
                ports        = ports,
                scan_type    = scan_type,
                profile      = profile,
                svc_detect   = service_detection,
                os_detect    = os_detection,
                progress_cb  = progress_callback,
            )
            for orig, ip, hostname in host_pairs
        ]
        host_results = await asyncio.gather(*tasks)
        result.hosts    = list(host_results)
        result.scan_end = datetime.now()
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _scan_host(
        self,
        original: str,
        ip: str,
        hostname: str,
        ports: list[int],
        scan_type: str,
        profile: TimingProfile,
        svc_detect: bool,
        os_detect: bool,
        progress_cb: Optional[Callable[[], None]],
    ) -> HostResult:
        host = HostResult(
            target     = original,
            ip         = ip,
            hostname   = hostname,
            scan_start = datetime.now(),
        )

        # --- Port scanning ---
        def _cb(result: PortResult) -> None:
            if self.verbose or result.state == PortState.OPEN:
                if self._on_port:
                    self._on_port(ip, result)
            if progress_cb:
                progress_cb()

        if scan_type == "tcp":
            port_results = await tcp_scan(
                host        = ip,
                ports       = ports,
                timeout     = profile.connect_timeout,
                concurrency = profile.concurrency,
                inter_probe = profile.inter_probe,
                callback    = _cb,
            )
        elif scan_type == "syn":
            from .syn import syn_scan, ScanNotAvailableError
            try:
                port_results = await syn_scan(
                    host        = ip,
                    ports       = ports,
                    timeout     = profile.connect_timeout,
                    concurrency = min(profile.concurrency, 200),
                    callback    = _cb,
                )
            except ScanNotAvailableError as exc:
                from .output import console
                console.print(f"[red]SYN scan unavailable:[/red] {exc}  Falling back to TCP.")
                port_results = await tcp_scan(
                    host        = ip,
                    ports       = ports,
                    timeout     = profile.connect_timeout,
                    concurrency = profile.concurrency,
                    callback    = _cb,
                )
        elif scan_type == "udp":
            from .udp import udp_scan, ScanNotAvailableError
            try:
                port_results = await udp_scan(
                    host        = ip,
                    ports       = ports,
                    timeout     = profile.connect_timeout * 2,
                    concurrency = min(profile.concurrency, 50),
                    callback    = _cb,
                )
            except ScanNotAvailableError as exc:
                from .output import console
                console.print(f"[red]UDP scan unavailable:[/red] {exc}")
                port_results = []
        else:
            raise ValueError(f"Unknown scan type: {scan_type!r}")

        # Populate service name from DB for all open ports
        for r in port_results:
            if r.state == PortState.OPEN and not r.service:
                r.service = get_service_name(r.port)

        host.ports = port_results

        # --- Banner / service-version detection ---
        if svc_detect:
            await enrich_results(ip, port_results, timeout=profile.banner_timeout)

        # --- OS detection ---
        if os_detect:
            host.os_guess = await detect_os(ip)

        host.scan_end = datetime.now()
        return host
