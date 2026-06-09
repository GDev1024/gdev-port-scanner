"""
Target expansion, port-range parsing, and privilege helpers.
"""

import ipaddress
import os
import socket
import sys
from typing import Generator

from .services import TOP_100_PORTS, TOP_1000_PORTS


# ---------------------------------------------------------------------------
# Privilege / dependency checks
# ---------------------------------------------------------------------------

def is_root() -> bool:
    """Return True if the process has root/admin privileges."""
    if sys.platform == "win32":
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0


def scapy_available() -> bool:
    """Return True if scapy is importable."""
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------

def resolve_host(target: str) -> tuple[str, str]:
    """
    Resolve *target* (IP string or hostname) to (ip, hostname).
    Raises ValueError if resolution fails.
    """
    # Already a valid IP?
    try:
        addr = str(ipaddress.ip_address(target))
        try:
            hostname = socket.gethostbyaddr(addr)[0]
        except Exception:
            hostname = ""
        return addr, hostname
    except ValueError:
        pass

    # Hostname → forward lookup
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {target!r}")


def expand_targets(target: str) -> Generator[tuple[str, str], None, None]:
    """
    Yield (ip, hostname) pairs for *target*.
    Handles single IP, hostname, and CIDR notation.
    """
    # CIDR network?
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts())
        if not hosts:
            # /32 or /128 — treat as single host
            hosts = [network.network_address]
        for addr in hosts:
            yield str(addr), ""
        return
    except ValueError:
        pass

    # Single target
    ip, hostname = resolve_host(target)
    yield ip, hostname


# ---------------------------------------------------------------------------
# Port-range parsing
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    """
    Parse a port specification into a sorted list of port numbers.

    Accepted formats:
      "80"              single port
      "80,443,8080"     comma-separated
      "1-1000"          inclusive range
      "80,443,1000-2000" mixed
      "top100"          top 100 common ports
      "top1000"         top 1000 common ports
      "all"             every port (1–65535)
    """
    s = spec.strip().lower()

    if s == "top100":
        return sorted(TOP_100_PORTS)
    if s == "top1000":
        return sorted(TOP_1000_PORTS)
    if s in ("all", "1-65535"):
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"Port range out of bounds: {part!r}")
            if lo > hi:
                raise ValueError(f"Port range start > end: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"Port out of bounds: {p}")
            ports.add(p)

    if not ports:
        raise ValueError(f"No valid ports parsed from: {spec!r}")
    return sorted(ports)
