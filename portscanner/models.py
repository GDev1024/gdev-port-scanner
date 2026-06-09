"""Data models for scan results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class PortState(str, Enum):
    OPEN          = "open"
    CLOSED        = "closed"
    FILTERED      = "filtered"
    OPEN_FILTERED = "open|filtered"  # ambiguous UDP state


class ScanType(str, Enum):
    TCP = "tcp"
    SYN = "syn"
    UDP = "udp"


@dataclass
class PortResult:
    port:     int
    protocol: str        # "tcp" or "udp"
    state:    PortState
    service:  str = ""   # "http", "ssh", …
    version:  str = ""   # "Apache/2.4.51", "OpenSSH 8.9p1"
    banner:   str = ""   # raw first-response bytes, decoded
    latency:  float = 0.0  # ms


@dataclass
class OSGuess:
    family:     str = ""    # "Linux/Unix/macOS", "Windows", …
    ttl:        int = 0
    confidence: str = "low" # "low" | "medium" | "high"
    method:     str = "ttl"


@dataclass
class HostResult:
    target:     str              # original user input
    ip:         str              # resolved IP address
    hostname:   str = ""         # reverse-DNS name
    is_up:      bool = True
    os_guess:   Optional[OSGuess] = None
    ports:      list = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end:   Optional[datetime] = None

    @property
    def open_ports(self) -> list:
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def elapsed(self) -> float:
        if self.scan_start and self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0.0


@dataclass
class ScanResult:
    hosts:      list = field(default_factory=list)
    scan_type:  str = "tcp"
    timing:     str = "T3"
    scan_start: Optional[datetime] = None
    scan_end:   Optional[datetime] = None

    @property
    def total_open(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def elapsed(self) -> float:
        if self.scan_start and self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0.0
