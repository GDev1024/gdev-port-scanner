"""Timing templates T0–T5, mirroring nmap's naming convention."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TimingProfile:
    name:            str
    connect_timeout: float   # seconds; per-port connect attempt
    banner_timeout:  float   # seconds; banner read window
    concurrency:     int     # max simultaneous async connections
    inter_probe:     float   # delay between probes (seconds); 0 = none


TIMING: dict[int, TimingProfile] = {
    0: TimingProfile("paranoid",    5.0, 10.0,   10, 0.5),
    1: TimingProfile("sneaky",      3.0,  6.0,   50, 0.1),
    2: TimingProfile("polite",      2.0,  4.0,  150, 0.0),
    3: TimingProfile("normal",      1.0,  3.0,  500, 0.0),  # default
    4: TimingProfile("aggressive",  0.5,  2.0, 1000, 0.0),
    5: TimingProfile("insane",      0.2,  1.0, 2000, 0.0),
}

DEFAULT_TIMING = TIMING[3]


def get_timing(t: int) -> TimingProfile:
    """Return the TimingProfile for template index t (0–5)."""
    if t not in TIMING:
        raise ValueError(f"Timing template must be 0–5, got {t}")
    return TIMING[t]
