#!/usr/bin/env python3
"""
GDev Port Scanner — Interactive wizard.
Run this for a guided, menu-driven scan experience.

  python interactive.py
"""

import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import questionary
from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# Re-use the single shared console from the output module
from portscanner import __version__
from portscanner.exporters import export_csv, export_json, export_xml
from portscanner.output import (
    console,
    make_progress,
    print_banner,
    print_discovered,
    print_host_result,
    print_scan_info,
    print_summary,
)
from portscanner.scanner import ScanEngine
from portscanner.utils import is_root, parse_ports, scapy_available

# ---------------------------------------------------------------------------
# questionary theme
# ---------------------------------------------------------------------------
STYLE = questionary.Style([
    ("qmark",       "fg:#00d7ff bold"),
    ("question",    "bold"),
    ("answer",      "fg:#00ff87 bold"),
    ("pointer",     "fg:#00d7ff bold"),
    ("highlighted", "fg:#00d7ff bold"),
    ("selected",    "fg:#00ff87"),
    ("separator",   "fg:#444444"),
    ("instruction", "fg:#666666 italic"),
    ("disabled",    "fg:#555555 italic"),
])


# ---------------------------------------------------------------------------
# Wizard helpers
# ---------------------------------------------------------------------------

def _step(n: int, total: int, title: str) -> None:
    console.print()
    console.rule(
        f"[bold cyan]Step {n} of {total}[/bold cyan]  [bold]{title}[/bold]",
        style="cyan dim",
        align="left",
    )


def _validate_targets(val: str) -> bool | str:
    return True if val.strip() else "Enter at least one target."


def _validate_ports(val: str) -> bool | str:
    try:
        parse_ports(val)
        return True
    except ValueError as exc:
        return str(exc)


def _validate_filename(val: str) -> bool | str:
    if not val.strip():
        return "Filename cannot be empty."
    if any(c in val for c in r'\/:*?"<>|'):
        return "Filename contains an invalid character."
    return True


# ---------------------------------------------------------------------------
# Wizard (all synchronous — async scan runs after)
# ---------------------------------------------------------------------------

def wizard() -> dict | None:
    """
    Walk the user through six steps and return a scan config dict,
    or None if cancelled.
    """
    print_banner(__version__)
    console.print(Panel(
        "  [bold]↑↓[/bold] navigate   [bold]Space[/bold] toggle   "
        "[bold]Enter[/bold] confirm   [bold]Ctrl-C[/bold] exit",
        border_style="dim",
        padding=(0, 2),
    ))

    # ── Step 1 · Targets ────────────────────────────────────────────────────
    _step(1, 6, "Target(s)")
    raw = questionary.text(
        "IP address, hostname, or CIDR  (comma-separate for multiple):",
        instruction="e.g. 192.168.1.1  |  10.0.0.0/24  |  example.com",
        validate=_validate_targets,
        style=STYLE,
    ).ask()
    if raw is None:
        return None
    targets = [t.strip() for t in raw.split(",") if t.strip()]

    # ── Step 2 · Ports ───────────────────────────────────────────────────────
    _step(2, 6, "Port Range")
    port_choice = questionary.select(
        "Which ports should we scan?",
        choices=[
            questionary.Choice("Top 1000 ports  (recommended — covers ~99% of services)", "top1000"),
            questionary.Choice("Top 100 ports   (fastest)",                                "top100"),
            questionary.Choice("Custom range    (you specify)",                            "custom"),
            questionary.Choice("All ports       (1-65535 — can take many minutes)",        "all"),
        ],
        style=STYLE,
    ).ask()
    if port_choice is None:
        return None

    port_spec = port_choice
    if port_choice == "custom":
        port_spec = questionary.text(
            "Port specification:",
            instruction="e.g.  22,80,443    or    1-1024    or    80,8000-9000",
            validate=_validate_ports,
            style=STYLE,
        ).ask()
        if port_spec is None:
            return None

    # ── Step 3 · Scan type ───────────────────────────────────────────────────
    _step(3, 6, "Scan Type")

    has_scapy = scapy_available()
    has_root  = is_root()
    raw_ok    = has_scapy and has_root

    if not raw_ok:
        reasons = []
        if not has_scapy:
            reasons.append("scapy not installed  (pip install scapy)")
        if not has_root:
            reasons.append("not running as administrator")
        console.print(Panel(
            "\n".join(f"  [yellow]![/yellow]  {r}" for r in reasons),
            title="[yellow]SYN / UDP unavailable[/yellow]",
            border_style="yellow dim",
            padding=(0, 1),
        ))

    scan_choices = [
        questionary.Choice(
            "TCP Connect  —  no root needed, works everywhere  (default)", "tcp"
        ),
        questionary.Choice(
            "SYN Stealth  —  faster & quieter; requires root + scapy"
            + ("" if raw_ok else "  [unavailable]"),
            "syn",
            disabled=not raw_ok,
        ),
        questionary.Choice(
            "UDP          —  slow & ambiguous; requires root + scapy"
            + ("" if raw_ok else "  [unavailable]"),
            "udp",
            disabled=not raw_ok,
        ),
    ]
    scan_type = questionary.select("Scan type:", choices=scan_choices, style=STYLE).ask()
    if scan_type is None:
        return None

    # ── Step 4 · Detection ───────────────────────────────────────────────────
    _step(4, 6, "Detection")
    detect = questionary.checkbox(
        "Enable detection features:",
        choices=[
            questionary.Choice(
                "Service & version detection  (banner grabbing)",
                "sV", checked=True,
            ),
            questionary.Choice(
                "OS detection                 (TTL analysis, no root needed)",
                "O", checked=True,
            ),
        ],
        style=STYLE,
    ).ask()
    if detect is None:
        return None

    service_detection = "sV" in detect
    os_detection      = "O"  in detect

    # ── Step 5 · Timing ──────────────────────────────────────────────────────
    _step(5, 6, "Timing Template")
    timing_choices = [
        questionary.Choice("T0  Paranoid     5.0s/port    10 threads   IDS-safe", "0"),
        questionary.Choice("T1  Sneaky       3.0s/port    50 threads",             "1"),
        questionary.Choice("T2  Polite       2.0s/port   150 threads",             "2"),
        questionary.Choice("T3  Normal       1.0s/port   500 threads   (default)", "3"),
        questionary.Choice("T4  Aggressive   0.5s/port  1000 threads",             "4"),
        questionary.Choice("T5  Insane       0.2s/port  2000 threads   may miss ports", "5"),
    ]
    timing_str = questionary.select(
        "Select timing template:",
        choices=timing_choices,
        default=timing_choices[3],
        style=STYLE,
    ).ask()
    if timing_str is None:
        return None
    timing = int(timing_str)

    # ── Step 6 · Output ──────────────────────────────────────────────────────
    _step(6, 6, "Output")
    verbose = questionary.confirm(
        "Show closed/filtered ports in the table?",
        default=False, style=STYLE,
    ).ask()
    if verbose is None:
        return None

    export_formats = questionary.checkbox(
        "Export results to file(s):",
        choices=[
            questionary.Choice("JSON",                   "json"),
            questionary.Choice("CSV",                    "csv"),
            questionary.Choice("XML  (nmap-compatible)", "xml"),
        ],
        style=STYLE,
    ).ask()
    if export_formats is None:
        return None

    output_stem = ""
    if export_formats:
        output_stem = questionary.text(
            "Output filename (without extension):",
            default="scan_results",
            validate=_validate_filename,
            style=STYLE,
        ).ask()
        if output_stem is None:
            return None

    # ── Summary panel ────────────────────────────────────────────────────────
    _timing_names = ["Paranoid","Sneaky","Polite","Normal","Aggressive","Insane"]
    _port_labels  = {
        "top1000": "Top 1000 ports",
        "top100":  "Top 100 ports",
        "all":     "All ports (1-65535)",
    }

    det_parts = []
    if service_detection: det_parts.append("Service / Version")
    if os_detection:      det_parts.append("OS Detection")

    exp_parts = [f".{f}" for f in export_formats]
    exp_str   = (", ".join(exp_parts) + f"  ->  {output_stem}.*") if exp_parts else "None"

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="dim",  width=16)
    grid.add_column(style="bold", min_width=30)

    grid.add_row("Target(s)",  ", ".join(targets))
    grid.add_row("Ports",      _port_labels.get(port_spec, port_spec))
    grid.add_row("Scan type",  scan_type.upper())
    grid.add_row("Detection",  ", ".join(det_parts) or "None")
    grid.add_row("Timing",     f"T{timing}  {_timing_names[timing]}")
    grid.add_row("Verbose",    "Yes" if verbose else "No")
    grid.add_row("Export",     exp_str)

    console.print()
    console.print(Panel(
        grid,
        title="[bold]Scan Summary[/bold]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    ))
    console.print()

    go = questionary.confirm("Ready to scan?", default=True, style=STYLE).ask()
    if not go:
        console.print(Panel(
            "[yellow]Scan cancelled.[/yellow]  Run [bold]python interactive.py[/bold] to start over.",
            border_style="yellow dim",
            padding=(0, 2),
        ))
        return None

    return {
        "targets":           targets,
        "port_spec":         port_spec,
        "scan_type":         scan_type,
        "service_detection": service_detection,
        "os_detection":      os_detection,
        "timing":            timing,
        "verbose":           verbose,
        "export_formats":    export_formats,
        "output_stem":       output_stem,
    }


# ---------------------------------------------------------------------------
# Async scan runner
# ---------------------------------------------------------------------------

async def run_scan(cfg: dict) -> None:
    ports = parse_ports(cfg["port_spec"])

    print_scan_info(
        targets   = cfg["targets"],
        ports     = ports,
        scan_type = cfg["scan_type"],
        timing    = str(cfg["timing"]),
    )

    progress, add_task = make_progress()
    # One task covering all ports across all targets
    total_ports = len(ports) * len(cfg["targets"])
    task_id = add_task("Scanning", total=total_ports)

    engine = ScanEngine(verbose=cfg["verbose"])

    # _on_port_found: only for printing open-port discoveries (no progress here)
    def _on_port_found(host: str, result) -> None:
        print_discovered(host, result)

    engine.on_port_found(_on_port_found)

    # _tick: called for EVERY port completion — single source of truth for progress
    def _tick() -> None:
        progress.advance(task_id)

    with Live(progress, console=console, refresh_per_second=15):
        result = await engine.scan(
            targets           = cfg["targets"],
            ports             = ports,
            scan_type         = cfg["scan_type"],
            timing            = cfg["timing"],
            service_detection = cfg["service_detection"],
            os_detection      = cfg["os_detection"],
            progress_callback = _tick,
        )

    for host in result.hosts:
        print_host_result(host, show_closed=cfg["verbose"])

    print_summary(result)

    stem = cfg["output_stem"]
    for fmt in cfg["export_formats"]:
        path = f"{stem}.{fmt}"
        if fmt == "json":
            export_json(result, path)
        elif fmt == "csv":
            export_csv(result, path)
        elif fmt == "xml":
            export_xml(result, path)
        console.print(f"  [dim]{fmt.upper()} saved  ->  {path}[/dim]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        cfg = wizard()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(0)

    if cfg is None:
        sys.exit(0)

    try:
        asyncio.run(run_scan(cfg))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
