#!/usr/bin/env python3
"""
GDev Port Scanner — CLI entry point.

Usage examples:
  python main.py 192.168.1.1
  python main.py 192.168.1.0/24 -p 1-1000 -sV -O
  python main.py example.com --top-ports 100 -T4 -oJ results.json
  python main.py 10.0.0.1 -p all -sS -v          (requires root + scapy)
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Windows asyncio compatibility — must be set before any asyncio.run() call
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


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
from portscanner.utils import parse_ports, scapy_available, is_root

from rich.live import Live


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscanner",
        description="GDev Port Scanner — full-featured async Python port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py 192.168.1.1
  python main.py 192.168.1.0/24 -p 80,443,8080 -sV
  python main.py scanme.nmap.org --top-ports 1000 -T4 -sV -O
  python main.py 10.0.0.1 -p all -sS           (root + scapy required)
  python main.py 10.0.0.1 -p 53,161 -sU        (root + scapy required)
        """,
    )

    p.add_argument("targets", nargs="+", metavar="TARGET",
                   help="IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)")

    # Port selection
    port_group = p.add_argument_group("Port Selection")
    meg = port_group.add_mutually_exclusive_group()
    meg.add_argument("-p", dest="ports", metavar="PORTS",
                     help='Port spec: "80", "1-1000", "80,443,8080", "all"')
    meg.add_argument("--top-ports", dest="top_ports", type=int, metavar="N",
                     choices=[100, 1000],
                     help="Scan top N most common ports (100 or 1000)")

    # Scan type
    scan_group = p.add_argument_group("Scan Type")
    scan_meg = scan_group.add_mutually_exclusive_group()
    scan_meg.add_argument("-sT", dest="scan_type", action="store_const", const="tcp",
                          help="TCP connect scan [default]")
    scan_meg.add_argument("-sS", dest="scan_type", action="store_const", const="syn",
                          help="SYN stealth scan (requires root + scapy)")
    scan_meg.add_argument("-sU", dest="scan_type", action="store_const", const="udp",
                          help="UDP scan (requires root + scapy)")

    # Detection
    det_group = p.add_argument_group("Detection")
    det_group.add_argument("-sV", dest="service_detection", action="store_true",
                           help="Banner grabbing + service/version detection")
    det_group.add_argument("-O", dest="os_detection", action="store_true",
                           help="OS detection (TTL-based, no root needed)")

    # Timing
    t_group = p.add_argument_group("Timing")
    t_group.add_argument("-T", dest="timing", type=int, default=3,
                         choices=range(6), metavar="0-5",
                         help="Timing template: 0=paranoid … 5=insane (default: 3)")

    # Output
    out_group = p.add_argument_group("Output")
    out_group.add_argument("-oJ", dest="json_out", metavar="FILE",
                           help="Export results as JSON to FILE")
    out_group.add_argument("-oC", dest="csv_out",  metavar="FILE",
                           help="Export results as CSV to FILE")
    out_group.add_argument("-oX", dest="xml_out",  metavar="FILE",
                           help="Export results as nmap-compatible XML to FILE")
    out_group.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                           help="Show all ports (including closed/filtered)")
    out_group.add_argument("--open-only", dest="open_only", action="store_true",
                           help="Show only open ports in the table (default behaviour)")
    out_group.add_argument("--no-ping", dest="no_ping", action="store_true",
                           help="Skip host-up check; treat all hosts as reachable")
    out_group.add_argument("--no-banner", dest="no_banner",
                           action="store_true",
                           help="Skip banner grabbing even when -sV is given")
    out_group.add_argument("--version", action="version",
                           version=f"GDev Port Scanner {__version__}")

    return p


# ---------------------------------------------------------------------------
# Port list resolution
# ---------------------------------------------------------------------------

def resolve_ports(args: argparse.Namespace) -> list[int]:
    if args.top_ports:
        spec = f"top{args.top_ports}"
    elif args.ports:
        spec = args.ports
    else:
        spec = "top1000"  # default

    try:
        return parse_ports(spec)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] Invalid port specification — {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def preflight(args: argparse.Namespace) -> None:
    scan_type = args.scan_type or "tcp"

    if scan_type in ("syn", "udp"):
        if not scapy_available():
            console.print(
                f"[red]Error:[/red] -{scan_type.upper()} requires scapy.\n"
                "  Install it with:  [bold]pip install scapy[/bold]\n"
                "  On Windows also install Npcap from https://npcap.com"
            )
            sys.exit(2)
        if not is_root():
            console.print(
                f"[red]Error:[/red] -{scan_type.upper()} requires root / administrator privileges."
            )
            sys.exit(2)


# ---------------------------------------------------------------------------
# Main async scan routine
# ---------------------------------------------------------------------------

async def run_scan(args: argparse.Namespace) -> None:
    ports     = resolve_ports(args)
    scan_type = args.scan_type or "tcp"

    print_banner(__version__)
    print_scan_info(
        targets   = args.targets,
        ports     = ports,
        scan_type = scan_type,
        timing    = str(args.timing),
    )

    # Build progress bar
    progress, add_task = make_progress()

    engine = ScanEngine(verbose=args.verbose, no_ping=args.no_ping)

    # _on_port_found: only for printing discoveries — no progress advance here
    def _on_port_found(host: str, result) -> None:
        print_discovered(host, result)

    engine.on_port_found(_on_port_found)

    # One progress task for all ports across all targets
    total_ports = len(ports) * len(args.targets)
    task_id = add_task("Scanning", total=total_ports)

    # _tick is the single source of progress advancement — called per port
    def _tick() -> None:
        progress.advance(task_id)

    with Live(progress, console=console, refresh_per_second=15):
        result = await engine.scan(
            targets           = args.targets,
            ports             = ports,
            scan_type         = scan_type,
            timing            = args.timing,
            service_detection = args.service_detection and not args.no_banner,
            os_detection      = args.os_detection,
            progress_callback = _tick,
        )

    # Print per-host tables
    show_closed = args.verbose and not args.open_only
    for host in result.hosts:
        print_host_result(host, show_closed=show_closed)

    print_summary(result)

    # Exports
    if args.json_out:
        export_json(result, args.json_out)
        console.print(f"[dim]JSON saved to {args.json_out}[/dim]")
    if args.csv_out:
        export_csv(result, args.csv_out)
        console.print(f"[dim]CSV saved  to {args.csv_out}[/dim]")
    if args.xml_out:
        export_xml(result, args.xml_out)
        console.print(f"[dim]XML saved  to {args.xml_out}[/dim]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()

    # No arguments → show a helpful hint panel before argparse prints usage
    if len(sys.argv) == 1:
        from rich.panel import Panel
        console.print(Panel(
            "  [bold]python interactive.py[/bold]   [dim]guided wizard (recommended)[/dim]\n"
            "  [bold]python main.py TARGET[/bold]   [dim]direct flags  (e.g. main.py 192.168.1.1 -sV -O)[/dim]",
            title="[cyan]GDev Port Scanner[/cyan]",
            border_style="cyan dim",
            padding=(0, 2),
        ))
        console.print()

    args = parser.parse_args()

    if not args.scan_type:
        args.scan_type = "tcp"

    preflight(args)

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
