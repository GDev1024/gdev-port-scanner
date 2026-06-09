"""
Rich terminal output — progress bar, scan tables, and summary.
"""

from datetime import datetime
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    Task,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from .models import HostResult, PortResult, PortState, ScanResult

console = Console(highlight=False)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATE_STYLE: dict[PortState, str] = {
    PortState.OPEN:          "bold green",
    PortState.CLOSED:        "dim",
    PortState.FILTERED:      "yellow",
    PortState.OPEN_FILTERED: "cyan",
}

_TIMING_NAMES = {
    "0": "Paranoid",
    "1": "Sneaky",
    "2": "Polite",
    "3": "Normal",
    "4": "Aggressive",
    "5": "Insane",
}


class _PortRateColumn(ProgressColumn):
    """Displays scan rate as  '  342 p/s'."""
    def render(self, task: Task) -> Text:
        speed = task.speed
        if speed is None or speed == 0:
            return Text("    -- p/s", style="dim")
        color = "green" if speed >= 200 else "yellow"
        return Text(f"{int(speed):>5} p/s", style=color)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_ART = r"""
  ____  ____           _   ____
 / ___||  _ \ ___  ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
| |  _ | | | / _ \/ _ \ |___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |_| || |_|  __/  __/ |  ___) | (_| (_| | | | | | | |  __/ |
 \____||____/\___|\___|_||____/ \___\__,_|_| |_|_| |_|\___|_|
"""


def print_banner(version: str = "1.0.0") -> None:
    art = Text(_BANNER_ART.strip("\n"), style="bold cyan", justify="center")
    sub = Text(
        f"\n  v{version}  |  Open Source Python Port Scanner",
        style="dim",
        justify="center",
    )
    console.print(Panel(
        Text.assemble(art, sub),
        border_style="cyan dim",
        padding=(0, 2),
    ))
    console.print()


# ---------------------------------------------------------------------------
# Scan header
# ---------------------------------------------------------------------------

def print_scan_info(
    targets: list[str],
    ports: list[int],
    scan_type: str,
    timing: str,
) -> None:
    if len(ports) == 65535:
        port_desc = "All ports (1-65535)"
    elif ports == list(range(min(ports), max(ports) + 1)):
        port_desc = f"{min(ports)}-{max(ports)}  ({len(ports)} ports)"
    else:
        port_desc = f"{len(ports)} ports"

    timing_name = _TIMING_NAMES.get(str(timing), "?")

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="dim",  width=12)
    grid.add_column(style="bold", min_width=20)

    grid.add_row("Target(s)",  ", ".join(targets))
    grid.add_row("Ports",      port_desc)
    grid.add_row("Scan type",  scan_type.upper())
    grid.add_row("Timing",     f"T{timing}  ({timing_name})")
    grid.add_row("Started",    datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

    console.print(Panel(
        grid,
        title="[bold blue]Scan Parameters[/bold blue]",
        border_style="blue dim",
    ))
    console.print()


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

def make_progress() -> tuple[Progress, callable]:
    """
    Returns (progress_widget, add_task_fn).

    The widget is designed to be used inside a  ``rich.live.Live``  context.
    Advance with  ``progress.advance(task_id)``  for each completed port.
    """
    prog = Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        _PortRateColumn(),
        TimeElapsedColumn(),
        expand=True,
    )
    return prog, prog.add_task


# ---------------------------------------------------------------------------
# Per-host result table
# ---------------------------------------------------------------------------

def print_host_result(host: HostResult, show_closed: bool = False) -> None:
    """Print a Rich table for one host's scan results."""

    # ── Build header ────────────────────────────────────────────────────────
    title_parts: list[str] = [f"[bold cyan]{host.ip}[/bold cyan]"]
    if host.hostname:
        title_parts.append(f"[dim]{host.hostname}[/dim]")

    status_parts: list[str] = []
    if host.is_up:
        status_parts.append("[green]up[/green]")
        open_with_latency = [p for p in host.open_ports if p.latency]
        if open_with_latency:
            avg = sum(p.latency for p in open_with_latency) / len(open_with_latency)
            status_parts.append(f"[dim]{avg:.1f} ms avg[/dim]")
    else:
        status_parts.append("[yellow]down[/yellow]")

    if host.os_guess:
        status_parts.append(
            f"[dim]OS: {host.os_guess.family} (TTL {host.os_guess.ttl})[/dim]"
        )

    console.print()
    console.rule("  ".join(title_parts), style="blue")
    console.print("  " + "   ".join(status_parts))

    if not host.is_up:
        return

    # ── Filter ports ─────────────────────────────────────────────────────────
    display = [
        p for p in host.ports
        if p.state != PortState.CLOSED or show_closed
    ]

    if not display:
        console.print(
            Panel("[dim]All scanned ports are closed.[/dim]",
                  border_style="dim", padding=(0, 2))
        )
        return

    # ── Build table ──────────────────────────────────────────────────────────
    table = Table(
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="dim",
        show_lines=False,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("PORT",    style="bold",   width=11)
    table.add_column("STATE",                   width=12)
    table.add_column("SERVICE",                 width=14)
    table.add_column("VERSION",                 width=26)
    table.add_column("LAT",   justify="right",  width=8)

    for port in sorted(display, key=lambda p: p.port):
        state_style = _STATE_STYLE.get(port.state, "")
        latency_col = f"{port.latency:.1f} ms" if port.latency else ""

        # Version cell: prefer detected version, fall back to first line of banner
        if port.version:
            version_cell = port.version
        elif port.banner:
            first_line = port.banner.split("\n")[0][:40].strip()
            version_cell = Text(first_line, style="dim")
        else:
            version_cell = ""

        table.add_row(
            f"{port.port}/{port.protocol}",
            Text(port.state.value, style=state_style),
            port.service,
            version_cell,
            Text(latency_col, style="dim"),
        )

    console.print(table)

    closed_n = sum(1 for p in host.ports if p.state == PortState.CLOSED)
    if closed_n and not show_closed:
        console.print(f"  [dim]{closed_n} closed port(s) not shown  (use -v to display)[/dim]")


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------

def print_summary(result: ScanResult) -> None:
    total_hosts = len(result.hosts)
    up_hosts    = sum(1 for h in result.hosts if h.is_up)
    total_open  = result.total_open
    elapsed     = result.elapsed

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="dim",  width=16)
    grid.add_column(style="bold")

    grid.add_row("Hosts",       f"{up_hosts}/{total_hosts} up")
    grid.add_row("Open ports",  f"[green]{total_open}[/green]")
    grid.add_row("Duration",    f"{elapsed:.2f}s")
    grid.add_row("Completed",   datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

    console.print()
    console.print(Panel(
        grid,
        title="[bold green]Scan Complete[/bold green]",
        border_style="green dim",
    ))


# ---------------------------------------------------------------------------
# Live discovery line
# ---------------------------------------------------------------------------

def print_discovered(host: str, result: PortResult) -> None:
    if result.state == PortState.OPEN:
        latency = f"  [dim]{result.latency:.1f}ms[/dim]" if result.latency else ""
        console.print(
            f"  [green]+[/green] [bold]{result.port}/{result.protocol}[/bold]"
            f"  [cyan]{host}[/cyan]"
            f"  [dim]{result.service or ''}[/dim]"
            f"{latency}"
        )
