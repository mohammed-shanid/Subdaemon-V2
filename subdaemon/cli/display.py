"""
SubDaemon v2 — CLI Display
───────────────────────────
Terminal UI built on the `rich` library.
Falls back to plain ANSI if rich is not installed.

Separate from all logic — display knows nothing about DNS or HTTP.
Engine calls display_callback(finding, stats) and display handles the rest.
"""

from __future__ import annotations

import sys
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from subdaemon.core.engine import ScanStats
    from subdaemon.output.writer import Finding

# ─── Rich backend ─────────────────────────────────────────────────────────────

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn, MofNCompleteColumn
    )
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ─── ANSI fallback ────────────────────────────────────────────────────────────

class _ANSI:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    @staticmethod
    def strip(text: str) -> str:
        import re
        return re.sub(r"\033\[[0-9;]*m", "", text)


BANNER = r"""
 ___  _   _ ___ ___   _   ___ __  __  ___  _  _
/ __|| | | | _ ) _ \ /_\ | __|  \/  |/ _ \| \| |
\__ \| |_| | _ \  _// _ \| _|| |\/| | (_) | .` |
|___/ \___/|___/_/ /_/ \_\___|_|  |_|\___/|_|\_|
"""

VERSION = "2.0.0"


# ─── Rich Display ─────────────────────────────────────────────────────────────

class RichDisplay:
    """
    Full live display using rich.
    Shows: banner, live stats panel, scrolling findings table, progress bar.
    """

    def __init__(self, domain: str, total: int = 0, quiet: bool = False):
        self._domain   = domain
        self._total    = total
        self._quiet    = quiet
        self._console  = Console(highlight=False)
        self._findings: list["Finding"] = []
        self._live:     Optional[Live] = None
        self._start    = time.monotonic()

        # Progress
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("[yellow]{task.fields[rate]}/s"),
            TimeElapsedColumn(),
            console=self._console,
        )
        self._task = self._progress.add_task(
            f"Scanning [bold]{domain}[/bold]",
            total=total if total > 0 else None,
            rate="0",
        )

        self._table = Table(
            "Hostname", "IP", "HTTP", "Title", "Tech",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
            expand=True,
            min_width=80,
        )

    def _make_layout(self, stats: "ScanStats") -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._make_stats_panel(stats), name="stats", size=7),
            Layout(self._progress,                name="progress", size=3),
            Layout(self._table,                   name="table"),
        )
        return layout

    def _make_stats_panel(self, stats: "ScanStats") -> Panel:
        s = stats
        text = Text()
        text.append(f"  Domain   : ", style="dim")
        text.append(f"{self._domain}\n", style="bold cyan")
        text.append(f"  Queued   : ", style="dim")
        text.append(f"{s.total_queued:<8}", style="white")
        text.append(f"  Resolved : ", style="dim")
        text.append(f"{s.dns_resolved:<8}", style="green")
        text.append(f"  Found    : ", style="dim")
        text.append(f"{s.found}\n", style="bold green")
        text.append(f"  Checked  : ", style="dim")
        text.append(f"{s.dns_checked:<8}", style="white")
        text.append(f"  WC Hits  : ", style="dim")
        text.append(f"{s.wildcard_hits:<8}", style="yellow")
        text.append(f"  Errors   : ", style="dim")
        text.append(f"{s.errors}\n", style="red")
        return Panel(text, title="[bold cyan]SubDaemon v2[/bold cyan]", border_style="cyan")

    def start(self):
        if not self._quiet:
            self._console.print(f"[bold red]{BANNER}[/bold red]")
            self._console.print(
                f"[cyan]  Version {VERSION}  |  "
                f"Target: [bold]{self._domain}[/bold][/cyan]\n"
            )

    def update(self, finding: "Finding", stats: "ScanStats"):
        """Called by engine for each new finding."""
        self._findings.append(finding)

        # Update progress bar
        self._progress.update(
            self._task,
            completed=stats.dns_checked,
            total=stats.total_queued if stats.total_queued > 0 else None,
            rate=f"{stats.rate:.0f}",
        )

        # Add row to table
        ip_str    = finding.ipv4[0] if finding.ipv4 else (finding.ipv6[0] if finding.ipv6 else "")
        http_str  = str(finding.http_status) if finding.http_status else "DNS"
        title_str = (finding.title or "")[:50]
        tech_str  = ", ".join(finding.technologies[:3])

        status_style = (
            "green"  if finding.http_status and finding.http_status < 300 else
            "yellow" if finding.http_status and finding.http_status < 400 else
            "red"    if finding.http_status else
            "cyan"
        )

        self._table.add_row(
            Text(finding.hostname, style="bold"),
            Text(ip_str,           style="dim"),
            Text(http_str,         style=status_style),
            Text(title_str,        style="dim"),
            Text(tech_str,         style="magenta"),
        )

        # Print immediately if no live context
        if not self._live:
            self._console.print(
                f"  [green][+][/green] [bold]{finding.hostname}[/bold]"
                f" [dim]{ip_str}[/dim]"
                + (f" [cyan]{http_str}[/cyan]" if finding.http_status else "")
                + (f' [dim]"{title_str}"[/dim]' if title_str else "")
            )

    def print_summary(self, stats: "ScanStats"):
        self._console.print()
        self._console.rule("[bold cyan]Scan Complete[/bold cyan]")
        self._console.print(f"  [green]✓[/green] Domain      : [bold]{self._domain}[/bold]")
        self._console.print(f"  [green]✓[/green] Total found : [bold green]{stats.found}[/bold green]")
        self._console.print(f"  [cyan]·[/cyan] DNS checked : {stats.dns_checked}")
        self._console.print(f"  [cyan]·[/cyan] DNS resolved: {stats.dns_resolved}")
        self._console.print(f"  [cyan]·[/cyan] WC filtered : {stats.wildcard_hits}")
        self._console.print(f"  [cyan]·[/cyan] Avg rate    : {stats.rate:.0f}/s")
        self._console.print(f"  [cyan]·[/cyan] Elapsed     : {stats.elapsed:.2f}s")
        self._console.rule()


# ─── Plain ANSI Display ───────────────────────────────────────────────────────

class PlainDisplay:
    """Minimal ANSI display — no rich dependency."""

    def __init__(self, domain: str, total: int = 0, quiet: bool = False):
        self._domain  = domain
        self._total   = total
        self._quiet   = quiet
        self._start   = time.monotonic()

    def start(self):
        if not self._quiet:
            c = _ANSI
            print(f"{c.RED}{BANNER}{c.RESET}")
            print(f"{c.CYAN}  Version {VERSION} | Target: {c.BOLD}{self._domain}{c.RESET}\n")

    def update(self, finding: "Finding", stats: "ScanStats"):
        if self._quiet:
            return

        c = _ANSI
        ip  = finding.ipv4[0] if finding.ipv4 else (finding.ipv6[0] if finding.ipv6 else "")
        http = f" HTTP:{finding.http_status}" if finding.http_status else ""
        title = f' "{finding.title[:60]}"' if finding.title else ""

        print(
            f"  {c.GREEN}[+]{c.RESET} "
            f"{c.BOLD}{finding.hostname}{c.RESET}"
            f" {c.CYAN}{ip}{c.RESET}"
            f"{c.YELLOW}{http}{c.RESET}"
            f"{c.WHITE}{title}{c.RESET}"
        )

        # Progress line
        if self._total > 0:
            pct = stats.dns_checked / self._total * 100
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            sys.stdout.write(
                f"\r  [{bar}] {pct:.1f}% | "
                f"Found:{stats.found} Rate:{stats.rate:.0f}/s"
            )
            sys.stdout.flush()

    def print_summary(self, stats: "ScanStats"):
        c = _ANSI
        print(f"\n\n{'='*60}")
        print(f"{c.CYAN}  SCAN COMPLETE{c.RESET}")
        print(f"{'='*60}")
        print(f"  Domain  : {c.BOLD}{self._domain}{c.RESET}")
        print(f"  Found   : {c.GREEN}{c.BOLD}{stats.found}{c.RESET}")
        print(f"  Checked : {stats.dns_checked}/{stats.total_queued}")
        print(f"  Rate    : {stats.rate:.0f}/s")
        print(f"  Elapsed : {stats.elapsed:.2f}s")
        print(f"{'='*60}\n")


# ─── Factory ──────────────────────────────────────────────────────────────────

def make_display(domain: str, total: int = 0, quiet: bool = False, no_color: bool = False):
    if RICH_AVAILABLE and not no_color:
        return RichDisplay(domain, total, quiet)
    return PlainDisplay(domain, total, quiet)
