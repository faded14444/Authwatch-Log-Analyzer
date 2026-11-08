"""Colourful terminal report built with rich."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from authwatch.models import Alert, Severity

if TYPE_CHECKING:
    from authwatch.scan import ScanSummary

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def _fmt_time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "-"


def _fmt_span(first: datetime, last: datetime) -> str:
    if first.date() == last.date():
        return f"{first:%Y-%m-%d %H:%M:%S} → {last:%H:%M:%S}"
    return f"{_fmt_time(first)} → {_fmt_time(last)}"


def _fmt_accounts(usernames: Sequence[str]) -> str:
    if len(usernames) <= 2:
        return ", ".join(usernames)
    return f"{usernames[0]}, {usernames[1]} +{len(usernames) - 2} more"


def _header(summary: ScanSummary) -> str:
    files = len(summary.files)
    line = (
        f"[bold]authwatch[/] · {files} file{'s' if files != 1 else ''} · "
        f"{summary.auth_events} logon events ({summary.analyzed_events} analysed)"
    )
    if summary.first_event and summary.last_event:
        line += f" · {_fmt_time(summary.first_event)} → {_fmt_time(summary.last_event)} UTC"
    return line


def render(alerts: Sequence[Alert], summary: ScanSummary, console: Console) -> None:
    console.print(_header(summary))

    if summary.skipped_records or summary.skipped_chunks:
        console.print(
            f"[yellow]warning:[/] skipped {summary.skipped_records} corrupted record(s) "
            f"and {summary.skipped_chunks} corrupted chunk(s)"
        )
    if summary.auth_events == 0:
        console.print(
            "[yellow]No logon events found. Expected a Windows *Security* log "
            "(events 4624/4625) or a Linux SSH log (auth.log / secure).[/]"
        )

    if not alerts:
        console.print("[bold green]No alerts.[/]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Source IP")
    table.add_column("Account(s)")
    table.add_column("Attempts", justify="right")
    table.add_column("Time (UTC)")
    table.add_column("MITRE")

    for alert in alerts:
        table.add_row(
            f"[{SEVERITY_STYLE[alert.severity]}] {alert.severity.label.upper()} [/]",
            alert.rule,
            alert.source_ip,
            _fmt_accounts(alert.usernames),
            str(alert.count),
            _fmt_span(alert.first_seen, alert.last_seen),
            ", ".join(alert.mitre),
        )
    console.print(table)

    console.print("[bold]Details[/]")
    for number, alert in enumerate(alerts, start=1):
        style = SEVERITY_STYLE[alert.severity]
        console.print(f"  {number}. [{style}]{alert.severity.label.upper()}[/] {alert.description}")

    counts = Counter(alert.severity for alert in alerts)
    parts = [f"{counts[sev]} {sev.label}" for sev in sorted(Severity, reverse=True) if counts[sev]]
    console.print(f"\n[bold]Summary:[/] {len(alerts)} alert(s) - " + ", ".join(parts))
