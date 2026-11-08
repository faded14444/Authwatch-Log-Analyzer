"""Command-line interface: `authwatch scan <files or folders>`.

Exit codes: 0 = no alerts, 1 = alerts found, 2 = error. This makes the tool easy
to chain in scripts (e.g. `authwatch scan logs/ || notify-team`).
"""

from __future__ import annotations

import argparse
from datetime import timedelta
from pathlib import Path

from rich.console import Console

from authwatch import __version__
from authwatch.config import DetectionConfig
from authwatch.models import Severity
from authwatch.parsers import LogParseError
from authwatch.reporters.console import render
from authwatch.reporters.json_report import write_json
from authwatch.scan import collect_files, scan

EXIT_OK = 0
EXIT_ALERTS = 1
EXIT_ERROR = 2


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {number}")
    return number


def build_parser() -> argparse.ArgumentParser:
    defaults = DetectionConfig()
    parser = argparse.ArgumentParser(
        prog="authwatch",
        description="Detect brute-force, password spraying and suspicious logons "
        "in Windows Security logs (.evtx) and Linux SSH logs (auth.log / secure).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="analyse log files or folders")
    s.add_argument(
        "paths", nargs="+",
        help=".evtx files, Linux auth.log/secure files (also .gz) "
        "or folders (searched recursively)",
    )
    s.add_argument("-o", "--output", type=Path, help="also write alerts to this JSON file")
    s.add_argument(
        "--linux-year", type=_positive_int, metavar="YEAR",
        help="year of the LAST line in Linux logs whose lines have no year "
        "(default: the year the file was last modified)",
    )
    s.add_argument(
        "--min-severity",
        choices=[sev.label for sev in Severity],
        default="low",
        help="only report alerts at or above this severity (default: low)",
    )

    rules = s.add_argument_group("detection thresholds")
    minutes = lambda td: int(td.total_seconds() // 60)  # noqa: E731
    rules.add_argument("--bf-threshold", type=_positive_int, default=defaults.bf_threshold,
                       help=f"brute-force: failures per account (default: {defaults.bf_threshold})")
    rules.add_argument("--bf-window", type=_positive_int, default=minutes(defaults.bf_window),
                       metavar="MIN", help="brute-force: time window in minutes "
                       f"(default: {minutes(defaults.bf_window)})")
    rules.add_argument("--spray-users", type=_positive_int, default=defaults.spray_min_users,
                       help="password spraying: distinct accounts "
                       f"(default: {defaults.spray_min_users})")
    rules.add_argument("--spray-window", type=_positive_int,
                       default=minutes(defaults.spray_window), metavar="MIN",
                       help="password spraying: time window in minutes "
                       f"(default: {minutes(defaults.spray_window)})")
    rules.add_argument("--saf-failures", type=_positive_int, default=defaults.saf_min_failures,
                       help="success after failures: failures before the success "
                       f"(default: {defaults.saf_min_failures})")
    rules.add_argument("--saf-window", type=_positive_int, default=minutes(defaults.saf_window),
                       metavar="MIN", help="success after failures: look-back window in "
                       f"minutes (default: {minutes(defaults.saf_window)})")
    return parser


def _config_from_args(args: argparse.Namespace) -> DetectionConfig:
    return DetectionConfig(
        bf_threshold=args.bf_threshold,
        bf_window=timedelta(minutes=args.bf_window),
        spray_min_users=args.spray_users,
        spray_window=timedelta(minutes=args.spray_window),
        saf_min_failures=args.saf_failures,
        saf_window=timedelta(minutes=args.saf_window),
    )


def main(
    argv: list[str] | None = None,
    console: Console | None = None,
    err_console: Console | None = None,
) -> int:
    console = console or Console()
    err_console = err_console or Console(stderr=True)
    args = build_parser().parse_args(argv)

    try:
        files = collect_files(args.paths)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]error:[/] {exc}")
        return EXIT_ERROR
    if not files:
        err_console.print(
            "[bold red]error:[/] no supported log files (.evtx, auth.log*, secure*) "
            "found in the given paths"
        )
        return EXIT_ERROR

    try:
        result = scan(files, _config_from_args(args), linux_year=args.linux_year)
    except (LogParseError, OSError) as exc:
        err_console.print(f"[bold red]error:[/] {exc}")
        return EXIT_ERROR

    min_severity = Severity.from_label(args.min_severity)
    alerts = [a for a in result.alerts if a.severity >= min_severity]

    render(alerts, result.summary, console)
    if args.output:
        try:
            write_json(alerts, result.summary, args.output)
        except OSError as exc:
            err_console.print(f"[bold red]error:[/] cannot write {args.output}: {exc}")
            return EXIT_ERROR
        console.print(f"Alerts written to [bold]{args.output}[/]")

    return EXIT_ALERTS if alerts else EXIT_OK
