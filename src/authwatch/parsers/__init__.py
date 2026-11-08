"""Parsers turn raw log files into `AuthEvent` objects.

To support a new log source, add a module here that yields `AuthEvent`s and route
files to it in `iter_events` - detectors and reporters need no changes.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from authwatch.models import AuthEvent
from authwatch.parsers.common import LogParseError, ParseStats, parse_timestamp
from authwatch.parsers.evtx_parser import EVTX_MAGIC, EvtxParseError, iter_evtx, parse_event_xml
from authwatch.parsers.linux_auth_parser import iter_auth_log


def _has_evtx_header(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(EVTX_MAGIC)) == EVTX_MAGIC
    except OSError:
        return False


def iter_events(
    path: Path, stats: ParseStats, linux_year: int | None = None
) -> Iterator[AuthEvent]:
    """Pick the right parser for a file: .evtx / EVTX header -> Windows, otherwise Linux."""
    path = Path(path)
    if path.suffix.lower() == ".evtx" or _has_evtx_header(path):
        return iter_evtx(path, stats)
    return iter_auth_log(path, stats, year=linux_year)


__all__ = [
    "EvtxParseError",
    "LogParseError",
    "ParseStats",
    "iter_auth_log",
    "iter_events",
    "iter_evtx",
    "parse_event_xml",
    "parse_timestamp",
]
