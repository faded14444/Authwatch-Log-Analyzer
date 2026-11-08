"""Glue between parsers, noise filter and detectors: one call scans a set of files."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from pathlib import Path

from authwatch.config import DetectionConfig
from authwatch.detectors import run_detections
from authwatch.filters import filter_noise
from authwatch.models import Alert, AuthEvent
from authwatch.parsers import ParseStats, iter_events

ParseFn = Callable[[Path, ParseStats], Iterator[AuthEvent]]

# auth.log, auth.log.1, auth.log.2.gz (Debian/Ubuntu); secure, secure-20261001 (RHEL/Fedora)
_LINUX_LOG_NAME = re.compile(r"^(auth\.log|secure)([.-].*)?$", re.IGNORECASE)


def _is_supported_log(path: Path) -> bool:
    return path.suffix.lower() == ".evtx" or bool(_LINUX_LOG_NAME.match(path.name))


@dataclass
class ScanSummary:
    files: list[str] = field(default_factory=list)
    records: int = 0
    auth_events: int = 0
    analyzed_events: int = 0
    skipped_records: int = 0
    skipped_chunks: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "files": self.files,
            "records": self.records,
            "auth_events": self.auth_events,
            "analyzed_events": self.analyzed_events,
            "skipped_records": self.skipped_records,
            "skipped_chunks": self.skipped_chunks,
            "first_event": self.first_event.isoformat() if self.first_event else None,
            "last_event": self.last_event.isoformat() if self.last_event else None,
        }


@dataclass
class ScanResult:
    alerts: list[Alert]
    summary: ScanSummary
    events: list[AuthEvent] = field(default_factory=list)  # analysed (noise-filtered) events


def collect_files(paths: Iterable[str | Path]) -> list[Path]:
    """Expand the CLI arguments into a sorted, de-duplicated list of log files.

    Folders are searched recursively for .evtx files and Linux auth logs. A file named
    explicitly is always used, whatever its name.
    """
    found: dict[Path, None] = {}
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and _is_supported_log(child):
                    found[child] = None
        elif path.is_file():
            found[path] = None
        else:
            raise FileNotFoundError(f"path does not exist: {path}")
    return list(found)


def scan(
    files: Iterable[Path],
    config: DetectionConfig | None = None,
    parse: ParseFn | None = None,
    linux_year: int | None = None,
) -> ScanResult:
    if parse is None:
        parse = partial(iter_events, linux_year=linux_year)
    stats = ParseStats()
    summary = ScanSummary()

    events: list[AuthEvent] = []
    for path in files:
        summary.files.append(str(path))
        events.extend(parse(path, stats))

    summary.records = stats.records
    summary.auth_events = len(events)
    summary.skipped_records = stats.skipped_records
    summary.skipped_chunks = stats.skipped_chunks
    if events:
        summary.first_event = min(e.timestamp for e in events)
        summary.last_event = max(e.timestamp for e in events)

    analyzed = filter_noise(events)
    summary.analyzed_events = len(analyzed)

    return ScanResult(
        alerts=run_detections(analyzed, config), summary=summary, events=analyzed
    )
