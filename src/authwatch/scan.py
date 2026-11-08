"""Glue between parsers, noise filter and detectors: one call scans a set of files."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from authwatch.config import DetectionConfig
from authwatch.detectors import run_detections
from authwatch.filters import filter_noise
from authwatch.models import Alert, AuthEvent
from authwatch.parsers.evtx_parser import ParseStats, iter_evtx

ParseFn = Callable[[Path, ParseStats], Iterator[AuthEvent]]


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


def collect_files(paths: Iterable[str | Path]) -> list[Path]:
    """Expand the CLI arguments into a sorted, de-duplicated list of .evtx files."""
    found: dict[Path, None] = {}
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() == ".evtx":
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
) -> ScanResult:
    parse = parse or iter_evtx
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

    return ScanResult(alerts=run_detections(analyzed, config), summary=summary)
