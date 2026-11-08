"""Pieces shared by all parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

_FRACTION = re.compile(r"\.(\d+)")
_COMPACT_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


class LogParseError(Exception):
    """The file is missing, unreadable or in an unsupported format."""


@dataclass
class ParseStats:
    files: int = 0
    records: int = 0  # EVTX records or text lines read
    skipped_records: int = 0  # records/lines that looked relevant but could not be decoded
    skipped_chunks: int = 0  # EVTX only: whole 64 KB chunks that could not be read


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 style timestamps into timezone-aware UTC datetimes.

    Handles python-evtx output ("2026-10-01 09:00:00.123456"), native Windows XML
    ("2026-10-01T09:00:00.1234567Z", 7 fractional digits) and RFC 3339 syslog
    ("2026-10-01T11:00:00.123456+02:00"). Values without a timezone are taken as UTC.
    """
    text = value.strip().replace("Z", "+00:00")
    text = _COMPACT_OFFSET.sub(r"\1:\2", text)  # +0200 -> +02:00
    # datetime supports at most 6 fractional digits (microseconds).
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
