"""Parse Linux SSH authentication logs into AuthEvents.

Supported files: /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/Fedora),
including rotated, gzip-compressed copies (auth.log.2.gz).

Only two kinds of sshd lines are turned into events:
  "Failed password for [invalid user] NAME from IP port N ssh2"  -> failure
  "Accepted <method> for NAME from IP port N ssh2"                -> success
Other lines about the same attempt ("Invalid user ...", "pam_unix(sshd:auth):
authentication failure", "Connection closed ...") are ignored on purpose: counting
them too would report every attempt two or three times.
"""

from __future__ import annotations

import gzip
import re
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from authwatch.models import AuthEvent
from authwatch.parsers.common import LogParseError, ParseStats, parse_timestamp

SOURCE_NAME = "linux-auth"
GZIP_MAGIC = b"\x1f\x8b"
_MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

# "Oct  1 09:14:02 web01 sshd[2101]: ..."  (classic syslog: no year, no timezone)
_TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)
# "2026-10-01T09:14:02.123456+02:00 web01 sshd[2101]: ..."  (RFC 3339, newer rsyslog)
_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<msg>.*)$"
)
# OpenSSH 9.8+ logs per-connection messages as "sshd-session".
_SSHD = re.compile(r"^sshd(?:-session)?\[\d+\]:\s*(?P<body>.*)$")
# rsyslog collapses identical lines: "message repeated 4 times: [ Failed password ...]"
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<body>.*?)\s*\]$")
_FAILED = re.compile(
    r"^Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>.*?) from (?P<ip>\S+) port \d+"
)
_ACCEPTED = re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")


def _text_opener(path: Path) -> Callable[[], TextIO]:
    """Return a function that opens the log as text (transparently un-gzipping)."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
        if head.startswith(GZIP_MAGIC):
            with gzip.open(path, "rb") as gz:
                head = gz.read(4096)

            def opener() -> TextIO:
                return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        else:

            def opener() -> TextIO:
                return path.open("r", encoding="utf-8", errors="replace")
    except (OSError, EOFError) as exc:  # gzip.BadGzipFile is an OSError
        raise LogParseError(f"cannot read {path}: {exc}") from exc

    if b"\x00" in head:
        raise LogParseError(f"{path} is not a text log (binary content)")
    return opener


def _count_year_rollovers(lines: Iterable[str]) -> int:
    """Count Dec -> Jan jumps, so classic syslog lines can be given the right year."""
    rollovers, previous = 0, None
    for line in lines:
        match = _TRADITIONAL.match(line)
        month = _MONTHS.get(match["mon"]) if match else None
        if month is None:
            continue
        if previous is not None and month < previous:
            rollovers += 1
        previous = month
    return rollovers


def _parse_message(msg: str) -> tuple[bool, str | None, str, int] | None:
    """Return (success, username, ip, how_many_times) for a relevant sshd message."""
    sshd = _SSHD.match(msg)
    if not sshd:
        return None
    body, times = sshd["body"], 1
    repeated = _REPEATED.match(body)
    if repeated:
        body, times = repeated["body"], int(repeated["n"])

    if failed := _FAILED.match(body):
        return False, failed["user"].strip() or None, failed["ip"], times
    if accepted := _ACCEPTED.match(body):
        return True, accepted["user"], accepted["ip"], times
    return None


def iter_auth_log(
    path: Path, stats: ParseStats | None = None, year: int | None = None
) -> Iterator[AuthEvent]:
    """Yield SSH logon events from a Linux auth log, one line at a time.

    Classic syslog lines carry no year and no timezone. `year` is the year of the
    *last* line in the file (default: the year the file was last modified); earlier
    lines are adjusted across New Year automatically. Such times are taken as UTC.
    """
    stats = stats if stats is not None else ParseStats()
    path = Path(path)
    opener = _text_opener(path)

    if year is None:
        year = datetime.fromtimestamp(path.stat().st_mtime, UTC).year
    with opener() as fh:
        current_year = year - _count_year_rollovers(fh)
    stats.files += 1

    previous_month = None
    with opener() as fh:
        for raw in fh:
            stats.records += 1
            line = raw.rstrip("\r\n")

            if match := _TRADITIONAL.match(line):
                month = _MONTHS.get(match["mon"])
                if month is None:
                    continue
                if previous_month is not None and month < previous_month:
                    current_year += 1
                previous_month = month
            elif not (match := _RFC3339.match(line)):
                continue

            parsed = _parse_message(match["msg"])
            if parsed is None:
                continue
            success, user, ip, times = parsed

            try:
                if "ts" in match.groupdict():
                    timestamp = parse_timestamp(match["ts"])
                else:
                    timestamp = datetime(
                        current_year, month, int(match["day"]),
                        int(match["hh"]), int(match["mm"]), int(match["ss"]), tzinfo=UTC,
                    )
            except ValueError:  # e.g. "Feb 30"
                stats.skipped_records += 1
                continue

            event = AuthEvent(
                timestamp=timestamp,
                success=success,
                username=user,
                source_ip=ip,
                computer=match["host"],
                source=SOURCE_NAME,
            )
            for _ in range(times):
                yield event
