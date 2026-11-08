"""Parse Windows Security logs (.evtx) into AuthEvents.

Only two event IDs matter for authentication attacks:
  4624 - an account was successfully logged on
  4625 - an account failed to log on
Everything else in the file is skipped.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

from authwatch.models import AuthEvent
from authwatch.parsers.common import LogParseError, ParseStats, parse_timestamp

LOGON_SUCCESS = 4624
LOGON_FAILURE = 4625
EVTX_MAGIC = b"ElfFile\x00"
SOURCE_NAME = "windows-evtx"

__all__ = ["EvtxParseError", "ParseStats", "iter_evtx", "parse_event_xml", "parse_timestamp"]


class EvtxParseError(LogParseError):
    """The file is missing, unreadable or not an EVTX log."""


def _clean(value: str | None) -> str | None:
    """Windows writes "-" for empty fields; normalise that to None."""
    if value is None:
        return None
    value = value.strip()
    return None if value in ("", "-") else value


def _to_int(value: str | None) -> int | None:
    value = _clean(value)
    return int(value) if value is not None and value.isdigit() else None


def _strip_namespaces(root: ET.Element) -> None:
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]


def parse_event_xml(xml: str) -> AuthEvent | None:
    """Convert one event's XML to an AuthEvent, or None if it is not a logon event.

    Raises ValueError / ET.ParseError for malformed logon events.
    """
    root = ET.fromstring(xml)
    _strip_namespaces(root)

    system = root.find("System")
    if system is None:
        return None
    event_id_text = (system.findtext("EventID") or "").strip()
    if not event_id_text.isdigit():
        return None
    event_id = int(event_id_text)
    if event_id not in (LOGON_SUCCESS, LOGON_FAILURE):
        return None

    time_created = system.find("TimeCreated")
    system_time = time_created.get("SystemTime") if time_created is not None else None
    if not system_time:
        raise ValueError(f"event {event_id} has no TimeCreated/SystemTime")

    data = {d.get("Name"): d.text for d in root.iterfind("EventData/Data")}

    return AuthEvent(
        timestamp=parse_timestamp(system_time),
        success=event_id == LOGON_SUCCESS,
        username=_clean(data.get("TargetUserName")),
        source_ip=_clean(data.get("IpAddress")),
        domain=_clean(data.get("TargetDomainName")),
        logon_type=_to_int(data.get("LogonType")),
        computer=_clean(system.findtext("Computer")),
        source=SOURCE_NAME,
    )


def _check_magic(path: Path) -> None:
    try:
        with path.open("rb") as fh:
            header = fh.read(len(EVTX_MAGIC))
    except OSError as exc:
        raise EvtxParseError(f"cannot read {path}: {exc}") from exc
    if header != EVTX_MAGIC:
        raise EvtxParseError(f"{path} is not an EVTX file (bad header)")


def iter_evtx(path: Path, stats: ParseStats | None = None) -> Iterator[AuthEvent]:
    """Yield logon events from an .evtx file one by one (constant memory).

    A corrupted record or chunk is counted in `stats` and skipped, so one bad
    spot does not stop the whole analysis.
    """
    from Evtx.Evtx import Evtx  # imported lazily: only needed for real files

    stats = stats if stats is not None else ParseStats()
    path = Path(path)
    _check_magic(path)
    stats.files += 1

    with Evtx(str(path)) as log:
        for chunk in log.chunks():
            try:
                records = list(chunk.records())
            except Exception:  # python-evtx raises various errors on corrupt chunks
                stats.skipped_chunks += 1
                continue
            for record in records:
                stats.records += 1
                try:
                    event = parse_event_xml(record.xml())
                except Exception:
                    stats.skipped_records += 1
                    continue
                if event is not None:
                    yield event
