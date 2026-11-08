"""Parse Windows Security logs (.evtx) into AuthEvents.

Event IDs that matter for authentication attacks:
  4624 - an account was successfully logged on                 (any Windows host)
  4625 - an account failed to log on                           (any Windows host)
  4768 - a Kerberos ticket (TGT) was requested                 (domain controller)
  4771 - Kerberos pre-authentication failed                    (domain controller)
  4776 - the DC attempted to validate NTLM credentials         (domain controller)
For 4768/4771/4776 the result code decides whether the attempt is a success, a
failure that points to credential guessing, or neither (e.g. clock skew), in which
case the event is skipped. Everything else in the file is skipped too.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

from authwatch.models import AuthEvent
from authwatch.parsers.common import LogParseError, ParseStats, parse_timestamp

LOGON_SUCCESS = 4624
LOGON_FAILURE = 4625
KERBEROS_TGT_REQUEST = 4768
KERBEROS_PREAUTH_FAILED = 4771
NTLM_VALIDATION = 4776
SUPPORTED_EVENTS = {
    LOGON_SUCCESS, LOGON_FAILURE, KERBEROS_TGT_REQUEST, KERBEROS_PREAUTH_FAILED, NTLM_VALIDATION,
}

# Kerberos result codes (RFC 4120) that mean someone is guessing credentials.
KERBEROS_FAILURES = {
    0x06: "unknown account",  # KDC_ERR_C_PRINCIPAL_UNKNOWN - guessing account names
    0x12: "account disabled, locked or expired",  # KDC_ERR_CLIENT_REVOKED
    0x18: "wrong password",  # KDC_ERR_PREAUTH_FAILED
}
# NTLM status codes (NTSTATUS) that mean someone is guessing credentials.
NTLM_FAILURES = {
    0xC0000064: "unknown account",
    0xC000006A: "wrong password",
    0xC000006D: "bad user name or password",
    0xC0000072: "account disabled",
    0xC0000234: "account locked out",
}

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


def _clean_ip(value: str | None) -> str | None:
    """Normalise IPv4-mapped IPv6 ("::ffff:10.0.0.5", common in 4768) to plain IPv4,
    so the same attacker is not split into two sources."""
    value = _clean(value)
    if value is None:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return value
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _status(value: str | None) -> int | None:
    value = _clean(value)
    try:
        return int(value, 16) if value is not None else None
    except ValueError:
        return None


def _outcome(event_id: int, data: dict[str, str | None]) -> bool | None:
    """True = success, False = credential-guessing failure, None = not relevant."""
    if event_id in (LOGON_SUCCESS, LOGON_FAILURE):
        return event_id == LOGON_SUCCESS

    status = _status(data.get("Status"))
    if status is None:
        return None
    if status == 0 and event_id in (KERBEROS_TGT_REQUEST, NTLM_VALIDATION):
        return True
    failures = NTLM_FAILURES if event_id == NTLM_VALIDATION else KERBEROS_FAILURES
    return False if status in failures else None


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
    if event_id not in SUPPORTED_EVENTS:
        return None

    data = {d.get("Name"): d.text for d in root.iterfind("EventData/Data")}
    success = _outcome(event_id, data)
    if success is None:
        return None

    time_created = system.find("TimeCreated")
    system_time = time_created.get("SystemTime") if time_created is not None else None
    if not system_time:
        raise ValueError(f"event {event_id} has no TimeCreated/SystemTime")

    workstation = _clean(data.get("Workstation")) if event_id == NTLM_VALIDATION else None

    return AuthEvent(
        timestamp=parse_timestamp(system_time),
        success=success,
        username=_clean(data.get("TargetUserName")),
        source_ip=_clean_ip(data.get("IpAddress")),
        domain=_clean(data.get("TargetDomainName")),
        logon_type=_to_int(data.get("LogonType")),
        computer=_clean(system.findtext("Computer")),
        source=SOURCE_NAME,
        source_host=workstation.lstrip("\\") if workstation else None,
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
