"""Core data structures shared by parsers, detectors and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum


class Severity(IntEnum):
    """Alert severity. Higher value = more urgent, so alerts sort naturally."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> Severity:
        return cls[label.upper()]


@dataclass(frozen=True)
class AuthEvent:
    """A single authentication attempt, independent of the log source.

    Every parser (Windows EVTX, Linux auth.log) converts its raw records into this
    shape, so detectors never need to know where the data came from.
    """

    timestamp: datetime  # timezone-aware, UTC
    success: bool
    username: str | None
    source_ip: str | None
    domain: str | None = None
    logon_type: int | None = None
    computer: str | None = None  # host that recorded the event
    source: str = "unknown"  # log source, e.g. "windows-evtx"
    source_host: str | None = None  # client workstation name, when the log has no IP (NTLM 4776)


@dataclass
class Alert:
    """Result of a detection rule firing."""

    rule: str
    severity: Severity
    mitre: tuple[str, ...]
    source: str  # IP address, or workstation name for NTLM events without an IP
    usernames: tuple[str, ...]
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    computers: tuple[str, ...] = field(default=())

    @property
    def duration(self) -> timedelta:
        return self.last_seen - self.first_seen

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "mitre": list(self.mitre),
            "source": self.source,
            "usernames": list(self.usernames),
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "computers": list(self.computers),
            "description": self.description,
        }
