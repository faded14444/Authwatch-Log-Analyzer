"""Brute-force: many failed logons from one IP against one account.

MITRE ATT&CK T1110.001 - Brute Force: Password Guessing.
"""

from __future__ import annotations

from collections.abc import Sequence

from authwatch.config import DetectionConfig
from authwatch.detectors._common import (
    computers,
    find_bursts,
    format_duration,
    group_by,
    normalise_user,
    source_key,
)
from authwatch.models import Alert, AuthEvent, Severity

RULE = "Brute-force"
MITRE = ("T1110.001",)


def detect(events: Sequence[AuthEvent], config: DetectionConfig) -> list[Alert]:
    failures = [e for e in events if not e.success]
    groups = group_by(failures, lambda e: (source_key(e), normalise_user(e)))

    alerts: list[Alert] = []
    for (src, _), group in groups.items():
        for burst in find_bursts(group, config.bf_window, config.bf_threshold):
            first, last = burst[0], burst[-1]
            user = first.username or "?"
            alerts.append(
                Alert(
                    rule=RULE,
                    severity=Severity.HIGH,
                    mitre=MITRE,
                    source=src or "?",
                    usernames=(user,),
                    count=len(burst),
                    first_seen=first.timestamp,
                    last_seen=last.timestamp,
                    computers=computers(burst),
                    description=(
                        f"{len(burst)} failed logons for account '{user}' from {src} "
                        f"within {format_duration(last.timestamp - first.timestamp)}"
                    ),
                )
            )
    return alerts
