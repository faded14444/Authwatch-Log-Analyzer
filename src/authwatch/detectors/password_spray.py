"""Password spraying: one IP tries a few passwords against many different accounts.

Attackers do this slowly on purpose to stay under account-lockout limits, so the
rule counts *distinct accounts* over a longer window instead of raw attempts.

MITRE ATT&CK T1110.003 - Brute Force: Password Spraying.
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

RULE = "Password spraying"
MITRE = ("T1110.003",)


def detect(events: Sequence[AuthEvent], config: DetectionConfig) -> list[Alert]:
    failures = [e for e in events if not e.success]
    groups = group_by(failures, source_key)

    alerts: list[Alert] = []
    for src, group in groups.items():
        bursts = find_bursts(
            group, config.spray_window, config.spray_min_users, distinct=normalise_user
        )
        for burst in bursts:
            first, last = burst[0], burst[-1]
            accounts: dict[str, str] = {}
            for event in burst:
                accounts.setdefault(normalise_user(event), event.username or "?")
            usernames = tuple(sorted(accounts.values(), key=str.lower))
            alerts.append(
                Alert(
                    rule=RULE,
                    severity=Severity.HIGH,
                    mitre=MITRE,
                    source=src or "?",
                    usernames=usernames,
                    count=len(burst),
                    first_seen=first.timestamp,
                    last_seen=last.timestamp,
                    computers=computers(burst),
                    description=(
                        f"{len(burst)} failed logons against {len(usernames)} different "
                        f"accounts from {src} within "
                        f"{format_duration(last.timestamp - first.timestamp)}"
                    ),
                )
            )
    return alerts
