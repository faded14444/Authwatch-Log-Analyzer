"""Successful logon right after a run of failures from the same IP.

This is the alert an analyst looks at first: the attack may have worked.

MITRE ATT&CK T1110 (Brute Force) leading to T1078 (Valid Accounts).
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections.abc import Sequence

from authwatch.config import DetectionConfig
from authwatch.detectors._common import computers, group_by, normalise_user, source_key
from authwatch.models import Alert, AuthEvent, Severity

RULE = "Success after failures"
MITRE = ("T1110", "T1078")


def detect(events: Sequence[AuthEvent], config: DetectionConfig) -> list[Alert]:
    failures_by_source = group_by((e for e in events if not e.success), source_key)
    successes_by_source = group_by((e for e in events if e.success), source_key)

    alerts: list[Alert] = []
    for src, successes in successes_by_source.items():
        failures = failures_by_source.get(src, [])
        if len(failures) < config.saf_min_failures:
            continue
        failure_times = [f.timestamp for f in failures]
        open_alerts: dict[str, Alert] = {}  # one alert per account per attack

        for success in successes:
            start = bisect_left(failure_times, success.timestamp - config.saf_window)
            end = bisect_right(failure_times, success.timestamp)
            prior = failures[start:end]
            if len(prior) < config.saf_min_failures:
                continue

            user_key = normalise_user(success)
            previous = open_alerts.get(user_key)
            if previous and success.timestamp - previous.last_seen <= config.saf_window:
                previous.last_seen = success.timestamp  # same attack, extend it
                continue

            user = success.username or "?"
            same_account = any(normalise_user(f) == user_key for f in prior)
            target = "against this same account" if same_account else "against other accounts"
            alert = Alert(
                rule=RULE,
                severity=Severity.CRITICAL,
                mitre=MITRE,
                source=src or "?",
                usernames=(user,),
                count=len(prior),
                first_seen=prior[0].timestamp,
                last_seen=success.timestamp,
                computers=computers([*prior, success]),
                description=(
                    f"Account '{user}' logged on successfully from {src} after "
                    f"{len(prior)} failed attempts {target} - verify this logon"
                ),
            )
            open_alerts[user_key] = alert
            alerts.append(alert)
    return alerts
