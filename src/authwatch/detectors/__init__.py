"""Detection rules. Each rule is a function: (sorted events, config) -> list[Alert]."""

from __future__ import annotations

from collections.abc import Iterable

from authwatch.config import DetectionConfig
from authwatch.detectors import brute_force, password_spray, success_after_failures
from authwatch.models import Alert, AuthEvent

DETECTORS = (
    brute_force.detect,
    password_spray.detect,
    success_after_failures.detect,
)


def run_detections(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Alert]:
    """Run every rule and return alerts, most severe first, then oldest first."""
    config = config or DetectionConfig()
    ordered = sorted(events, key=lambda e: e.timestamp)
    alerts = [alert for detect in DETECTORS for alert in detect(ordered, config)]
    alerts.sort(key=lambda a: (-a.severity, a.first_seen, a.rule, a.source_ip))
    return alerts


__all__ = ["DETECTORS", "run_detections"]
