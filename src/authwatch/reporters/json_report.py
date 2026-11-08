"""Machine-readable report - easy to feed into a SIEM, a script or jq."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from authwatch import __version__
from authwatch.models import Alert

if TYPE_CHECKING:
    from authwatch.scan import ScanSummary


def build_report(
    alerts: Sequence[Alert], summary: ScanSummary, generated_at: datetime | None = None
) -> dict:
    generated_at = generated_at or datetime.now(UTC)
    return {
        "tool": "authwatch",
        "version": __version__,
        "generated_at": generated_at.isoformat(),
        "summary": summary.to_dict(),
        "alerts": [alert.to_dict() for alert in alerts],
    }


def write_json(alerts: Sequence[Alert], summary: ScanSummary, path: Path) -> None:
    report = build_report(alerts, summary)
    Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
