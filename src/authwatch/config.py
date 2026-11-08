"""Detection thresholds. Defaults are explained in the README."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class DetectionConfig:
    # Brute-force: many failures from one IP against one account.
    bf_threshold: int = 10
    bf_window: timedelta = timedelta(minutes=5)

    # Password spraying: failures from one IP against many different accounts.
    spray_min_users: int = 5
    spray_window: timedelta = timedelta(minutes=30)

    # Successful logon preceded by a run of failures from the same IP.
    saf_min_failures: int = 5
    saf_window: timedelta = timedelta(minutes=10)
