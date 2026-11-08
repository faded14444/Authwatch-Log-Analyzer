"""Helpers shared by detection rules: grouping and the sliding time window."""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Callable, Hashable, Iterable, Sequence
from datetime import timedelta
from typing import TypeVar

from authwatch.models import AuthEvent

K = TypeVar("K", bound=Hashable)


def group_by(
    events: Iterable[AuthEvent], key: Callable[[AuthEvent], K]
) -> dict[K, list[AuthEvent]]:
    """Group events, keeping their original (time) order inside each group."""
    groups: dict[K, list[AuthEvent]] = {}
    for event in events:
        groups.setdefault(key(event), []).append(event)
    return groups


def find_bursts(
    events: Sequence[AuthEvent],
    window: timedelta,
    threshold: int,
    distinct: Callable[[AuthEvent], Hashable] | None = None,
) -> list[list[AuthEvent]]:
    """Find attack bursts in time-sorted events using a sliding window.

    A burst starts when some `window`-long period contains at least `threshold`
    events (or `threshold` distinct values of `distinct(event)` when given).
    It keeps growing while the next event arrives within `window` of the
    previous one, so one long attack produces one burst - not one per window.
    """
    bursts: list[list[AuthEvent]] = []
    current: list[AuthEvent] | None = None
    in_window: deque[AuthEvent] = deque()
    distinct_counts: Counter[Hashable] = Counter()

    for event in events:
        in_window.append(event)
        if distinct:
            distinct_counts[distinct(event)] += 1
        while event.timestamp - in_window[0].timestamp > window:
            old = in_window.popleft()
            if distinct:
                distinct_counts[distinct(old)] -= 1
                if distinct_counts[distinct(old)] == 0:
                    del distinct_counts[distinct(old)]

        if current is not None:
            if event.timestamp - current[-1].timestamp <= window:
                current.append(event)
                continue
            bursts.append(current)
            current = None

        size = len(distinct_counts) if distinct else len(in_window)
        if size >= threshold:
            current = list(in_window)

    if current is not None:
        bursts.append(current)
    return bursts


def normalise_user(event: AuthEvent) -> str:
    """Account key for grouping.

    Windows account names are case-insensitive (ADMIN == admin); Linux user names
    are case-sensitive (Root and root are two different accounts).
    """
    name = event.username or ""
    return name if event.source == "linux-auth" else name.lower()


def computers(events: Iterable[AuthEvent]) -> tuple[str, ...]:
    return tuple(sorted({e.computer for e in events if e.computer}))


def format_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"
