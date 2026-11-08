from datetime import timedelta

import pytest

from authwatch.detectors._common import find_bursts, format_duration, group_by, normalise_user

WINDOW = timedelta(minutes=5)


def test_find_bursts_needs_threshold_inside_window(failures):
    assert find_bursts(failures(4), WINDOW, threshold=5) == []
    assert len(find_bursts(failures(5), WINDOW, threshold=5)) == 1


def test_find_bursts_merges_continuous_activity(failures):
    bursts = find_bursts(failures(50, every=30), WINDOW, threshold=5)
    assert len(bursts) == 1
    assert len(bursts[0]) == 50


def test_find_bursts_splits_on_long_gap(failures):
    events = failures(5) + failures(5, start=3600)
    assert [len(b) for b in find_bursts(events, WINDOW, threshold=5)] == [5, 5]


def test_find_bursts_distinct_counts_unique_values(make_event):
    events = [make_event(i, user=u) for i, u in enumerate(["a", "a", "b", "b", "c"])]
    assert find_bursts(events, WINDOW, threshold=3, distinct=normalise_user)
    assert not find_bursts(events, WINDOW, threshold=4, distinct=normalise_user)


def test_group_by_keeps_order(make_event):
    events = [make_event(i, ip=ip) for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "1.1.1.1"])]
    groups = group_by(events, lambda e: e.source_ip)
    assert [e.timestamp for e in groups["1.1.1.1"]] == [events[0].timestamp, events[2].timestamp]


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(0, "0s"), (45, "45s"), (133, "2m 13s"), (300, "5m"), (3900, "1h 5m"), (7200, "2h")],
)
def test_format_duration(seconds, expected):
    assert format_duration(timedelta(seconds=seconds)) == expected
