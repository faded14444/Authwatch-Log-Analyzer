from datetime import UTC, datetime, timedelta

import pytest

from authwatch.models import AuthEvent

BASE = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _make_event(
    seconds: float = 0,
    *,
    success: bool = False,
    user: str | None = "admin",
    ip: str | None = "10.0.0.5",
    computer: str | None = "DC01",
) -> AuthEvent:
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=seconds),
        success=success,
        username=user,
        source_ip=ip,
        computer=computer,
        source="test",
    )


@pytest.fixture
def make_event():
    """Factory for synthetic logon events: make_event(seconds_after_base, user=..., ...)."""
    return _make_event


@pytest.fixture
def failures(make_event):
    """failures(n, every=10, start=0, **kw) -> n failed logons `every` seconds apart."""

    def build(n: int, every: float = 10, start: float = 0, **kwargs):
        return [make_event(start + i * every, **kwargs) for i in range(n)]

    return build
