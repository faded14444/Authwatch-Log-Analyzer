from dataclasses import replace

import pytest

from authwatch.filters import filter_noise, is_noise


@pytest.mark.parametrize("ip", [None, "", "-", "127.0.0.1", "::1", "::ffff:127.0.0.1"])
def test_events_without_a_real_source_ip_are_noise(make_event, ip):
    assert is_noise(make_event(ip=ip))


@pytest.mark.parametrize("user", [None, "", "-", "DC01$", "ANONYMOUS LOGON", "anonymous logon"])
def test_system_and_empty_accounts_are_noise(make_event, user):
    assert is_noise(make_event(user=user))


@pytest.mark.parametrize("ip", ["10.0.0.5", "203.0.113.7", "fe80::1", "not-an-ip"])
def test_normal_events_are_kept(make_event, ip):
    assert not is_noise(make_event(ip=ip))


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1"])
def test_rdp_from_loopback_is_kept_because_it_means_tunnelling(make_event, ip):
    event = replace(make_event(ip=ip), logon_type=10)
    assert not is_noise(event)


def test_filter_noise_keeps_only_real_events(make_event):
    real = make_event()
    assert filter_noise([real, make_event(ip="127.0.0.1"), make_event(user="SRV$")]) == [real]
