"""Kerberos (4768, 4771) and NTLM (4776) events from domain controllers."""

from pathlib import Path

import pytest

from authwatch.config import DetectionConfig
from authwatch.detectors import password_spray
from authwatch.filters import is_noise
from authwatch.parsers import parse_event_xml
from authwatch.scan import scan

KERBEROS_SAMPLE = Path(__file__).parent.parent / "samples" / "kerberos_pwd_spray_4771.evtx"


def dc_event(event_id, status, user="admin", ip="172.16.66.1", workstation=None):
    fields = {"TargetUserName": user, "Status": status, "ServiceName": "krbtgt/CORP.LOCAL"}
    if ip is not None:
        fields["IpAddress"] = ip
    if workstation is not None:
        fields["Workstation"] = workstation
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f"<EventID>{event_id}</EventID>"
        '<TimeCreated SystemTime="2020-07-22 20:29:36.414827+00:00"/>'
        "<Computer>DC01.corp.local</Computer></System>"
        f"<EventData>{data}</EventData></Event>"
    )


@pytest.mark.parametrize(
    ("event_id", "status", "success"),
    [
        (4771, "0x00000018", False),  # Kerberos pre-auth failed: wrong password
        (4771, "0x00000012", False),  # account disabled / locked
        (4768, "0x00000006", False),  # TGT for an account that does not exist
        (4768, "0x00000000", True),  # TGT issued: successful authentication
        (4776, "0xc000006a", False),  # NTLM: wrong password
        (4776, "0xC0000064", False),  # NTLM: unknown account
        (4776, "0xC0000234", False),  # NTLM: account locked out
        (4776, "0x0", True),  # NTLM: credentials valid
    ],
)
def test_result_codes_map_to_success_or_failure(event_id, status, success):
    event = parse_event_xml(dc_event(event_id, status))
    assert event is not None
    assert event.success is success
    assert event.computer == "DC01.corp.local"


@pytest.mark.parametrize(
    ("event_id", "status"),
    [
        (4771, "0x00000025"),  # clock skew - a time problem, not an attack
        (4771, "0x00000017"),  # password expired - user knows the password
        (4776, "0xC0000071"),  # NTLM password expired
        (4768, "garbage"),
    ],
)
def test_irrelevant_result_codes_are_skipped(event_id, status):
    assert parse_event_xml(dc_event(event_id, status)) is None


def test_ipv4_mapped_ipv6_is_normalised():
    event = parse_event_xml(dc_event(4768, "0x0", ip="::ffff:172.16.66.1"))
    assert event.source_ip == "172.16.66.1"


def test_ntlm_event_uses_workstation_as_source():
    event = parse_event_xml(dc_event(4776, "0xC000006A", ip=None, workstation="\\\\WS-ATTACK"))
    assert event.source_ip is None
    assert event.source_host == "WS-ATTACK"
    assert not is_noise(event)  # a workstation name is enough to attribute the attempt


def test_event_without_ip_and_workstation_is_noise(make_event):
    assert is_noise(make_event(ip=None))


def test_ntlm_spray_is_grouped_by_workstation(make_event):
    from dataclasses import replace

    events = [
        replace(make_event(i, user=f"user{i}", ip=None), source_host="ws-attack" if i % 2 else "WS-ATTACK")
        for i in range(6)
    ]
    (alert,) = password_spray.detect(events, DetectionConfig())
    assert alert.source == "WS-ATTACK"  # host names are case-insensitive
    assert len(alert.usernames) == 6


@pytest.mark.skipif(not KERBEROS_SAMPLE.exists(), reason="download the sample - see samples/README.md")
def test_real_kerberos_spray_recording():
    """EVTX-ATTACK-SAMPLES: 9 accounts sprayed via Kerberos in 20 ms, then 'normal' logs on."""
    result = scan([KERBEROS_SAMPLE])
    assert [a.rule for a in result.alerts] == ["Success after failures", "Password spraying"]

    success, spray = result.alerts
    assert success.usernames == ("normal",)
    assert success.source == "172.16.66.1"  # the ::ffff: variant merged into the same alert
    assert "other accounts" in success.description
    assert spray.count == 9
    assert len(spray.usernames) == 9
