from datetime import UTC, datetime
from pathlib import Path

import pytest

from authwatch.parsers.evtx_parser import (
    EvtxParseError,
    ParseStats,
    iter_evtx,
    parse_event_xml,
    parse_timestamp,
)

SAMPLES = sorted((Path(__file__).parent.parent / "samples").glob("*.evtx"))
NAMESPACE = ' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def event_xml(
    event_id=4625,
    system_time="2026-10-01 09:00:00.123456",
    user="admin",
    ip="10.0.0.5",
    logon_type="3",
    computer="DC01.corp.local",
    namespace=True,
):
    return (
        f"<Event{NAMESPACE if namespace else ''}>"
        "<System>"
        '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f'<EventID Qualifiers="">{event_id}</EventID>'
        f'<TimeCreated SystemTime="{system_time}"/>'
        f"<Computer>{computer}</Computer>"
        "</System>"
        "<EventData>"
        f'<Data Name="TargetUserName">{user}</Data>'
        '<Data Name="TargetDomainName">CORP</Data>'
        f'<Data Name="LogonType">{logon_type}</Data>'
        f'<Data Name="IpAddress">{ip}</Data>'
        "</EventData>"
        "</Event>"
    )


def test_failed_logon_is_parsed():
    event = parse_event_xml(event_xml())
    assert event is not None
    assert event.success is False
    assert event.username == "admin"
    assert event.domain == "CORP"
    assert event.source_ip == "10.0.0.5"
    assert event.logon_type == 3
    assert event.computer == "DC01.corp.local"
    assert event.source == "windows-evtx"
    assert event.timestamp == datetime(2026, 10, 1, 9, 0, 0, 123456, tzinfo=UTC)


def test_successful_logon_is_parsed():
    event = parse_event_xml(event_xml(event_id=4624, logon_type="10"))
    assert event.success is True
    assert event.logon_type == 10


def test_other_event_ids_are_ignored():
    assert parse_event_xml(event_xml(event_id=4688)) is None


def test_dash_means_missing_value():
    event = parse_event_xml(event_xml(ip="-", user="-"))
    assert event.source_ip is None
    assert event.username is None


def test_xml_without_namespace_still_works():
    assert parse_event_xml(event_xml(namespace=False)).username == "admin"


def test_missing_timestamp_is_an_error():
    xml = event_xml().replace('SystemTime="2026-10-01 09:00:00.123456"', "")
    with pytest.raises(ValueError):
        parse_event_xml(xml)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-01 09:00:00.123456", datetime(2026, 10, 1, 9, 0, 0, 123456, tzinfo=UTC)),
        ("2026-10-01T09:00:00.1234567Z", datetime(2026, 10, 1, 9, 0, 0, 123456, tzinfo=UTC)),
        ("2026-10-01T09:00:00Z", datetime(2026, 10, 1, 9, 0, tzinfo=UTC)),
        ("2026-10-01T11:00:00.5+02:00", datetime(2026, 10, 1, 9, 0, 0, 500000, tzinfo=UTC)),
    ],
)
def test_parse_timestamp_formats(raw, expected):
    assert parse_timestamp(raw) == expected


@pytest.mark.parametrize("content", [b"", b"hello, this is not a log"])
def test_non_evtx_file_is_rejected(tmp_path, content):
    path = tmp_path / "fake.evtx"
    path.write_bytes(content)
    with pytest.raises(EvtxParseError):
        list(iter_evtx(path))


@pytest.mark.skipif(not SAMPLES, reason="no sample .evtx files in samples/")
@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.name)
def test_real_sample_files_parse(sample):
    stats = ParseStats()
    events = list(iter_evtx(sample, stats))
    assert stats.files == 1
    assert stats.records > 0
    assert all(e.timestamp.tzinfo is not None for e in events)
