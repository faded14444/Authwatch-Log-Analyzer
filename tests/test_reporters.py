import io
import json
from datetime import UTC, datetime

from rich.console import Console

from authwatch.config import DetectionConfig
from authwatch.detectors import brute_force
from authwatch.reporters import build_report, render, write_json
from authwatch.scan import ScanSummary


def _console():
    buffer = io.StringIO()
    return Console(file=buffer, width=200, color_system=None), buffer


def _summary(**overrides):
    values = dict(
        files=["Security.evtx"],
        records=50,
        auth_events=10,
        analyzed_events=10,
        first_event=datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
        last_event=datetime(2026, 10, 1, 9, 2, tzinfo=UTC),
    )
    values.update(overrides)
    return ScanSummary(**values)


def test_console_shows_alert_table(failures):
    alerts = brute_force.detect(failures(10), DetectionConfig())
    console, buffer = _console()
    render(alerts, _summary(), console)
    out = buffer.getvalue()
    assert "Brute-force" in out
    assert "10.0.0.5" in out
    assert "HIGH" in out
    assert "T1110.001" in out
    assert "10 failed logons for account 'admin'" in out
    assert "Summary:" in out


def test_console_without_alerts():
    console, buffer = _console()
    render([], _summary(), console)
    assert "No alerts." in buffer.getvalue()


def test_console_hints_when_no_logon_events():
    console, buffer = _console()
    render([], _summary(auth_events=0, analyzed_events=0), console)
    assert "Security" in buffer.getvalue()


def test_console_warns_about_skipped_records():
    console, buffer = _console()
    render([], _summary(skipped_records=3), console)
    assert "skipped 3 corrupted record(s)" in buffer.getvalue()


def test_json_report_structure(failures):
    alerts = brute_force.detect(failures(10), DetectionConfig())
    generated = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
    report = build_report(alerts, _summary(), generated_at=generated)
    assert report["tool"] == "authwatch"
    assert report["generated_at"] == "2026-11-08T12:00:00+00:00"
    assert report["summary"]["auth_events"] == 10
    assert report["alerts"][0]["rule"] == "Brute-force"
    assert report["alerts"][0]["severity"] == "high"
    assert report["alerts"][0]["first_seen"] == "2026-10-01T09:00:00+00:00"


def test_write_json_creates_valid_file(tmp_path, failures):
    alerts = brute_force.detect(failures(10), DetectionConfig())
    out = tmp_path / "alerts.json"
    write_json(alerts, _summary(), out)
    assert json.loads(out.read_text(encoding="utf-8"))["alerts"][0]["count"] == 10
