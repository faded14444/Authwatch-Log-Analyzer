import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from rich.console import Console

from authwatch.cli import EXIT_ALERTS, main
from authwatch.config import DetectionConfig
from authwatch.detectors import run_detections
from authwatch.reporters.html_report import build_html, choose_bucket, timeline_svg
from authwatch.scan import ScanSummary

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"
GENERATED = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def _summary(events):
    return ScanSummary(
        files=["Security.evtx"],
        auth_events=len(events),
        analyzed_events=len(events),
        first_event=min((e.timestamp for e in events), default=None),
        last_event=max((e.timestamp for e in events), default=None),
    )


def _report(events):
    alerts = run_detections(events, DetectionConfig())
    return build_html(alerts, _summary(events), events, generated_at=GENERATED), alerts


@pytest.mark.parametrize(
    ("span", "bucket"),
    [
        (timedelta(0), 1),
        (timedelta(seconds=90), 1),
        (timedelta(minutes=10), 10),
        (timedelta(hours=1), 60),
        (timedelta(hours=2), 300),  # exactly 120 one-minute bars would be one too many
        (timedelta(days=1), 900),
        (timedelta(days=20), 6 * 3600),
        (timedelta(days=3000), None),  # beyond the list: size is computed
    ],
)
def test_choose_bucket_keeps_bars_readable(span, bucket):
    size = choose_bucket(span)
    assert span.total_seconds() / size <= 120
    if bucket is not None:
        assert size == bucket


def test_report_contains_alerts_timeline_and_mitre_links(failures, make_event):
    html, alerts = _report(failures(10) + [make_event(200, success=True)])
    assert html.startswith("<!doctype html>")
    assert "Success after failures" in html and "Brute-force" in html
    assert 'class="badge sev-critical"' in html
    assert 'href="https://attack.mitre.org/techniques/T1110/001/"' in html
    assert html.count('class="bar-fail"') >= 1
    assert html.count('class="bar-ok"') == 1
    assert html.count('class="band band-') == len(alerts)


def test_values_from_logs_are_escaped(failures):
    evil = '<script>alert("pwned")</script>'
    html, _ = _report(failures(10, user=evil))
    assert "<script" not in html
    assert "&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt;" in html


def test_report_is_self_contained(failures):
    html, _ = _report(failures(10))
    assert "http://" not in html
    # the only external URLs are links to MITRE ATT&CK, never loaded resources
    assert all(url.startswith("https://attack.mitre.org/") for url in
               [part.split('"')[0] for part in html.split('href="')[1:]])
    assert "<script" not in html and "<link" not in html


def test_empty_report():
    html = build_html([], _summary([]), [], generated_at=GENERATED)
    assert "No alerts." in html
    assert "No logon events to plot." in html
    assert "No logon events found" in html


def test_timeline_has_one_bar_group_per_active_bucket(make_event):
    events = [make_event(0), make_event(1), make_event(120, success=True)]
    svg = timeline_svg(events, [])
    assert svg.count("<g><title>") == 2  # two buckets with activity, empty ones skipped


def test_cli_writes_html_report(tmp_path):
    out = tmp_path / "report.html"
    code = main(
        ["scan", str(SAMPLE), "--linux-year", "2026", "--html", str(out)],
        console=Console(file=io.StringIO(), width=200),
        err_console=Console(file=io.StringIO(), width=200),
    )
    assert code == EXIT_ALERTS
    html = out.read_text(encoding="utf-8")
    assert "Password spraying" in html
    assert "203.0.113.45" in html
