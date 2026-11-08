import io
import json

import pytest
from rich.console import Console

from authwatch import scan as scan_module
from authwatch.cli import EXIT_ALERTS, EXIT_ERROR, EXIT_OK, main
from authwatch.scan import collect_files, scan


def fake_parser(events_by_name):
    """Stand-in for iter_events: returns prepared events for each file name."""

    def parse(path, stats, **_):
        events = events_by_name.get(path.name, [])
        stats.files += 1
        stats.records += len(events)
        yield from events

    return parse


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    code = main(
        list(args),
        console=Console(file=out, width=200, color_system=None),
        err_console=Console(file=err, width=200, color_system=None),
    )
    return code, out.getvalue(), err.getvalue()


# --- collect_files / scan ---------------------------------------------------


def test_collect_files_finds_evtx_recursively(tmp_path):
    (tmp_path / "a.evtx").touch()
    (tmp_path / "B.EVTX").touch()
    (tmp_path / "notes.txt").touch()
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.evtx").touch()
    names = sorted(p.name for p in collect_files([tmp_path]))
    assert names == ["B.EVTX", "a.evtx", "c.evtx"]


def test_collect_files_deduplicates(tmp_path):
    file = tmp_path / "a.evtx"
    file.touch()
    assert collect_files([file, tmp_path]) == [file]


def test_collect_files_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        collect_files([tmp_path / "nope.evtx"])


def test_scan_filters_noise_and_fills_summary(tmp_path, failures, make_event):
    file = tmp_path / "Security.evtx"
    events = failures(10) + [make_event(5, ip="127.0.0.1")]
    result = scan([file], parse=fake_parser({file.name: events}))
    assert result.summary.auth_events == 11
    assert result.summary.analyzed_events == 10
    assert result.summary.first_event == events[0].timestamp
    assert [a.rule for a in result.alerts] == ["Brute-force"]


# --- CLI ----------------------------------------------------------------------


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "Security.evtx"
    path.touch()
    return path


def test_cli_reports_alerts_and_writes_json(monkeypatch, log_file, failures, make_event):
    events = failures(10) + [make_event(200, success=True)]
    monkeypatch.setattr(scan_module, "iter_events", fake_parser({log_file.name: events}))
    out_json = log_file.parent / "alerts.json"

    code, out, _ = run_cli("scan", str(log_file), "--output", str(out_json))

    assert code == EXIT_ALERTS
    assert "CRITICAL" in out and "Brute-force" in out
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert [a["rule"] for a in report["alerts"]] == ["Success after failures", "Brute-force"]


def test_cli_without_alerts_exits_zero(monkeypatch, log_file, failures):
    monkeypatch.setattr(scan_module, "iter_events", fake_parser({log_file.name: failures(3)}))
    code, out, _ = run_cli("scan", str(log_file))
    assert code == EXIT_OK
    assert "No alerts." in out


def test_cli_min_severity_filters_alerts(monkeypatch, log_file, failures):
    monkeypatch.setattr(scan_module, "iter_events", fake_parser({log_file.name: failures(10)}))
    code, out, _ = run_cli("scan", str(log_file), "--min-severity", "critical")
    assert code == EXIT_OK
    assert "No alerts." in out


def test_cli_thresholds_are_configurable(monkeypatch, log_file, failures):
    monkeypatch.setattr(scan_module, "iter_events", fake_parser({log_file.name: failures(3)}))
    code, out, _ = run_cli("scan", str(log_file), "--bf-threshold", "3")
    assert code == EXIT_ALERTS
    assert "Brute-force" in out


def test_cli_missing_path_is_an_error(tmp_path):
    code, _, err = run_cli("scan", str(tmp_path / "missing.evtx"))
    assert code == EXIT_ERROR
    assert "does not exist" in err


def test_cli_folder_without_evtx_is_an_error(tmp_path):
    code, _, err = run_cli("scan", str(tmp_path))
    assert code == EXIT_ERROR
    assert "no supported log files" in err


def test_cli_rejects_file_that_is_not_evtx(tmp_path):
    bogus = tmp_path / "bogus.evtx"
    bogus.write_text("definitely not a Windows log")
    code, _, err = run_cli("scan", str(bogus))
    assert code == EXIT_ERROR
    assert "not an EVTX file" in err


def test_cli_rejects_invalid_threshold(log_file):
    with pytest.raises(SystemExit) as exc:
        run_cli("scan", str(log_file), "--bf-threshold", "0")
    assert exc.value.code == 2
