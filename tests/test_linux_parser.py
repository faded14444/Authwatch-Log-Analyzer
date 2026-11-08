import gzip
from datetime import UTC, datetime
from pathlib import Path

import pytest

from authwatch.parsers import LogParseError, ParseStats, iter_auth_log, iter_events
from authwatch.scan import collect_files, scan

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"
FAIL_ROOT = "Oct  1 09:14:02 web01 sshd[2101]: Failed password for root from 203.0.113.45 port 50122 ssh2"


def write_log(tmp_path, *lines, name="auth.log"):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def parse(path, year=2026, stats=None):
    return list(iter_auth_log(path, stats or ParseStats(), year=year))


def test_failed_password(tmp_path):
    (event,) = parse(write_log(tmp_path, FAIL_ROOT))
    assert event.success is False
    assert event.username == "root"
    assert event.source_ip == "203.0.113.45"
    assert event.computer == "web01"
    assert event.source == "linux-auth"
    assert event.timestamp == datetime(2026, 10, 1, 9, 14, 2, tzinfo=UTC)


def test_failed_password_for_invalid_user(tmp_path):
    line = "Oct  1 09:40:05 web01 sshd[1]: Failed password for invalid user admin from 198.51.100.23 port 4 ssh2"
    (event,) = parse(write_log(tmp_path, line))
    assert event.username == "admin"
    assert event.success is False


def test_accepted_publickey_is_a_success(tmp_path):
    line = "Oct  1 09:02:17 web01 sshd[1]: Accepted publickey for alice from 192.0.2.10 port 5 ssh2: ED25519 SHA256:abc"
    (event,) = parse(write_log(tmp_path, line))
    assert event.success is True
    assert event.username == "alice"


def test_message_repeated_counts_every_attempt(tmp_path):
    repeated = (
        "Oct  1 09:14:09 web01 sshd[2101]: message repeated 3 times: "
        "[ Failed password for root from 203.0.113.45 port 50122 ssh2]"
    )
    assert len(parse(write_log(tmp_path, FAIL_ROOT, repeated))) == 4


def test_rfc3339_timestamps_are_converted_to_utc(tmp_path):
    line = "2026-10-01T11:14:02.123456+02:00 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
    (event,) = parse(write_log(tmp_path, line))
    assert event.timestamp == datetime(2026, 10, 1, 9, 14, 2, 123456, tzinfo=UTC)


def test_openssh_sshd_session_tag(tmp_path):
    line = "Oct  1 09:46:57 web01 sshd-session[2335]: Failed password for invalid user test from 198.51.100.23 port 4 ssh2"
    assert parse(write_log(tmp_path, line))[0].username == "test"


def test_lines_about_the_same_attempt_are_not_double_counted(tmp_path):
    path = write_log(
        tmp_path,
        "Oct  1 09:40:03 web01 sshd[1]: Invalid user admin from 198.51.100.23 port 4",
        "Oct  1 09:14:02 web01 sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.45  user=root",
        "Oct  1 09:14:12 web01 sshd[1]: Connection closed by authenticating user root 203.0.113.45 port 5 [preauth]",
        "Oct  1 09:00:01 web01 CRON[1840]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "not a syslog line at all",
    )
    assert parse(path) == []


def test_year_rollover_uses_the_year_of_the_last_line(tmp_path):
    path = write_log(
        tmp_path,
        "Dec 31 23:59:58 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
        "Jan  1 00:00:03 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
    )
    assert [e.timestamp.year for e in parse(path, year=2026)] == [2025, 2026]


def test_impossible_date_is_counted_as_skipped(tmp_path):
    stats = ParseStats()
    path = write_log(tmp_path, FAIL_ROOT.replace("Oct  1", "Feb 30"))
    assert parse(path, stats=stats) == []
    assert stats.skipped_records == 1


def test_gzip_rotated_log(tmp_path):
    path = tmp_path / "auth.log.2.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write(FAIL_ROOT + "\n")
    assert len(parse(path)) == 1


def test_binary_file_is_rejected(tmp_path):
    path = tmp_path / "auth.log"
    path.write_bytes(b"\x00\x01\x02 binary junk")
    with pytest.raises(LogParseError):
        parse(path)


def test_iter_events_sends_text_files_to_the_linux_parser(tmp_path):
    path = write_log(tmp_path, FAIL_ROOT, name="secure")
    assert [e.source for e in iter_events(path, ParseStats(), linux_year=2026)] == ["linux-auth"]


def test_collect_files_finds_linux_logs(tmp_path):
    for name in ["auth.log", "auth.log.1", "auth.log.2.gz", "secure", "secure-20261001",
                 "syslog", "notes.txt", "Security.evtx"]:
        (tmp_path / name).touch()
    names = sorted(p.name for p in collect_files([tmp_path]))
    assert names == ["Security.evtx", "auth.log", "auth.log.1", "auth.log.2.gz",
                     "secure", "secure-20261001"]


def test_linux_usernames_are_case_sensitive(tmp_path):
    lines = [
        f"Oct  1 09:14:{i:02d} web01 sshd[1]: Failed password for {'Root' if i % 2 else 'root'} "
        "from 203.0.113.45 port 1 ssh2"
        for i in range(12)
    ]
    result = scan([write_log(tmp_path, *lines)], linux_year=2026)
    # 6 + 6 attempts on two *different* Linux accounts: below the brute-force threshold of 10
    assert [a.rule for a in result.alerts] == []


def test_sample_log_end_to_end():
    result = scan([SAMPLE], linux_year=2026)
    by_rule = {alert.rule: alert for alert in result.alerts}
    assert list(by_rule) == ["Success after failures", "Brute-force", "Password spraying"]

    assert by_rule["Success after failures"].usernames == ("root",)
    assert by_rule["Success after failures"].count == 15
    assert by_rule["Brute-force"].count == 15
    assert by_rule["Brute-force"].source == "203.0.113.45"

    spray = by_rule["Password spraying"]
    assert spray.source == "198.51.100.23"
    assert len(spray.usernames) == 7
    assert spray.count == 8
