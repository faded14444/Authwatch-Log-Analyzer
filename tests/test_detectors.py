from authwatch.config import DetectionConfig
from authwatch.detectors import (
    brute_force,
    password_spray,
    run_detections,
    success_after_failures,
)
from authwatch.models import Severity

CFG = DetectionConfig()  # defaults: bf 10/5min, spray 5 users/30min, saf 5/10min


class TestBruteForce:
    def test_threshold_reached_gives_one_alert(self, failures):
        alerts = brute_force.detect(failures(10), CFG)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.count == 10
        assert alert.severity is Severity.HIGH
        assert alert.mitre == ("T1110.001",)
        assert alert.usernames == ("admin",)
        assert alert.source == "10.0.0.5"
        assert alert.computers == ("DC01",)

    def test_below_threshold_is_quiet(self, failures):
        assert brute_force.detect(failures(9), CFG) == []

    def test_slow_failures_outside_window_are_quiet(self, failures):
        # 10 failures over 9 minutes: no 5-minute window holds more than 6
        assert brute_force.detect(failures(10, every=60), CFG) == []

    def test_long_attack_is_a_single_alert(self, failures):
        alerts = brute_force.detect(failures(100), CFG)
        assert len(alerts) == 1
        assert alerts[0].count == 100

    def test_separate_attacks_give_separate_alerts(self, failures):
        events = failures(10) + failures(10, start=3600)
        assert len(brute_force.detect(events, CFG)) == 2

    def test_different_ips_are_not_combined(self, failures):
        events = failures(5, ip="10.0.0.5") + failures(5, start=1, ip="10.0.0.6")
        assert brute_force.detect(sorted(events, key=lambda e: e.timestamp), CFG) == []

    def test_usernames_are_case_insensitive(self, make_event):
        events = [make_event(i, user="Admin" if i % 2 else "admin") for i in range(10)]
        assert len(brute_force.detect(events, CFG)) == 1

    def test_successful_logons_are_ignored(self, failures):
        assert brute_force.detect(failures(10, success=True), CFG) == []

    def test_threshold_is_configurable(self, failures):
        assert len(brute_force.detect(failures(3), DetectionConfig(bf_threshold=3))) == 1


class TestPasswordSpray:
    def test_many_accounts_from_one_ip(self, make_event):
        events = [make_event(i * 60, user=f"user{i}") for i in range(6)]
        alerts = password_spray.detect(events, CFG)
        assert len(alerts) == 1
        assert alerts[0].severity is Severity.HIGH
        assert alerts[0].mitre == ("T1110.003",)
        assert len(alerts[0].usernames) == 6
        assert "6 different accounts" in alerts[0].description

    def test_few_accounts_is_quiet(self, make_event):
        events = [make_event(i * 60, user=f"user{i}") for i in range(4)]
        assert password_spray.detect(events, CFG) == []

    def test_one_account_hammered_is_brute_force_not_spray(self, failures):
        assert password_spray.detect(failures(30), CFG) == []

    def test_very_slow_spray_outside_window_is_quiet(self, make_event):
        events = [make_event(i * 31 * 60, user=f"user{i}") for i in range(6)]
        assert password_spray.detect(events, CFG) == []

    def test_account_names_are_case_insensitive(self, make_event):
        users = ["Admin", "admin", "ADMIN", "bob", "carol"]  # only 3 distinct accounts
        events = [make_event(i, user=u) for i, u in enumerate(users)]
        assert password_spray.detect(events, CFG) == []


class TestSuccessAfterFailures:
    def test_success_after_failures_is_critical(self, failures, make_event):
        success = make_event(70, success=True)
        alerts = success_after_failures.detect(failures(6) + [success], CFG)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity is Severity.CRITICAL
        assert alert.count == 6
        assert alert.last_seen == success.timestamp
        assert "same account" in alert.description

    def test_success_without_failures_is_quiet(self, make_event):
        assert success_after_failures.detect([make_event(0, success=True)], CFG) == []

    def test_too_few_failures_is_quiet(self, failures, make_event):
        events = failures(4) + [make_event(50, success=True)]
        assert success_after_failures.detect(events, CFG) == []

    def test_failures_from_another_ip_do_not_count(self, failures, make_event):
        events = failures(6, ip="10.9.9.9") + [make_event(70, success=True)]
        assert success_after_failures.detect(events, CFG) == []

    def test_old_failures_outside_window_do_not_count(self, failures, make_event):
        events = failures(6) + [make_event(20 * 60, success=True)]
        assert success_after_failures.detect(events, CFG) == []

    def test_spray_then_success_on_other_account(self, make_event):
        events = [make_event(i * 10, user=f"user{i}") for i in range(6)]
        events.append(make_event(100, success=True, user="svc_backup"))
        alerts = success_after_failures.detect(events, CFG)
        assert len(alerts) == 1
        assert "other accounts" in alerts[0].description

    def test_repeated_successes_extend_one_alert(self, failures, make_event):
        second = make_event(90, success=True)
        events = failures(6) + [make_event(70, success=True), second]
        alerts = success_after_failures.detect(events, CFG)
        assert len(alerts) == 1
        assert alerts[0].last_seen == second.timestamp


def test_run_detections_sorts_most_severe_first(failures, make_event):
    events = failures(10) + [make_event(200, success=True)]
    alerts = run_detections(reversed(events))  # unsorted input must be handled
    assert [a.rule for a in alerts] == ["Success after failures", "Brute-force"]


def test_run_detections_on_empty_input():
    assert run_detections([]) == []
