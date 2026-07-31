import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzer import (
    Findings,
    LoginEvent,
    build_risk_summary,
    detect_brute_force,
    detect_off_hours,
    detect_credential_stuffing,
    parse_log,
)


class TestParsing(unittest.TestCase):
    def test_parse_sample_log(self):
        path = os.path.join(os.path.dirname(__file__), "..", "sample_auth.log")
        events = parse_log(path)
        self.assertTrue(len(events) > 0)
        self.assertTrue(all(isinstance(e, LoginEvent) for e in events))


class TestBruteForce(unittest.TestCase):
    def test_detects_repeated_failures_same_ip(self):
        base = datetime(2026, 1, 1, 12, 0, 0)
        events = [
            LoginEvent(base, "Failed", "admin", "1.2.3.4"),
            LoginEvent(base, "Failed", "root", "1.2.3.4"),
            LoginEvent(base, "Failed", "test", "1.2.3.4"),
            LoginEvent(base, "Failed", "guest", "1.2.3.4"),
            LoginEvent(base, "Failed", "oracle", "1.2.3.4"),
        ]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ip"], "1.2.3.4")

    def test_no_finding_below_threshold(self):
        base = datetime(2026, 1, 1, 12, 0, 0)
        events = [LoginEvent(base, "Failed", "admin", "1.2.3.4")]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 0)


class TestOffHours(unittest.TestCase):
    def test_flags_late_night_login(self):
        late = datetime(2026, 1, 1, 3, 0, 0)
        events = [LoginEvent(late, "Accepted", "cwhite", "5.6.7.8")]
        findings = detect_off_hours(events)
        self.assertEqual(len(findings), 1)

    def test_ignores_business_hours_login(self):
        daytime = datetime(2026, 1, 1, 10, 0, 0)
        events = [LoginEvent(daytime, "Accepted", "jsmith", "5.6.7.8")]
        findings = detect_off_hours(events)
        self.assertEqual(len(findings), 0)


class TestCredentialStuffing(unittest.TestCase):
    def test_flags_many_distinct_usernames(self):
        base = datetime(2026, 1, 1, 3, 0, 0)
        events = [
            LoginEvent(base, "Failed", "user1", "9.9.9.9"),
            LoginEvent(base, "Failed", "user2", "9.9.9.9"),
            LoginEvent(base, "Failed", "user3", "9.9.9.9"),
            LoginEvent(base, "Failed", "user4", "9.9.9.9"),
        ]
        findings = detect_credential_stuffing(events, distinct_user_threshold=4, window_minutes=10)
        self.assertEqual(len(findings), 1)


class TestRiskSummary(unittest.TestCase):
    def test_scores_and_ranks_by_severity(self):
        findings = Findings(
            brute_force=[{"ip": "1.1.1.1", "attempt_count": 5, "window_minutes": 10}],
            off_hours=[{"ip": "2.2.2.2", "user": "bob", "hour": 3, "timestamp": "2026-01-01T03:00:00"}],
            credential_stuffing=[],
        )
        summary = build_risk_summary(findings)
        self.assertEqual(summary[0]["ip"], "1.1.1.1")  # brute-force outranks off-hours
        self.assertGreater(summary[0]["score"], summary[1]["score"])

    def test_combined_signals_increase_score(self):
        findings = Findings(
            brute_force=[{"ip": "3.3.3.3", "attempt_count": 5, "window_minutes": 10}],
            off_hours=[{"ip": "3.3.3.3", "user": "eve", "hour": 2, "timestamp": "2026-01-01T02:00:00"}],
            credential_stuffing=[{"ip": "3.3.3.3", "distinct_usernames": ["a", "b", "c", "d"], "window_minutes": 10}],
        )
        summary = build_risk_summary(findings)
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["score"], 100)  # capped even though weights sum higher
        self.assertEqual(len(summary[0]["reasons"]), 3)

    def test_empty_findings_returns_empty_summary(self):
        findings = Findings()
        self.assertEqual(build_risk_summary(findings), [])


if __name__ == "__main__":
    unittest.main()
