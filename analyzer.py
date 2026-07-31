#!/usr/bin/env python3
"""
log_analyzer.py

Parses authentication logs (SSH/auth-log style) and flags suspicious
login activity:
  - Brute-force attempts: N+ failed logins from the same IP within a
    configurable time window.
  - Off-hours logins: successful logins outside normal business hours.
  - Credential-stuffing pattern: one IP attempting many DIFFERENT
    usernames in a short window.

Designed to run against real auth.log-style input, but ships with a
synthetic sample log (sample_auth.log) so it works out of the box.

Usage:
    python analyzer.py sample_auth.log
    python analyzer.py sample_auth.log --threshold 4 --window 5 --json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

BUSINESS_HOURS_START = 6   # 6 AM
BUSINESS_HOURS_END = 20    # 8 PM


@dataclass
class LoginEvent:
    timestamp: datetime
    status: str
    user: str
    ip: str


@dataclass
class Findings:
    brute_force: list = field(default_factory=list)
    off_hours: list = field(default_factory=list)
    credential_stuffing: list = field(default_factory=list)

    def is_empty(self):
        return not (self.brute_force or self.off_hours or self.credential_stuffing)


def parse_log(path):
    """Parse a log file into a list of LoginEvent objects."""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            match = LOG_PATTERN.match(line.strip())
            if not match:
                continue
            try:
                ts = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            events.append(
                LoginEvent(
                    timestamp=ts,
                    status=match.group("status"),
                    user=match.group("user"),
                    ip=match.group("ip"),
                )
            )
    return events


def detect_brute_force(events, threshold=5, window_minutes=10):
    """Flag IPs with >= threshold failed logins within window_minutes."""
    failures_by_ip = defaultdict(list)
    for e in events:
        if e.status == "Failed":
            failures_by_ip[e.ip].append(e)

    findings = []
    for ip, fails in failures_by_ip.items():
        fails.sort(key=lambda e: e.timestamp)
        window = []
        for e in fails:
            window.append(e)
            # drop events that fell outside the window
            window = [w for w in window if (e.timestamp - w.timestamp).total_seconds() <= window_minutes * 60]
            if len(window) >= threshold:
                findings.append(
                    {
                        "ip": ip,
                        "attempt_count": len(window),
                        "window_minutes": window_minutes,
                        "first_attempt": window[0].timestamp.isoformat(),
                        "last_attempt": window[-1].timestamp.isoformat(),
                        "usernames_tried": sorted({w.user for w in window}),
                    }
                )
                break  # one finding per IP is enough
    return findings


def detect_off_hours(events):
    """Flag successful logins outside business hours."""
    findings = []
    for e in events:
        if e.status == "Accepted" and not (BUSINESS_HOURS_START <= e.timestamp.hour < BUSINESS_HOURS_END):
            findings.append(
                {
                    "ip": e.ip,
                    "user": e.user,
                    "timestamp": e.timestamp.isoformat(),
                    "hour": e.timestamp.hour,
                }
            )
    return findings


def detect_credential_stuffing(events, distinct_user_threshold=4, window_minutes=10):
    """Flag IPs attempting many distinct usernames in a short window."""
    attempts_by_ip = defaultdict(list)
    for e in events:
        attempts_by_ip[e.ip].append(e)

    findings = []
    for ip, attempts in attempts_by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)
        window = []
        for e in attempts:
            window.append(e)
            window = [w for w in window if (e.timestamp - w.timestamp).total_seconds() <= window_minutes * 60]
            distinct_users = {w.user for w in window}
            if len(distinct_users) >= distinct_user_threshold:
                findings.append(
                    {
                        "ip": ip,
                        "distinct_usernames": sorted(distinct_users),
                        "window_minutes": window_minutes,
                        "first_attempt": window[0].timestamp.isoformat(),
                        "last_attempt": window[-1].timestamp.isoformat(),
                    }
                )
                break
    return findings


def build_risk_summary(findings):
    """
    Aggregate findings by IP into a single 0-100 risk score.

    Weighting is intentionally simple and documented so it's easy to
    defend or tune in an interview: brute-force and credential-stuffing
    are stronger compromise indicators than a single off-hours login,
    so they're weighted higher. Scores are additive per IP and capped
    at 100.
    """
    WEIGHTS = {
        "brute_force": 45,
        "credential_stuffing": 40,
        "off_hours": 15,
    }

    scores = defaultdict(lambda: {"score": 0, "reasons": []})

    for f in findings.brute_force:
        ip = f["ip"]
        scores[ip]["score"] += WEIGHTS["brute_force"]
        scores[ip]["reasons"].append(
            f"brute-force ({f['attempt_count']} failed attempts in {f['window_minutes']}m)"
        )

    for f in findings.credential_stuffing:
        ip = f["ip"]
        scores[ip]["score"] += WEIGHTS["credential_stuffing"]
        scores[ip]["reasons"].append(
            f"credential-stuffing ({len(f['distinct_usernames'])} usernames tried)"
        )

    for f in findings.off_hours:
        ip = f["ip"]
        scores[ip]["score"] += WEIGHTS["off_hours"]
        scores[ip]["reasons"].append(f"off-hours login for {f['user']} at hour {f['hour']}")

    summary = [
        {"ip": ip, "score": min(data["score"], 100), "reasons": data["reasons"]}
        for ip, data in scores.items()
    ]
    summary.sort(key=lambda x: x["score"], reverse=True)
    return summary


def analyze(path, threshold=5, window_minutes=10):
    events = parse_log(path)
    if not events:
        print(f"No parseable auth events found in {path}", file=sys.stderr)

    findings = Findings(
        brute_force=detect_brute_force(events, threshold=threshold, window_minutes=window_minutes),
        off_hours=detect_off_hours(events),
        credential_stuffing=detect_credential_stuffing(events, window_minutes=window_minutes),
    )
    return events, findings


def print_report(events, findings):
    print("=" * 60)
    print("SUSPICIOUS LOGIN ACTIVITY REPORT")
    print("=" * 60)
    print(f"Total events parsed: {len(events)}\n")

    print(f"[!] Brute-force candidates: {len(findings.brute_force)}")
    for f in findings.brute_force:
        print(f"    IP {f['ip']}: {f['attempt_count']} failed attempts "
              f"between {f['first_attempt']} and {f['last_attempt']} "
              f"(usernames tried: {', '.join(f['usernames_tried'])})")

    print(f"\n[!] Off-hours successful logins: {len(findings.off_hours)}")
    for f in findings.off_hours:
        print(f"    {f['user']}@{f['ip']} logged in at {f['timestamp']} (hour {f['hour']})")

    print(f"\n[!] Credential-stuffing candidates: {len(findings.credential_stuffing)}")
    for f in findings.credential_stuffing:
        print(f"    IP {f['ip']} tried {len(f['distinct_usernames'])} usernames "
              f"between {f['first_attempt']} and {f['last_attempt']}: "
              f"{', '.join(f['distinct_usernames'])}")

    if findings.is_empty():
        print("\nNo suspicious activity detected.")
        print("=" * 60)
        return

    risk_summary = build_risk_summary(findings)
    print(f"\n[*] Top offenders by risk score:")
    for entry in risk_summary[:10]:
        print(f"    {entry['ip']}  —  risk {entry['score']}/100")
        for reason in entry["reasons"]:
            print(f"        - {reason}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Analyze auth logs for suspicious login activity.")
    parser.add_argument("logfile", help="Path to the auth log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed-attempt threshold for brute-force detection (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="Time window in minutes (default: 10)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON instead of a text report")
    args = parser.parse_args()

    events, findings = analyze(args.logfile, threshold=args.threshold, window_minutes=args.window)

    if args.json:
        print(json.dumps(
            {
                "total_events": len(events),
                "brute_force": findings.brute_force,
                "off_hours": findings.off_hours,
                "credential_stuffing": findings.credential_stuffing,
                "risk_summary": build_risk_summary(findings),
            },
            indent=2,
        ))
    else:
        print_report(events, findings)


if __name__ == "__main__":
    main()
