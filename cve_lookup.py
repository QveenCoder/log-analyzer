#!/usr/bin/env python3
"""
cve_lookup.py

Looks up known CVEs for a given piece of software using the NVD
(National Vulnerability Database) REST API v2.0 — no API key required
for light usage, though NIST recommends one for higher rate limits.

This is meant to plug into log_analyzer.py's findings: once you know
which software/version is running on a flagged host, you can check
whether it has known, exploitable vulnerabilities.

Usage:
    python cve_lookup.py "openssh 7.2"
    python cve_lookup.py "apache log4j" --limit 3 --json

API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveLookupError(Exception):
    """Raised when the NVD API can't be reached or returns bad data."""


def _extract_cvss_score(cve_item):
    """Pull the best-available CVSS score out of an NVD CVE item."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0]["cvssData"]
            return {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": metrics[key][0].get("baseSeverity", data.get("baseSeverity")),
            }
    return {"version": None, "score": None, "severity": "UNKNOWN"}


def _extract_description(cve_item):
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def lookup_cve(keyword, results_limit=5, timeout=10, retries=2):
    """
    Query the NVD API for CVEs matching a free-text keyword
    (e.g. "openssh 7.2", "log4j 2.14").

    Returns a list of dicts: {id, description, cvss, published}.
    Raises CveLookupError on network failure after retries.
    """
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": results_limit,
    })
    url = f"{NVD_API_URL}?{params}"

    last_error = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "portfolio-cve-lookup/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_error = e
            if attempt < retries:
                time.sleep(2 ** attempt)  # simple backoff for NVD's rate limiting
            continue
    else:
        raise CveLookupError(f"Failed to reach NVD API after {retries + 1} attempts: {last_error}")

    results = []
    for vuln in payload.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        results.append({
            "id": cve_item.get("id"),
            "published": cve_item.get("published"),
            "description": _extract_description(cve_item),
            "cvss": _extract_cvss_score(cve_item),
        })
    return results


def print_results(keyword, results):
    print(f"CVE results for: {keyword}")
    print("=" * 60)
    if not results:
        print("No CVEs found (or NVD returned no matches for this keyword).")
        return
    for r in results:
        cvss = r["cvss"]
        score_str = f"{cvss['score']} ({cvss['severity']})" if cvss["score"] is not None else "N/A"
        print(f"{r['id']}  —  CVSS {score_str}  —  published {r['published']}")
        desc = r["description"]
        print(f"    {desc[:200]}{'...' if len(desc) > 200 else ''}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Look up CVEs for a piece of software via the NVD API.")
    parser.add_argument("keyword", help='Search term, e.g. "openssh 7.2"')
    parser.add_argument("--limit", type=int, default=5, help="Max results to return (default: 5)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    try:
        results = lookup_cve(args.keyword, results_limit=args.limit)
    except CveLookupError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(args.keyword, results)


if __name__ == "__main__":
    main()
