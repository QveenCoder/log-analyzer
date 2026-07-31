import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cve_lookup import CveLookupError, lookup_cve, _extract_cvss_score, _extract_description


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-99999",
                "published": "2023-05-01T00:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "A sample vulnerability description for testing."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "baseSeverity": "HIGH",
                            "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"},
                        }
                    ]
                },
            }
        }
    ]
}


def _mock_urlopen(response_dict):
    """Build a context-manager mock that mimics urllib's urlopen()."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_dict).encode("utf-8")
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp
    return mock_cm


class TestCveLookup(unittest.TestCase):
    @patch("cve_lookup.urllib.request.urlopen")
    def test_lookup_parses_results(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(SAMPLE_NVD_RESPONSE)

        results = lookup_cve("openssh 7.2")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "CVE-2023-99999")
        self.assertEqual(results[0]["cvss"]["score"], 7.5)
        self.assertEqual(results[0]["cvss"]["severity"], "HIGH")

    @patch("cve_lookup.urllib.request.urlopen")
    def test_lookup_handles_empty_results(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"vulnerabilities": []})

        results = lookup_cve("some nonexistent package xyz")
        self.assertEqual(results, [])

    @patch("cve_lookup.urllib.request.urlopen")
    @patch("cve_lookup.time.sleep", return_value=None)  # skip real backoff delay in tests
    def test_lookup_raises_after_retries_exhausted(self, mock_sleep, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("network down")

        with self.assertRaises(CveLookupError):
            lookup_cve("openssh", retries=1)

    def test_extract_description_prefers_english(self):
        cve_item = {
            "descriptions": [
                {"lang": "fr", "value": "Une description"},
                {"lang": "en", "value": "An English description"},
            ]
        }
        self.assertEqual(_extract_description(cve_item), "An English description")

    def test_extract_cvss_falls_back_when_missing(self):
        self.assertEqual(_extract_cvss_score({})["severity"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
