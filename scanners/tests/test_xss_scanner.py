import pytest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, "../xss")
sys.path.insert(0, "../../scanner-core")

from sentinel_core import ScanTarget, ScanConfig, Severity


SCAN_ID = "test-scan-xss-001"


@pytest.fixture
def config():
    return ScanConfig(max_requests_per_second=5, request_timeout=10)


class TestReflectedXss:

    def test_unencoded_reflection_produces_finding(self, config):
        from scanners.xss.scanner import XssScanner
        scanner = XssScanner()
        target = ScanTarget(url="http://localhost:3000", scan_id=SCAN_ID, domain="localhost")

        mock_response = MagicMock()

        with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
            crawl_response = MagicMock()
            crawl_response.text = '<form method="get"><input name="q" value=""></form>'
            mock_get.return_value = crawl_response

            def side_effect(url, **kwargs):
                params = kwargs.get("params", {})
                payload = params.get("q", "")
                r = MagicMock()
                r.text = f"<html>Result: {payload}</html>"
                return r

            mock_get.side_effect = side_effect

            findings = scanner.scan(target, config)
            xss_findings = [f for f in findings if "XSS" in f.title]
            assert len(xss_findings) > 0, "Expected XSS finding when payload reflects unencoded"

    def test_encoded_reflection_no_finding(self, config):
        from scanners.xss.scanner import XssScanner
        scanner = XssScanner()
        target = ScanTarget(url="http://localhost:3000", scan_id=SCAN_ID, domain="localhost")

        with patch("requests.get") as mock_get:
            crawl_response = MagicMock()
            crawl_response.text = '<form method="get"><input name="q" value=""></form>'

            def side_effect(url, **kwargs):
                params = kwargs.get("params", {})
                payload = params.get("q", "")
                r = MagicMock()
                encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                r.text = f"<html>Result: {encoded}</html>"
                return r

            mock_get.side_effect = side_effect
            findings = scanner.scan(target, config)
            xss_findings = [f for f in findings if "XSS" in f.title and "Header" not in f.title]
            assert len(xss_findings) == 0, "Should not produce XSS finding when payload is HTML-encoded"
