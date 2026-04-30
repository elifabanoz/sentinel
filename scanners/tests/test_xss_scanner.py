import sys
import os
import importlib.util
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner-core"))

# Load XSS scanner from specific file to avoid name conflict
_spec = importlib.util.spec_from_file_location(
    "xss_scanner",
    os.path.join(os.path.dirname(__file__), "..", "xss", "scanner.py")
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
XssScanner = _module.XssScanner

from sentinel_core import ScanTarget, ScanConfig, Severity

SCAN_ID = "test-scan-xss-001"
config = ScanConfig(max_requests_per_second=5, request_timeout=10)


@pytest.fixture
def scanner():
    return XssScanner()


class TestReflectedXss:

    def test_unencoded_reflection_produces_finding(self, scanner):
        # Should produce finding when payload is not encoded
        target = ScanTarget(url="http://example.com", scan_id=SCAN_ID, domain="example.com")

        crawl_html = '<form method="get" action="/search"><input name="q" value=""></form>'

        def mock_get(url, **kwargs):
            r = MagicMock()
            params = kwargs.get("params", {})
            q = params.get("q", "")
            if q:
                r.text = f"<html><body>Result: {q}</body></html>"
            else:
                r.text = crawl_html
            return r

        with patch("requests.get", side_effect=mock_get):
            with patch("requests.post", return_value=MagicMock(text="")):
                findings = scanner.scan(target, config)

        xss = [f for f in findings if "XSS" in f.title and "Header" not in f.title]
        assert len(xss) > 0, "Expected XSS finding when payload reflects unencoded"
        assert xss[0].severity == Severity.HIGH

    def test_encoded_reflection_no_finding(self, scanner):
        # Should not produce finding when payload is HTML-encoded
        target = ScanTarget(url="http://example.com", scan_id=SCAN_ID, domain="example.com")

        crawl_html = '<form method="get" action="/search"><input name="q" value=""></form>'

        def mock_get(url, **kwargs):
            r = MagicMock()
            params = kwargs.get("params", {})
            q = params.get("q", "")
            if q:
                encoded = q.replace("<", "&lt;").replace(">", "&gt;")
                r.text = f"<html><body>Result: {encoded}</body></html>"
            else:
                r.text = crawl_html
            return r

        with patch("requests.get", side_effect=mock_get):
            with patch("requests.post", return_value=MagicMock(text="")):
                findings = scanner.scan(target, config)

        xss = [f for f in findings if "XSS" in f.title and "Header" not in f.title]
        assert len(xss) == 0, "Should not produce finding when payload is HTML-encoded"
