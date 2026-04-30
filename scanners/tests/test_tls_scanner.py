import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Add scanner-core and tls scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tls"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner-core"))

from sentinel_core import ScanTarget, ScanConfig, Severity
from scanner import TlsScanner

SCAN_ID = "test-scan-001"
config = ScanConfig(max_requests_per_second=5, request_timeout=10)


@pytest.fixture
def scanner():
    return TlsScanner()


class TestSecurityHeaders:

    def test_missing_headers_produce_findings(self, scanner):
        target = ScanTarget(url="http://example.com", scan_id=SCAN_ID, domain="example.com")

        mock_response = MagicMock()
        # No security headers
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html></html>"

        with patch("requests.get", return_value=mock_response):
            findings = scanner._check_security_headers(target, config)

        assert len(findings) >= 4, "Expected findings for all 4 missing security headers"
        titles = [f.title for f in findings]
        assert any("CSP" in t for t in titles)
        assert any("HSTS" in t for t in titles)
        assert any("X-Frame" in t for t in titles)

    def test_all_headers_present_no_findings(self, scanner):
        target = ScanTarget(url="https://secure.example.com", scan_id=SCAN_ID, domain="secure.example.com")

        mock_response = MagicMock()
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
        mock_response.text = "<html></html>"

        with patch("requests.get", return_value=mock_response):
            findings = scanner._check_security_headers(target, config)

        assert len(findings) == 0, "Should not produce findings when all headers are present"

    def test_partial_headers_correct_count(self, scanner):
        target = ScanTarget(url="https://partial.example.com", scan_id=SCAN_ID, domain="partial.example.com")

        mock_response = MagicMock()
        # Only HSTS and CSP are present, other headers are missing
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
        }
        mock_response.text = "<html></html>"

        with patch("requests.get", return_value=mock_response):
            findings = scanner._check_security_headers(target, config)

        assert len(findings) == 2, "Expected exactly 2 findings for 2 missing headers"
