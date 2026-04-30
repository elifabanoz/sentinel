import sys
import os
import importlib.util
import pytest
from unittest.mock import patch, MagicMock

# Add scanner-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner-core"))

# Load TLS scanner from specific file to avoid name conflict
_spec = importlib.util.spec_from_file_location(
    "tls_scanner",
    os.path.join(os.path.dirname(__file__), "..", "tls", "scanner.py")
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
TlsScanner = _module.TlsScanner

from sentinel_core import ScanTarget, ScanConfig, Severity

SCAN_ID = "test-scan-001"
config = ScanConfig(max_requests_per_second=5, request_timeout=10)


@pytest.fixture
def scanner():
    return TlsScanner()


class TestSecurityHeaders:

    def test_missing_headers_produce_findings(self, scanner):
        # Should produce findings when security headers are missing
        target = ScanTarget(url="http://example.com", scan_id=SCAN_ID, domain="example.com")

        mock_response = MagicMock()
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html></html>"

        with patch("requests.get", return_value=mock_response):
            findings = scanner._check_security_headers(target, config)

        assert len(findings) >= 4
        titles = [f.title for f in findings]
        assert any("CSP" in t for t in titles)
        assert any("HSTS" in t for t in titles)
        assert any("X-Frame" in t for t in titles)

    def test_all_headers_present_no_findings(self, scanner):
        # Should not produce findings when all headers are present
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

        assert len(findings) == 0

    def test_partial_headers_correct_count(self, scanner):
        # Should produce findings for only the missing headers
        target = ScanTarget(url="https://partial.example.com", scan_id=SCAN_ID, domain="partial.example.com")

        mock_response = MagicMock()
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
        }
        mock_response.text = "<html></html>"

        with patch("requests.get", return_value=mock_response):
            findings = scanner._check_security_headers(target, config)

        assert len(findings) == 2
