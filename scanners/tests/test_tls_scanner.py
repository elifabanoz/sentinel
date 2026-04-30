import pytest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, "../tls")
sys.path.insert(0, "../../scanner-core")

from sentinel_core import ScanTarget, ScanConfig, Severity
from scanners.tls.scanner import TlsScanner


SCAN_ID = "test-scan-001"
JUICE_SHOP_URL = "http://localhost:3000"


@pytest.fixture
def scanner():
    return TlsScanner()


@pytest.fixture
def config():
    return ScanConfig(max_requests_per_second=5, request_timeout=10)


class TestSecurityHeaders:

    def test_missing_csp_produces_finding(self, scanner, config):
        target = ScanTarget(url=JUICE_SHOP_URL, scan_id=SCAN_ID, domain="localhost")
        findings = scanner._check_security_headers(target, config)

        csp_findings = [f for f in findings if "CSP" in f.title]
        assert len(csp_findings) > 0, "Expected CSP missing finding for Juice Shop"
        assert csp_findings[0].severity == Severity.HIGH

    def test_missing_hsts_produces_finding(self, scanner, config):
        target = ScanTarget(url=JUICE_SHOP_URL, scan_id=SCAN_ID, domain="localhost")
        findings = scanner._check_security_headers(target, config)

        hsts_findings = [f for f in findings if "HSTS" in f.title]
        assert len(hsts_findings) > 0, "Expected HSTS missing finding for HTTP target"

    def test_secure_site_has_fewer_findings(self, scanner, config):
        target = ScanTarget(url="https://example.com", scan_id=SCAN_ID, domain="example.com")
        findings = scanner._check_security_headers(target, config)

        juice_target = ScanTarget(url=JUICE_SHOP_URL, scan_id=SCAN_ID, domain="localhost")
        juice_findings = scanner._check_security_headers(juice_target, config)

        assert len(findings) <= len(juice_findings), \
            "Secure site should have equal or fewer header findings than Juice Shop"


class TestTlsVersion:

    def test_old_tls_produces_finding(self, scanner):
        with patch("ssl.SSLContext") as mock_ctx:
            mock_sock = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value.__enter__ = lambda s: s
            mock_ctx.return_value.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            with patch("socket.create_connection", return_value=MagicMock(
                __enter__=lambda s: s,
                __exit__=MagicMock(return_value=False)
            )):
                target = ScanTarget(url="https://example.com", scan_id=SCAN_ID, domain="example.com")
                findings = scanner._check_tls_version(target)

                assert len(findings) > 0
                assert all(f.severity == Severity.HIGH for f in findings)
