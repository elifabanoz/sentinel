import ssl
import socket
import requests
from datetime import datetime, timezone
from typing import List

from sentinel_core import Scanner, ScanTarget, ScanConfig, Finding, Severity
from sentinel_core.owasp import OwaspCategory


class TlsScanner(Scanner):

    def scan(self, target: ScanTarget, config: ScanConfig) -> List[Finding]:
        findings = []

        findings.extend(self._check_tls_version(target))
        findings.extend(self._check_certificate(target))
        findings.extend(self._check_security_headers(target, config))

        return findings

    def _check_tls_version(self, target: ScanTarget) -> List[Finding]:
        findings = []
        hostname = target.domain

        for version, protocol in [
            (ssl.TLSVersion.TLSv1, "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = version
                ctx.maximum_version = version
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        # Bağlantı başarılıysa bu eski versiyon destekleniyor demek
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                            title=f"{protocol} Supported",
                            description=f"{protocol} is deprecated and vulnerable to POODLE/BEAST attacks.",
                            evidence=f"Successfully connected to {hostname} using {protocol}",
                            remediation=f"Disable {protocol} on your server. Only TLS 1.2 and 1.3 should be accepted.",
                            cvss_score=7.4,
                            scan_id=target.scan_id,
                        ))
            except Exception:
                pass

        return findings

    def _check_certificate(self, target: ScanTarget) -> List[Finding]:
        """Sertifika geçerlilik tarihini kontrol eder — 30 günden az kaldıysa uyarır"""
        findings = []
        hostname = target.domain

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            # Sertifikanın bitiş tarihini parse et
            expiry_str = cert.get("notAfter", "")
            expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry_date - datetime.now(timezone.utc)).days

            if days_left < 0:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    title="SSL Certificate Expired",
                    description=f"The SSL certificate expired {abs(days_left)} days ago.",
                    evidence=f"Certificate expired on {expiry_date.date()}",
                    remediation="Renew the SSL certificate immediately.",
                    cvss_score=9.1,
                    scan_id=target.scan_id,
                ))
            elif days_left < 30:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    title="SSL Certificate Expiring Soon",
                    description=f"The SSL certificate expires in {days_left} days.",
                    evidence=f"Certificate expires on {expiry_date.date()}",
                    remediation="Renew the SSL certificate before it expires.",
                    cvss_score=5.3,
                    scan_id=target.scan_id,
                ))
        except Exception as e:
            findings.append(Finding(
                severity=Severity.HIGH,
                owasp_category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                title="SSL Certificate Check Failed",
                description="Could not retrieve or validate the SSL certificate.",
                evidence=str(e),
                remediation="Ensure a valid SSL certificate is installed.",
                cvss_score=7.5,
                scan_id=target.scan_id,
            ))

        return findings

    def _check_security_headers(self, target: ScanTarget, config: ScanConfig) -> List[Finding]:
        findings = []

        try:
            response = requests.get(
                target.url,
                timeout=config.request_timeout,
                allow_redirects=True,
                verify=True,
            )
            headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            return [Finding(
                severity=Severity.INFO,
                title="Security Headers Check Failed",
                description=f"Could not fetch headers: {e}",
                scan_id=target.scan_id,
            )]

        required_headers = [
            (
                "strict-transport-security",
                "HSTS Missing",
                "HSTS forces browsers to use HTTPS. Without it, downgrade attacks (SSL stripping) are possible.",
                Severity.HIGH,
                6.5,
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
            ),
            (
                "content-security-policy",
                "CSP Missing",
                "Without CSP, browsers execute any script on the page, making XSS attacks easier.",
                Severity.HIGH,
                6.1,
                "Add a Content-Security-Policy header restricting script sources.",
                OwaspCategory.A05_SECURITY_MISCONFIGURATION,
            ),
            (
                "x-frame-options",
                "X-Frame-Options Missing",
                "Without this header, the page can be embedded in an iframe, enabling clickjacking attacks.",
                Severity.MEDIUM,
                4.3,
                "Add: X-Frame-Options: DENY or SAMEORIGIN",
                OwaspCategory.A05_SECURITY_MISCONFIGURATION,
            ),
            (
                "x-content-type-options",
                "X-Content-Type-Options Missing",
                "Without this header, browsers may MIME-sniff responses, enabling content injection attacks.",
                Severity.LOW,
                3.1,
                "Add: X-Content-Type-Options: nosniff",
                OwaspCategory.A05_SECURITY_MISCONFIGURATION,
            ),
        ]

        for header_name, title, description, severity, cvss, remediation, owasp in required_headers:
            if header_name not in headers:
                findings.append(Finding(
                    severity=severity,
                    owasp_category=owasp,
                    title=title,
                    description=description,
                    evidence=f"Header '{header_name}' not present in response",
                    remediation=remediation,
                    cvss_score=cvss,
                    scan_id=target.scan_id,
                ))

        return findings
