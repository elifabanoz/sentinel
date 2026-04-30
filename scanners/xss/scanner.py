import uuid
from typing import List
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from sentinel_core import Scanner, ScanTarget, ScanConfig, Finding, Severity
from sentinel_core.owasp import OwaspCategory


class XssScanner(Scanner):

    def scan(self, target: ScanTarget, config: ScanConfig) -> List[Finding]:
        findings = []

        endpoints = self._crawl(target.url, config)
        for url, params, method in endpoints:
            for param_name in params:
                finding = self._test_reflected_xss(
                    url, params, param_name, method, target.scan_id, config
                )
                if finding:
                    findings.append(finding)

        findings.extend(self._test_header_injection(target, config))

        return findings

    def _crawl(self, base_url: str, config: ScanConfig) -> List[tuple]:
        endpoints = []
        try:
            response = requests.get(base_url, timeout=config.request_timeout, verify=True)
            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", base_url)
                method = form.get("method", "get").lower()

                if action.startswith("/"):
                    parsed = urlparse(base_url)
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                elif not action.startswith("http"):
                    action = base_url

                params = {}
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        params[name] = inp.get("value", "test")

                if params:
                    endpoints.append((action, params, method))

            parsed = urlparse(base_url)
            if parsed.query:
                query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                endpoints.append((base_url, query_params, "get"))

        except Exception:
            pass

        return endpoints

    def _test_reflected_xss(self, url, params, param_name, method,
                             scan_id, config) -> Finding | None:
        
        token = f"sentinel-xss-{uuid.uuid4().hex[:8]}"
        payload = f"<{token}>"

        injected = params.copy()
        injected[param_name] = payload

        try:
            if method == "post":
                response = requests.post(url, data=injected,
                                         timeout=config.request_timeout, verify=True)
            else:
                response = requests.get(url, params=injected,
                                        timeout=config.request_timeout, verify=True)

            if payload in response.text:
                return Finding(
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A03_INJECTION,
                    title="Reflected XSS",
                    description=(
                        f"Parameter '{param_name}' reflects unencoded user input in the response. "
                        "An attacker can inject malicious scripts that execute in the victim's browser."
                    ),
                    evidence=(
                        f"Injected: {payload}\n"
                        f"Found unencoded in response at: {url}\n"
                        f"Parameter: {param_name} (method: {method.upper()})"
                    ),
                    remediation=(
                        "HTML-encode all user-supplied input before rendering. "
                        "Use framework escaping functions (e.g. Thymeleaf th:text, React JSX). "
                        "Add Content-Security-Policy header."
                    ),
                    cvss_score=6.1,
                    scan_id=scan_id,
                )
        except Exception:
            pass

        return None

    def _test_header_injection(self, target: ScanTarget, config: ScanConfig) -> List[Finding]:
        
        findings = []
        token = f"sentinel-xss-{uuid.uuid4().hex[:8]}"
        payload = f"<{token}>"

        headers_to_test = {
            "User-Agent": payload,
            "Referer": payload,
        }

        for header_name, header_value in headers_to_test.items():
            try:
                response = requests.get(
                    target.url,
                    headers={header_name: header_value},
                    timeout=config.request_timeout,
                    verify=True,
                )
                if payload in response.text:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        owasp_category=OwaspCategory.A03_INJECTION,
                        title=f"Reflected XSS via {header_name} Header",
                        description=(
                            f"The {header_name} header value is reflected unencoded in the response. "
                            "This can lead to XSS if the header value is attacker-controlled."
                        ),
                        evidence=f"Header: {header_name}: {payload}\nFound unencoded in response",
                        remediation=f"HTML-encode the {header_name} header value before rendering it.",
                        cvss_score=4.7,
                        scan_id=target.scan_id,
                    ))
            except Exception:
                pass

        return findings
