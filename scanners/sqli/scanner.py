import re
import time
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

from sentinel_core import Scanner, ScanTarget, ScanConfig, Finding, Severity
from sentinel_core.owasp import OwaspCategory
from payloads import (
    ERROR_BASED_PAYLOADS, ERROR_PATTERNS,
    TIME_BASED_PAYLOADS,
    BOOLEAN_PAYLOADS,
)

# Kaç saniyeden uzun süren response time-based zafiyet sayılır
TIME_THRESHOLD = 5.0


class SqliScanner(Scanner):
    """SQL Injection zafiyetlerini 3 teknikle tespit eder: error, time-based, boolean-based"""

    def scan(self, target: ScanTarget, config: ScanConfig) -> List[Finding]:
        findings = []

        # Hedef URL'deki form'ları ve query parametrelerini bul
        endpoints = self._crawl(target.url, config)

        for url, params, method in endpoints:
            for param_name in params:
                findings.extend(self._test_error_based(url, params, param_name, method, target.scan_id, config))
                findings.extend(self._test_time_based(url, params, param_name, method, target.scan_id, config))
                findings.extend(self._test_boolean_based(url, params, param_name, method, target.scan_id, config))

                # Aynı parametre için zafiyet bulunduysa diğer parametrelere geç
                if findings:
                    break

        return findings

    def _crawl(self, base_url: str, config: ScanConfig) -> List[tuple]:
        """
        Sayfadaki form'ları ve URL query parametrelerini bulur.
        Her endpoint (url, params_dict, method) tuple'ı olarak döner.
        """
        endpoints = []

        try:
            response = requests.get(base_url, timeout=config.request_timeout, verify=True)
            soup = BeautifulSoup(response.text, "html.parser")

            # HTML form'larını bul
            for form in soup.find_all("form"):
                action = form.get("action", base_url)
                method = form.get("method", "get").lower()

                # Relative URL'yi absolute yap
                if action.startswith("/"):
                    parsed = urlparse(base_url)
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                elif not action.startswith("http"):
                    action = base_url

                # Form input'larını topla
                params = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        params[name] = inp.get("value", "test")

                if params:
                    endpoints.append((action, params, method))

            # URL'deki query parametrelerini de test et
            parsed = urlparse(base_url)
            if parsed.query:
                query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                endpoints.append((base_url, query_params, "get"))

        except Exception:
            pass

        return endpoints

    def _inject_param(self, params: dict, target_param: str, payload: str) -> dict:
        """Sadece hedef parametreyi payload ile değiştirir, diğerlerini korur"""
        injected = params.copy()
        injected[target_param] = payload
        return injected

    def _send_request(self, url: str, params: dict, method: str,
                      config: ScanConfig) -> Optional[requests.Response]:
        """HTTP isteği gönderir, hata olursa None döner"""
        try:
            if method == "post":
                return requests.post(url, data=params, timeout=config.request_timeout, verify=True)
            else:
                return requests.get(url, params=params, timeout=config.request_timeout + 6, verify=True)
        except Exception:
            return None

    def _test_error_based(self, url, params, param_name, method,
                          scan_id, config) -> List[Finding]:
        """
        SQL hata mesajı içeren response arar.
        Veritabanı hata mesajı döndürüyorsa input sanitize edilmemiş demektir.
        """
        for payload in ERROR_BASED_PAYLOADS:
            injected = self._inject_param(params, param_name, payload)
            response = self._send_request(url, injected, method, config)

            if response is None:
                continue

            # Response'ta bilinen SQL hata mesajı pattern'ı var mı?
            for pattern in ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return [Finding(
                        severity=Severity.CRITICAL,
                        owasp_category=OwaspCategory.A03_INJECTION,
                        title="SQL Injection (Error-Based)",
                        description=f"Parameter '{param_name}' is vulnerable to error-based SQL injection.",
                        evidence=f"Payload: {payload}\nMatched pattern: {pattern}\nURL: {url}",
                        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
                        cvss_score=9.8,
                        scan_id=scan_id,
                    )]

        return []

    def _test_time_based(self, url, params, param_name, method,
                         scan_id, config) -> List[Finding]:
        """
        Veritabanını kasıtlı yavaşlatan payload gönderir.
        Response süresi TIME_THRESHOLD'dan uzunsa zafiyet var.
        """
        for payload in TIME_BASED_PAYLOADS:
            injected = self._inject_param(params, param_name, payload)

            start = time.time()
            response = self._send_request(url, injected, method, config)
            elapsed = time.time() - start

            # 5 saniyeden uzun sürdüyse payload işe yaradı
            if response is not None and elapsed >= TIME_THRESHOLD:
                return [Finding(
                    severity=Severity.CRITICAL,
                    owasp_category=OwaspCategory.A03_INJECTION,
                    title="SQL Injection (Time-Based Blind)",
                    description=f"Parameter '{param_name}' is vulnerable to time-based blind SQL injection.",
                    evidence=f"Payload: {payload}\nResponse time: {elapsed:.2f}s (threshold: {TIME_THRESHOLD}s)\nURL: {url}",
                    remediation="Use parameterized queries or prepared statements.",
                    cvss_score=9.8,
                    scan_id=scan_id,
                )]

        return []

    def _test_boolean_based(self, url, params, param_name, method,
                            scan_id, config) -> List[Finding]:
        """
        True ve false condition'lar farklı response üretiyorsa zafiyet var.
        Veritabanı sorgusu koşula göre farklı sonuç döndürüyordur.
        """
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_params = self._inject_param(params, param_name, true_payload)
            false_params = self._inject_param(params, param_name, false_payload)

            true_response = self._send_request(url, true_params, method, config)
            false_response = self._send_request(url, false_params, method, config)

            if true_response is None or false_response is None:
                continue

            # Response boyutları veya status kodları farklıysa zafiyet sinyali
            size_diff = abs(len(true_response.text) - len(false_response.text))
            status_diff = true_response.status_code != false_response.status_code

            if size_diff > 50 or status_diff:
                return [Finding(
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A03_INJECTION,
                    title="SQL Injection (Boolean-Based Blind)",
                    description=f"Parameter '{param_name}' may be vulnerable to boolean-based blind SQL injection.",
                    evidence=(
                        f"True payload: {true_payload} → {len(true_response.text)} bytes\n"
                        f"False payload: {false_payload} → {len(false_response.text)} bytes\n"
                        f"Difference: {size_diff} bytes\nURL: {url}"
                    ),
                    remediation="Use parameterized queries or prepared statements.",
                    cvss_score=8.1,
                    scan_id=scan_id,
                )]

        return []
