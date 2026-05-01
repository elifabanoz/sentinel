import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import requests

from sentinel_core import Scanner, ScanTarget, ScanConfig, Finding, Severity
from sentinel_core.owasp import OwaspCategory

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"

DEPENDENCY_PATHS = [
    "requirements.txt",
    "package.json",
    "pom.xml",
]

def cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass
class DepsScanner(Scanner):

    def scan(self, target: ScanTarget, config: ScanConfig) -> list[Finding]:
        findings = []
        session = requests.Session()
        session.headers["User-Agent"] = "Sentinel-Scanner/1.0"

        for path in DEPENDENCY_PATHS:
            url = f"{target.url.rstrip('/')}/{path}"
            packages = self._fetch_and_parse(session, url, path, config)
            if packages:
                log.info(f"Found {len(packages)} packages in {path}")
                for name, version, ecosystem in packages:
                    vulns = self._query_osv(session, name, version, ecosystem)
                    for vuln in vulns:
                        findings.append(self._make_finding(vuln, name, version, path))

        return findings

    def _fetch_and_parse(self, session, url: str, path: str,
                         config: ScanConfig) -> list[tuple[str, str, str]]:
        try:
            resp = session.get(url, timeout=config.request_timeout)
            if resp.status_code != 200:
                return []
            content = resp.text

            if path == "requirements.txt":
                return self._parse_requirements(content)
            if path == "package.json":
                return self._parse_package_json(content)
            if path == "pom.xml":
                return self._parse_pom_xml(content)
        except requests.RequestException as e:
            log.debug(f"Could not fetch {url}: {e}")
        return []

    def _parse_requirements(self, content: str) -> list[tuple[str, str, str]]:
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
            if match:
                packages.append((match.group(1), match.group(2), "PyPI"))
        return packages

    def _parse_package_json(self, content: str) -> list[tuple[str, str, str]]:
        packages = []
        try:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies"):
                for name, version in data.get(section, {}).items():
                    clean = version.lstrip("^~>=<")
                    if re.match(r"^\d+\.\d+", clean):
                        packages.append((name, clean, "npm"))
        except json.JSONDecodeError:
            pass
        return packages

    def _parse_pom_xml(self, content: str) -> list[tuple[str, str, str]]:
        packages = []
        try:
            root = ET.fromstring(content)
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//m:dependency", ns):
                artifact = dep.findtext("m:artifactId", namespaces=ns)
                version = dep.findtext("m:version", namespaces=ns)
                if artifact and version and not version.startswith("$"):
                    packages.append((artifact, version, "Maven"))
        except ET.ParseError:
            pass
        return packages

    def _query_osv(self, session, name: str, version: str,
                   ecosystem: str) -> list[dict]:
        try:
            payload = {
                "version": version,
                "package": {"name": name, "ecosystem": ecosystem},
            }
            resp = session.post(OSV_API, json=payload, timeout=10)
            if resp.status_code == 200:
                return resp.json().get("vulns", [])
        except requests.RequestException as e:
            log.warning(f"OSV query failed for {name}@{version}: {e}")
        return []

    def _make_finding(self, vuln: dict, pkg_name: str,
                      version: str, source_file: str) -> Finding:
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No summary available")

        cvss_score = 5.0
        for severity_entry in vuln.get("severity", []):
            if severity_entry.get("type") == "CVSS_V3":
                score_str = severity_entry.get("score", "")
                try:
                    match = re.search(r"/(\d+\.\d+)$", score_str)
                    if match:
                        cvss_score = float(match.group(1))
                except ValueError:
                    pass

        severity = cvss_to_severity(cvss_score)

        aliases = vuln.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        return Finding(
            severity=severity,
            owasp_category=OwaspCategory.VULNERABLE_COMPONENTS.value,
            title=f"Vulnerable Dependency: {pkg_name}@{version} ({cve})",
            description=(
                f"{summary}\n\n"
                f"Package: {pkg_name} version {version}\n"
                f"Found in: {source_file}\n"
                f"Vulnerability ID: {vuln_id}"
            ),
            evidence=f"{source_file}: {pkg_name}=={version}",
            remediation=(
                f"Update {pkg_name} to a version that is not affected by {cve}. "
                f"Check https://osv.dev/vulnerability/{vuln_id} for patched versions."
            ),
            cvss_score=cvss_score,
        )
