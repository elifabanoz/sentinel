import logging
import socket
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import dns.zone
import dns.query
import dns.exception

from sentinel_core import Scanner, ScanTarget, ScanConfig, Finding, Severity
from sentinel_core.owasp import OwaspCategory

log = logging.getLogger(__name__)

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "portal", "app", "dashboard", "cdn", "static",
    "media", "assets", "img", "docs", "support", "help", "blog",
    "shop", "store", "payments", "auth", "login", "sso", "oauth",
    "db", "database", "redis", "rabbit", "jenkins", "gitlab", "git",
]


@dataclass
class OsintScanner(Scanner):

    def scan(self, target: ScanTarget, config: ScanConfig) -> list[Finding]:
        findings = []

        findings.extend(self._check_zone_transfer(target.domain))
        findings.extend(self._check_email_security(target.domain))
        findings.extend(self._enumerate_subdomains(target.domain))

        return findings

    def _check_zone_transfer(self, domain: str) -> list[Finding]:
        findings = []
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_host = str(ns.target).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                    names = [str(n) for n in zone.nodes.keys()]
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION.value,
                        title="DNS Zone Transfer Enabled",
                        description=(
                            f"DNS server {ns_host} allows zone transfer (AXFR) for {domain}. "
                            f"This exposes the full DNS record list to any requester."
                        ),
                        evidence=f"Nameserver: {ns_host} | Records found: {len(names)}",
                        remediation=(
                            "Restrict AXFR requests to trusted secondary nameservers only. "
                            "Add ACL rules in BIND: allow-transfer { trusted-ns-ip; };"
                        ),
                        cvss_score=7.5,
                    ))
                except (dns.exception.FormError, EOFError, ConnectionRefusedError, OSError):
                    pass
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
        return findings

    def _check_email_security(self, domain: str) -> list[Finding]:
        findings = []

        spf_found = False
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            for record in txt_records:
                txt = str(record).strip('"')
                if txt.startswith("v=spf1"):
                    spf_found = True
                    if "~all" in txt:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION.value,
                            title="SPF Record Uses Soft Fail (~all)",
                            description=(
                                "The SPF record uses ~all (soft fail) instead of -all (hard fail). "
                                "Emails from unauthorized servers will be marked as spam but not rejected."
                            ),
                            evidence=f"SPF record: {txt}",
                            remediation="Change ~all to -all in your SPF record to hard-fail unauthorized senders.",
                            cvss_score=5.3,
                        ))
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass

        if not spf_found:
            findings.append(Finding(
                severity=Severity.HIGH,
                owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION.value,
                title="Missing SPF Record",
                description=(
                    f"No SPF record found for {domain}. "
                    "Attackers can send emails that appear to come from this domain (email spoofing)."
                ),
                evidence=f"DNS TXT query for {domain} returned no SPF record",
                remediation='Add a TXT record: v=spf1 include:your-mail-provider.com -all',
                cvss_score=6.5,
            ))

        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in dmarc_records:
                txt = str(record).strip('"')
                if txt.startswith("v=DMARC1"):
                    if "p=none" in txt:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION.value,
                            title="DMARC Policy Set to None",
                            description=(
                                "DMARC policy is p=none which means no enforcement. "
                                "Spoofed emails are not rejected or quarantined."
                            ),
                            evidence=f"DMARC record: {txt}",
                            remediation="Change DMARC policy to p=quarantine or p=reject after monitoring.",
                            cvss_score=5.3,
                        ))
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            findings.append(Finding(
                severity=Severity.HIGH,
                owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION.value,
                title="Missing DMARC Record",
                description=(
                    f"No DMARC record found at _dmarc.{domain}. "
                    "Without DMARC, there is no policy for handling emails that fail SPF/DKIM checks."
                ),
                evidence=f"DNS TXT query for _dmarc.{domain} returned no result",
                remediation='Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                cvss_score=6.5,
            ))

        return findings

    def _enumerate_subdomains(self, domain: str) -> list[Finding]:
        discovered = []
        for prefix in SUBDOMAIN_WORDLIST:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(subdomain)
                discovered.append(subdomain)
                log.debug(f"Found subdomain: {subdomain}")
            except socket.error:
                pass

        if discovered:
            return [Finding(
                severity=Severity.INFO,
                owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION.value,
                title="Subdomains Discovered via DNS Enumeration",
                description=(
                    f"Found {len(discovered)} active subdomain(s) for {domain}. "
                    "Exposed subdomains may reveal internal services or staging environments."
                ),
                evidence=", ".join(discovered),
                remediation=(
                    "Review each subdomain. Ensure staging/dev subdomains are not publicly accessible. "
                    "Consider using wildcard DNS only for necessary subdomains."
                ),
                cvss_score=3.1,
            )]
        return []
