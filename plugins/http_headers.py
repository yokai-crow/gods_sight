import requests
from typing import List
from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Strict-Transport-Security": "Enforces HTTPS"
}

class HTTPHeaderPlugin(Plugin):
    name = "HTTP Security Headers"

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings = []
        failed_ports = []

        for r in results:
            # Only check open HTTP ports
            if r.service != "HTTP" or r.status.lower() != "open":
                continue

            scheme = "https" if r.port in [443, 8443] else "http"
            url = f"{scheme}://{r.host}:{r.port}/"

            try:
                # Fetch headers
                resp = requests.head(url, timeout=10, allow_redirects=True, verify=False)
                headers = {k.lower(): v for k, v in resp.headers.items()}
            except requests.RequestException as e:
                # Track failed ports to report later
                failed_ports.append((r.host, r.port, str(e)))
                continue

            # Check for missing security headers
            for header, reason in SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    severity = "MEDIUM" if header in ["Strict-Transport-Security", "Content-Security-Policy"] else "LOW"
                    findings.append(Finding(
                        id=f"MISSING_{header.upper().replace('-', '_')}_{r.host}_{r.port}",
                        title=f"Missing HTTP header: {header}",
                        severity=severity,
                        category="Misconfiguration",
                        confidence="HIGH",
                        description=f"The HTTP response is missing {header}. {reason}.",
                        evidence=f"Host {r.host}:{r.port} missing header: {header}",
                        remediation=f"Configure the web server to include {header}."
                    ))

        # Add aggregated failed ports as INFO findings
        for host, port, err in failed_ports:
            findings.append(Finding(
                id=f"HTTP_HEADERS_FAIL_{host}_{port}",
                title="Failed to fetch HTTP headers",
                severity="INFO",
                category="Information",
                confidence="HIGH",
                description=f"Could not fetch HTTP headers from {scheme}://{host}:{port}/: {err}",
                evidence=str(err),
                remediation="Ensure the host is reachable and running HTTP/HTTPS."
            ))

        return findings
