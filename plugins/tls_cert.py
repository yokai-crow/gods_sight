
import ssl
import socket
from typing import List
from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult
from datetime import datetime

class TLSCertPlugin(Plugin):
    name = "TLS Certificate Inspection"

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings = []

        for r in results:
            # Only check open HTTPS ports
            if r.port not in (443, 8443, 9443) or r.status != "Open":
                continue

            host = getattr(r, "host", None)  # Make sure ScanResult has host

            if not host:
                continue

            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, r.port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expires - datetime.utcnow()).days

                        if days_left < 30:
                            severity = "HIGH" if days_left < 7 else "MEDIUM"
                            findings.append(Finding(
                                id=f"TLS_CERT_EXPIRING_{host}_{r.port}",
                                title="TLS certificate nearing expiration",
                                severity=severity,
                                category="Crypto",
                                confidence="HIGH",
                                description=f"TLS certificate on {host}:{r.port} expires in {days_left} days.",
                                evidence=f"Certificate expires on {expires}",
                                remediation="Renew TLS certificate before expiration."
                            ))

            except ssl.SSLError as e:
                findings.append(Finding(
                    id=f"TLS_CERT_INVALID_{host}_{r.port}",
                    title="TLS certificate issue",
                    severity="HIGH",
                    category="Crypto",
                    confidence="HIGH",
                    description=f"Failed to validate TLS certificate on {host}:{r.port}: {e}",
                    evidence=str(e),
                    remediation="Check TLS certificate configuration and validity."
                ))
            except Exception as e:
                findings.append(Finding(
                    id=f"TLS_CERT_ERROR_{host}_{r.port}",
                    title="TLS certificate check failed",
                    severity="INFO",
                    category="Crypto",
                    confidence="MEDIUM",
                    description=f"Could not check TLS certificate on {host}:{r.port}: {e}",
                    evidence=str(e),
                    remediation="Ensure host is reachable and running HTTPS."
                ))

        return findings
