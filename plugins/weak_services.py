
from typing import List
from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult

# Define insecure / legacy services
WEAK_SERVICES = {
    21: {
        "name": "FTP",
        "severity": "HIGH",
        "description": "FTP transmits credentials and data in cleartext. This service is considered insecure on modern networks.",
        "remediation": "Disable FTP and migrate to SFTP or SCP."
    },
    23: {
        "name": "Telnet",
        "severity": "HIGH",
        "description": "Telnet provides unencrypted remote access and is highly insecure.",
        "remediation": "Disable Telnet and use SSH with key-based authentication."
    },
    110: {
        "name": "POP3",
        "severity": "MEDIUM",
        "description": "POP3 transmits credentials in cleartext unless secured with TLS.",
        "remediation": "Use secure alternatives like IMAPS or encrypted connections."
    },
    143: {
        "name": "IMAP",
        "severity": "MEDIUM",
        "description": "IMAP transmits credentials in cleartext unless secured with TLS.",
        "remediation": "Use secure alternatives like IMAPS."
    },
    3306: {
        "name": "MySQL",
        "severity": "MEDIUM",
        "description": "MySQL may allow insecure remote connections if not properly configured.",
        "remediation": "Restrict MySQL to local or VPN access and enable strong authentication."
    },
}

class WeakServicePlugin(Plugin):
    name = "Weak / Legacy Services"

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings = []

        for r in results:
            if r.port in WEAK_SERVICES and r.status == "Open":
                service = WEAK_SERVICES[r.port]
                host = getattr(r, "host", "unknown") 
                findings.append(Finding(
                    id=f"{service['name'].upper()}_DETECTED_{host}_{r.port}",
                    title=f"{service['name']} service detected",
                    severity=service["severity"],
                    category="Exposure",
                    confidence="HIGH",
                    description=service["description"],
                    evidence=f"Host {host}:{r.port} open ({service['name']})",
                    remediation=service["remediation"]
                ))

        return findings
