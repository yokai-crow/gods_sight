from typing import List
from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult

class SSHReachablePlugin(Plugin):
    name = "SSH Reachability"

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings = []

        for r in results:
            # Only trigger if port 22 is open
            if r.port == 22 and r.status.lower() == "open":
                findings.append(Finding(
                    id=f"SSH_REACHABLE_{r.host}_{r.port}",
                    title="SSH reachable from network",
                    severity="INFO",
                    category="Exposure",
                    confidence="HIGH",
                    description=(
                        f"SSH port {r.port} is reachable on host {r.host}. "
                        "This may be intentional for remote administration."
                    ),
                    evidence=f"Host {r.host}:{r.port} open ({r.banner or 'banner unavailable'})",
                    remediation=(
                        "If public SSH access is required, ensure key-based authentication, "
                        "disable password login, and restrict access using firewall rules or VPN."
                    )
                ))

        return findings
