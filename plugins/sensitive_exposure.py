import requests
from typing import List
from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult

class SensitiveExposurePlugin(Plugin):
    name = "Sensitive File Exposure"

    # High-confidence sensitive paths
    TARGET_FILES = {
        "/.env": {
            "severity": "CRITICAL",
            "signature": ["APP_KEY=", "DB_", "SECRET", "PASSWORD"]
        },
        "/wp-config.php": {
            "severity": "CRITICAL",
            "signature": ["DB_NAME", "DB_USER", "DB_PASSWORD"]
        },
        "/config.php": {
            "severity": "HIGH",
            "signature": ["password", "db", "$"]
        },
        "/phpinfo.php": {
            "severity": "HIGH",
            "signature": ["phpinfo()", "PHP Version"]
        },
        "/.git/config": {
            "severity": "CRITICAL",
            "signature": ["[core]", "repositoryformatversion"]
        },
        "/docker-compose.yml": {
            "severity": "HIGH",
            "signature": ["services:", "image:"]
        },
        "/backup.zip": {
            "severity": "CRITICAL",
            "signature": []
        },
        "/db.sql": {
            "severity": "CRITICAL",
            "signature": ["CREATE TABLE", "INSERT INTO"]
        }
    }

    TIMEOUT = 5
    MIN_SIZE = 200  # bytes

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings = []
        scanned_hosts = set()

        for r in results:
            if r.port not in (80, 443) or r.status != "Open":
                continue

            host_id = f"{r.host}:{r.port}"
            if host_id in scanned_hosts:
                continue

            scanned_hosts.add(host_id)
            scheme = "https" if r.port == 443 else "http"
            base_url = f"{scheme}://{r.host}"

            for path, meta in self.TARGET_FILES.items():
                url = base_url + path

                try:
                    resp = requests.get(
                        url,
                        timeout=self.TIMEOUT,
                        allow_redirects=False,
                        verify=False
                    )

                    # Strict validation
                    if resp.status_code != 200:
                        continue

                    if len(resp.content) < self.MIN_SIZE:
                        continue

                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type and path not in ("/phpinfo.php",):
                        continue

                    body = resp.text.lower()

                    # Signature validation (if defined)
                    if meta["signature"]:
                        if not any(sig.lower() in body for sig in meta["signature"]):
                            continue

                    findings.append(Finding(
                        id=f"EXPOSED_FILE_{path.replace('/', '').upper()}",
                        title="Exposed sensitive file detected",
                        severity=meta["severity"],
                        category="Sensitive Data Exposure",
                        confidence="HIGH",
                        description=(
                            f"The application exposes a sensitive file at `{path}`. "
                            "Such files often contain credentials, secrets, or internal configuration."
                        ),
                        evidence=f"Accessible via {url} (HTTP 200, validated content)",
                        remediation=(
                            "Remove the file from the web root immediately. "
                            "Rotate any exposed credentials and restrict access using server rules."
                        )
                    ))

                except requests.RequestException:
                    continue

        return findings
