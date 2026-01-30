# plugins/sql_injection.py
import requests
from typing import List
from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult

SQL_ERRORS = [
    "You have an error in your SQL syntax",
    "mysql_fetch",
    "mysqli_fetch",
    "ORA-01756",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "PDOException",
    "SQLSTATE"
]

COMMON_TEST_PATHS = [
    "/",
    "/index.php",
    "/product.php?id=1",
    "/list.php?id=1",
    "/news.php?id=1"
]

class SQLInjectionPlugin(Plugin):
    name = "SQL Injection Detection"

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings = []
        tested_hosts = set()

        for r in results:
            if r.service != "HTTP" or r.status != "Open":
                continue

            host = r.host
            if host in tested_hosts:
                continue

            tested_hosts.add(host)

            for path in COMMON_TEST_PATHS:
                url = f"http://{host}{path}"
                payload = "'"

                try:
                    resp = requests.get(
                        url + payload,
                        timeout=4,
                        verify=False
                    )

                    for error in SQL_ERRORS:
                        if error.lower() in resp.text.lower():
                            findings.append(Finding(
                                id=f"SQLI_POSSIBLE_{host}",
                                title="Possible SQL Injection vulnerability",
                                severity="HIGH",
                                category="Injection",
                                confidence="MEDIUM",
                                description=(
                                    "The application appears to be vulnerable to "
                                    "SQL Injection due to database error leakage."
                                ),
                                evidence=f"SQL error detected at {url}",
                                remediation=(
                                    "Use parameterized queries (prepared statements), "
                                    "input validation, and proper error handling."
                                )
                            ))
                            return findings  # Stop after first hit
                except Exception:
                    continue

        return findings

