import re
import asyncio
from typing import List, Set, Tuple
from urllib.parse import urljoin

import httpx

from plugins.base import Plugin
from core.findings import Finding
from core.results import ScanResult

# ===============================
# Tier-1 Constants
# ===============================

COMMON_DIR_PROBES = ["/", "/uploads/", "/static/", "/assets/", "/files/"]

STRICT_DIR_LISTING_PATTERNS = [
    r"index of\s*/",
    r"<title>\s*index of",
    r"<a href=\"\.\./\">"
]

TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Runtime"
]

SENSITIVE_ROBOTS_KEYWORDS = {
    "backup", "internal", "private", "config", "dump", "old", "test"
}

ADMIN_PATHS = [
    "/admin/",
    "/manager/",
    "/console/",
    "/phpmyadmin/"
]

# ===============================
# Plugin
# ===============================

class WebExposureTier1Plugin(Plugin):
    name = "Web Exposure Audit (Tier-1 Strict)"

    def __init__(self, config=None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 5)
        self.verify_tls = self.config.get("verify_tls", True)
        self.user_agent = self.config.get(
            "user_agent", "GodsSight-Tier1/1.0"
        )
        self.max_connections = self.config.get("max_connections", 10)

        self._seen: Set[Tuple] = set()
        self._lock = asyncio.Lock()

    # ---------------------------
    # Helpers
    # ---------------------------

    async def _safe_add(self, key: Tuple, findings: List[Finding], finding: Finding):
        async with self._lock:
            if key not in self._seen:
                self._seen.add(key)
                findings.append(finding)

    async def _get_base_url(self, client, host, port):
        schemes = [("https", 443), ("http", 80)]
        for scheme, default_port in schemes:
            url = f"{scheme}://{host}" if port == default_port else f"{scheme}://{host}:{port}"
            try:
                resp = await client.get(url, follow_redirects=True)
                return url, resp
            except httpx.RequestError:
                continue
        return None, None

    # ---------------------------
    # Tier-1 Checks
    # ---------------------------

    async def _check_directory_listing(self, client, base_url, host, port, findings):
        for path in COMMON_DIR_PROBES:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
                    matches = sum(1 for p in STRICT_DIR_LISTING_PATTERNS if re.search(p, resp.text, re.IGNORECASE))
                    if matches >= 2:
                        await self._safe_add(
                            ("DIR", host, port, path),
                            findings,
                            Finding(
                                id=f"DIR_LISTING_{host}_{port}_{path.strip('/') or 'root'}",
                                title="Directory listing enabled",
                                severity="HIGH",
                                category="Exposure",
                                confidence="HIGH",
                                description="The web server exposes a browsable directory index.",
                                evidence=f"{url} returned an index listing",
                                remediation="Disable directory indexing in the web server configuration."
                            )
                        )
            except httpx.RequestError:
                pass

    async def _check_cors(self, client, base_url, host, port, findings):
        origin = "https://evil.example"
        try:
            resp = await client.options(
                base_url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET"
                }
            )
            allow_origin = resp.headers.get("Access-Control-Allow-Origin")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials")

            if allow_origin in ("*", origin) and allow_creds == "true":
                await self._safe_add(
                    ("CORS", host, port),
                    findings,
                    Finding(
                        id=f"CORS_MISCONFIG_{host}_{port}",
                        title="Credentialed cross-origin access allowed",
                        severity="CRITICAL",
                        category="Misconfiguration",
                        confidence="HIGH",
                        description="The application allows credentialed cross-origin requests from arbitrary origins.",
                        evidence=f"ACAO={allow_origin}, ACAC={allow_creds}",
                        remediation="Restrict CORS to trusted origins and disable credentialed wildcard access."
                    )
                )
        except httpx.RequestError:
            pass

    async def _check_tech_headers(self, resp, host, port, findings):
        exposed = [f"{h}: {resp.headers[h]}" for h in TECH_HEADERS if h in resp.headers]
        if exposed:
            await self._safe_add(
                ("TECH", host, port),
                findings,
                Finding(
                    id=f"TECH_DISCLOSURE_{host}_{port}",
                    title="Technology disclosure via HTTP headers",
                    severity="LOW",
                    category="Information Disclosure",
                    confidence="HIGH",
                    description="Backend technologies are disclosed via HTTP response headers.",
                    evidence="; ".join(exposed),
                    remediation="Remove or generalize technology disclosure headers."
                )
            )

    async def _check_robots(self, client, base_url, host, port, findings):
        try:
            resp = await client.get(urljoin(base_url, "/robots.txt"))
            if resp.status_code == 200:
                hits = [line for line in resp.text.splitlines() if any(k in line.lower() for k in SENSITIVE_ROBOTS_KEYWORDS)]
                if hits:
                    await self._safe_add(
                        ("ROBOTS", host, port),
                        findings,
                        Finding(
                            id=f"ROBOTS_DISCLOSURE_{host}_{port}",
                            title="robots.txt exposes sensitive paths",
                            severity="INFO",
                            category="Information Disclosure",
                            confidence="HIGH",
                            description="robots.txt discloses sensitive or internal paths.",
                            evidence="\n".join(hits[:5]),
                            remediation="Avoid listing sensitive paths in robots.txt."
                        )
                    )
        except httpx.RequestError:
            pass

    async def _check_security_txt(self, client, base_url, host, port, findings):
        try:
            url = urljoin(base_url, "/.well-known/security.txt")
            resp = await client.get(url)
            if resp.status_code != 200 or not resp.text.strip():
                await self._safe_add(
                    ("SECURITYTXT", host, port),
                    findings,
                    Finding(
                        id=f"SECURITY_TXT_MISSING_{host}_{port}",
                        title="security.txt not found",
                        severity="INFO",
                        category="Best Practice",
                        confidence="HIGH",
                        description="No vulnerability disclosure policy was found.",
                        evidence=f"{url} returned HTTP {resp.status_code}",
                        remediation="Add a security.txt file under /.well-known/."
                    )
                )
        except httpx.RequestError:
            pass

    async def _check_admin_paths(self, client, base_url, host, port, findings):
        for path in ADMIN_PATHS:
            try:
                resp = await client.get(urljoin(base_url, path), follow_redirects=False)
                if resp.status_code in (200, 401, 403):
                    await self._safe_add(
                        ("ADMIN", host, port, path),
                        findings,
                        Finding(
                            id=f"ADMIN_PATH_{host}_{port}",
                            title="Administrative endpoint exposed",
                            severity="INFO",
                            category="Exposure",
                            confidence="MEDIUM",
                            description="An administrative endpoint is accessible.",
                            evidence=f"{path} → HTTP {resp.status_code}",
                            remediation="Restrict access to administrative interfaces."
                        )
                    )
            except httpx.RequestError:
                pass

    # ---------------------------
    # Runner
    # ---------------------------

    async def _scan(self, client, r: ScanResult, findings):
        if r.service != "HTTP" or r.status != "Open":
            return

        base_url, resp = await self._get_base_url(client, r.host, r.port)
        if not resp:
            return

        await asyncio.gather(
            self._check_directory_listing(client, base_url, r.host, r.port, findings),
            self._check_cors(client, base_url, r.host, r.port, findings),
            self._check_tech_headers(resp, r.host, r.port, findings),
            self._check_robots(client, base_url, r.host, r.port, findings),
            self._check_security_txt(client, base_url, r.host, r.port, findings),
            self._check_admin_paths(client, base_url, r.host, r.port, findings),
        )

    def run(self, results: List[ScanResult]) -> List[Finding]:
        findings: List[Finding] = []

        async def runner():
            limits = httpx.Limits(max_connections=self.max_connections)
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_tls,
                headers={"User-Agent": self.user_agent},
                limits=limits
            ) as client:
                await asyncio.gather(*(self._scan(client, r, findings) for r in results))

        asyncio.run(runner())
        return findings
