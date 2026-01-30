from dataclasses import dataclass

@dataclass
class Finding:
    id: str
    title: str
    severity: str        # INFO | LOW | MEDIUM | HIGH
    description: str
    evidence: str
    remediation: str
    confidence: str      # LOW | MEDIUM | HIGH
    category: str        # Exposure | Misconfiguration | Crypto | Observation
