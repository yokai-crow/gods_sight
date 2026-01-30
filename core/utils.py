from core.config import STRICT_SEVERITIES

# Strict mode filtering
def filter_findings(findings, strict=False):
    """
    Filters findings based on strict mode.

    Parameters:
        findings (list): List of Finding objects
        strict (bool): If True, only return MEDIUM or HIGH severity

    Returns:
        list: Filtered list of Finding objects
    """
    if not strict:
        return findings
    return [f for f in findings if f.severity in STRICT_SEVERITIES]


# Colored printing of findings
def print_findings(findings):
    if not findings:
        print("\n✔ No security findings detected.")
        return

    # ANSI colors
    COLORS = {
        "INFO": "\033[92m",    # Green
        "LOW": "\033[94m",     # Blue
        "MEDIUM": "\033[93m",  # Yellow
        "HIGH": "\033[91m",    # Red
    }
    RESET = "\033[0m"

    print("\n=== Security Findings ===")
    for f in findings:
        color = COLORS.get(f.severity.upper(), "")
        print(f"""
{color}[{f.severity}] {f.title}{RESET}
ID: {f.id}
Evidence: {f.evidence}
Impact: {f.description}
Remediation: {f.remediation}
""")
