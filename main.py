import argparse
import logging
import sys

from core.scanner import scan_ports
from core.plugin_loader import load_plugins
from core.results import ScanResult
from core.utils import filter_findings, print_findings
from core.output_json import export_json
from core.output_sarif import export_sarif
from core.target import validate_target 


# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Common ports shortcut
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]


# Banner
def print_banner():
    print("""
========================================================
 God's Sight — Open Source Security Assessment Tool
 Developed by Arun Saru
========================================================
""")


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="God's Sight Security Scanner")

    parser.add_argument("-H", "--host", required=True, help="Target host or IP")
    parser.add_argument("-C", "--common", action="store_true", help="Scan common ports only")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=1, help="Socket timeout")
    parser.add_argument("--retries", type=int, default=3, help="Retry count per port")

    parser.add_argument("--strict", action="store_true",
                        help="Show only MEDIUM and HIGH severity findings")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose debug logging")
    parser.add_argument("--json", action="store_true",
                        help="Export findings to JSON")
    parser.add_argument("--sarif", action="store_true",
                        help="Export findings to SARIF")

    args = parser.parse_args()

    # Logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    #VALIDATE TARGET
    try:
        resolved_ip = validate_target(args.host)
    except ValueError as e:
        logger.error(e)
        sys.exit(1)

    logger.info(f"Resolved {args.host} → {resolved_ip}")

    # Port selection
    ports = COMMON_PORTS if args.common else range(1, 1025)

    # Start scan
    logger.info(f"Starting scan against {args.host}")

    raw_results = scan_ports(
        resolved_ip,              
        list(ports),
        timeout=args.timeout,
        max_retries=args.retries,
        thread_pool_size=args.threads,
        verbose=args.verbose
    )

    # Convert results → ScanResult objects
    results = [
        ScanResult(
            host=args.host,         
            port=r["port"],
            status=r["status"],
            banner=r.get("banner")
        )
        for r in raw_results
    ]

    # Load plugins
    plugins = load_plugins()
 

    all_findings = []

    for plugin in plugins:
        logger.debug(f"Running plugin: {plugin.name}")
        try:
            all_findings.extend(plugin.run(results))
        except Exception as e:
            logger.error(f"Plugin '{plugin.name}' failed: {e}")

    # Apply strict filtering
    all_findings = filter_findings(all_findings, strict=args.strict)

    # Print results
    print_findings(all_findings)

    # Export
    if args.json:
        filename = f"{args.host}_findings.json"
        export_json(all_findings, filename)
        logger.info(f"Findings exported to {filename}")

    if args.sarif:
        filename = f"{args.host}_findings.sarif"
        export_sarif(all_findings, filename)
        logger.info(f"Findings exported to {filename}")


if __name__ == "__main__":
    main()
