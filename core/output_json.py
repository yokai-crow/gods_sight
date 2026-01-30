import json
from dataclasses import asdict

def export_json(findings, filename="results.json"):
    with open(filename, "w") as f:
        json.dump([asdict(fnd) for fnd in findings], f, indent=2)
