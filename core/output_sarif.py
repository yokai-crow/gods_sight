import json
from uuid import uuid4

def export_sarif(findings, filename="results.sarif"):
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GodsSight",
                    "version": "2.0",
                    "informationUri": "https://github.com/yokai-crow/gods-sight",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    rules_seen = {}

    for f in findings:
        if f.id not in rules_seen:
            rules_seen[f.id] = {
                "id": f.id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": f.severity.lower()
                }
            }

        sarif["runs"][0]["results"].append({
            "ruleId": f.id,
            "message": {"text": f.description},
            "level": f.severity.lower(),
            "guid": str(uuid4())
        })

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_seen.values())

    with open(filename, "w") as f:
        json.dump(sarif, f, indent=2)
