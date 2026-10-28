"""SARIF 2.1.0 export for JGD findings."""
from __future__ import annotations

from jgd.contracts.models import Finding

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def to_sarif(findings: list[Finding], tool_version: str) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        cls = f.entry.get("class", "unknown") if f.entry else "unknown"
        rule_id = f"jgd/{f.category}/{cls}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f.category,
                "shortDescription": {"text": f.verdict},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL.get(f.severity, "note"),
                "message": {"text": f"{f.verdict}: {cls}"},
                "locations": [
                    {
                        "logicalLocations": [
                            {"fullyQualifiedName": cls, "kind": "type"}
                        ]
                    }
                ],
                "properties": {
                    "verdict": f.verdict,
                    "confidence": f.confidence,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "jgd",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
