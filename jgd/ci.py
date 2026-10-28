"""CI/CD gate helpers: baseline comparison and policy exit decisions.

The gate is intentionally deterministic: it compares stable finding keys
(category, entry class, verdict, bridge class) and applies the configured
severity threshold. It never consults an LLM.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from jgd.contracts.models import Finding

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def finding_key(finding: Finding | dict[str, Any]) -> str:
    data = finding.to_dict() if isinstance(finding, Finding) else finding
    entry = data.get("entry") or {}
    bridge = data.get("bridge") or {}
    return "|".join(
        [
            str(data.get("category", "")),
            str(entry.get("class", "")),
            str(data.get("verdict", "")),
            str(bridge.get("class", "")),
        ]
    )


def load_baseline(path: str | Path) -> set[str]:
    """Load a prior run.json or findings.json and return stable finding keys.

    Supported shapes:
    - ``{"findings": [...]}`` (JGD run.json)
    - ``[...]`` (findings.json / gate source)
    - ``{"gate": ..., "findings": [...]}``
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data
    else:
        raise ValueError("baseline must be a run.json object or a findings array")
    if not isinstance(findings, list):
        raise ValueError("baseline findings must be an array")
    keys: set[str] = set()
    for item in findings:
        if isinstance(item, dict):
            keys.add(finding_key(item))
    return keys


def evaluate(
    findings: Iterable[Finding],
    *,
    baseline: set[str] | None = None,
    fail_on: str = "high",
) -> dict[str, Any]:
    """Return the gate decision and the blocking findings."""
    all_findings = list(findings)
    considered = (
        [f for f in all_findings if finding_key(f) not in baseline]
        if baseline is not None
        else list(all_findings)
    )
    threshold = SEVERITY.get(fail_on, SEVERITY["high"])
    blocking = [
        f
        for f in considered
        if threshold and SEVERITY.get(f.severity, 0) >= threshold
    ]
    return {
        "failOn": fail_on,
        "baselineApplied": baseline is not None,
        "baselineFindings": len(baseline) if baseline is not None else 0,
        "total": len(all_findings),
        "considered": len(considered),
        "new": len(considered),
        "blocking": len(blocking),
        "blockingIds": [f.id for f in blocking],
        "failed": bool(blocking),
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "verdict": f.verdict,
                "entry": f.entry.get("class", ""),
                "key": finding_key(f),
            }
            for f in blocking
        ],
    }


def write_gate(path: str | Path, decision: dict[str, Any]) -> None:
    Path(path).write_text(
        json.dumps(decision, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
