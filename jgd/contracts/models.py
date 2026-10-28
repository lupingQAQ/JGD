"""Stable JSON-facing contracts for JGD runs and findings."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from jgd.config import Budget, Policy


@dataclass(frozen=True)
class RunGoal:
    target: Path
    profile: str
    policy: Policy = field(default_factory=Policy)
    budget: Budget = field(default_factory=Budget)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": str(self.target),
            "profile": self.profile,
            "policy": asdict(self.policy),
            "budget": asdict(self.budget),
        }


@dataclass
class Finding:
    id: str
    category: str
    verdict: str
    severity: str
    confidence: float
    entry: dict[str, Any] = field(default_factory=dict)
    bridge: dict[str, Any] = field(default_factory=dict)
    sink: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    remediation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunResult:
    schema_version: str
    run_id: str
    tool: dict[str, Any]
    target: dict[str, Any]
    status: str
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "runId": self.run_id,
            "tool": self.tool,
            "target": self.target,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "coverage": self.coverage,
            "errors": self.errors,
        }
