"""Task 1 contract tests: hardened defaults and run models."""
from pathlib import Path

import pytest

from jgd.config import Budget, JgdConfig, Policy


def test_defaults_match_spec(tmp_path: Path):
    p = Policy()
    assert p.sandbox == "docker"
    assert p.offline is False
    assert p.llm == "on"
    assert p.poc is True
    assert p.allow_cloud_llm is False
    assert p.fail_on == "high"
    assert Budget().jobs == 8
    cfg = JgdConfig(home=tmp_path / "home", target=tmp_path / "jars")
    assert cfg.profile == "standard"
    assert cfg.policy.poc is True


def test_profile_is_validated(tmp_path: Path):
    with pytest.raises(ValueError, match="profile"):
        JgdConfig(home=tmp_path, target=tmp_path, profile="bogus")


def test_finding_roundtrip():
    from jgd.contracts.models import Finding, RunResult

    f = Finding(
        id="JGD-1",
        category="java-deserialization",
        verdict="CHAIN_CONFIRMED",
        severity="high",
        confidence=0.9,
        entry={"class": "A"},
        bridge={"class": "B"},
        sink={"class": "C"},
        evidence=[],
        remediation={},
    )
    r = RunResult(
        schema_version="jgd.run/v1",
        run_id="01J",
        tool={"name": "jgd"},
        target={"root": "/tmp"},
        status="completed",
        findings=[f],
        coverage={"jars": 1},
        errors=[],
    )
    data = r.to_dict()
    assert data["findings"][0]["verdict"] == "CHAIN_CONFIRMED"
    assert data["schemaVersion"] == "jgd.run/v1"
