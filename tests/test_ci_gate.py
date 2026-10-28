"""CI gate baseline behavior and deterministic policy exit decisions."""
import json
from pathlib import Path

from jgd import ci
from jgd.contracts.models import Finding


def _finding(
    fid: str,
    *,
    category: str = "java-deserialization",
    verdict: str = "CHAIN_CONFIRMED",
    severity: str = "high",
    entry: str = "demo/Bridge",
    bridge: str = "demo/Tail",
) -> Finding:
    return Finding(
        id=fid,
        category=category,
        verdict=verdict,
        severity=severity,
        confidence=0.9,
        entry={"class": entry},
        bridge={"class": bridge},
    )


def test_gate_blocks_new_high_findings():
    decision = ci.evaluate([_finding("JGD-P1")], fail_on="high")
    assert decision["failed"] is True
    assert decision["blocking"] == 1
    assert decision["blockingIds"] == ["JGD-P1"]


def test_baseline_excludes_legacy_finding():
    old = _finding("JGD-P1")
    decision = ci.evaluate([old], baseline={ci.finding_key(old)}, fail_on="high")
    assert decision["failed"] is False
    assert decision["total"] == 1
    assert decision["considered"] == 0
    assert decision["baselineApplied"] is True


def test_baseline_keeps_changed_finding_new():
    old = _finding("JGD-P1")
    changed = _finding("JGD-P2", verdict="PRESENT")
    decision = ci.evaluate(
        [changed], baseline={ci.finding_key(old)}, fail_on="high"
    )
    assert decision["failed"] is True
    assert decision["blockingIds"] == ["JGD-P2"]


def test_fail_on_none_never_blocks():
    decision = ci.evaluate([_finding("JGD-P1")], fail_on="none")
    assert decision["failed"] is False


def test_load_baseline_supports_run_and_findings_shapes(tmp_path: Path):
    f = _finding("JGD-P1")
    run = tmp_path / "run.json"
    run.write_text(json.dumps({"findings": [f.to_dict()]}), encoding="utf-8")
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([f.to_dict()]), encoding="utf-8")
    assert ci.load_baseline(run) == {ci.finding_key(f)}
    assert ci.load_baseline(findings) == {ci.finding_key(f)}


def test_write_gate_json(tmp_path: Path):
    path = tmp_path / "gate.json"
    decision = ci.evaluate([_finding("JGD-P1")], fail_on="high")
    ci.write_gate(path, decision)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["failed"] is True
    assert loaded["blockingIds"] == ["JGD-P1"]
