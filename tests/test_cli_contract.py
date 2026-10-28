"""Task 6: CLI contract, JSON/SARIF, doctor, DB build."""
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from jgd.adapters.sarif import to_sarif


def _run(args, cwd: Path):
    return subprocess.run(
        [sys.executable, "-m", "jgd", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
    )


def _empty_jar(target: Path) -> None:
    target.mkdir()
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass


def test_audit_json_and_exit_code(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    out = tmp_path / "out"
    r = _run(
        [
            "audit",
            "--target",
            str(target),
            "--profile",
            "known",
            "--format",
            "json",
            "--out",
            str(out),
        ],
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert r.returncode in (0, 10, 20), r.stderr
    data = json.loads((out / "run.json").read_text(encoding="utf-8"))
    assert data["schemaVersion"] == "jgd.run/v1"
    assert isinstance(data["findings"], list)


def test_audit_is_deterministic(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    project = Path(__file__).resolve().parent.parent
    outs = []
    fingerprints = []
    for name in ("a", "b"):
        out = tmp_path / name
        r = _run(
            [
                "audit",
                "--target",
                str(target),
                "--profile",
                "known",
                "--format",
                "json",
                "--out",
                str(out),
            ],
            cwd=project,
        )
        assert r.returncode in (0, 10, 20), r.stderr
        data = json.loads((out / "run.json").read_text(encoding="utf-8"))
        outs.append(sorted(json.dumps(f, sort_keys=True) for f in data["findings"]))
        fingerprints.append(data["target"]["fingerprint"])
    assert outs[0] == outs[1]
    assert fingerprints[0] == fingerprints[1]


def test_bad_target_returns_30(tmp_path: Path):
    r = _run(["audit", "--target", str(tmp_path / "nope")], cwd=Path(__file__).resolve().parent.parent)
    assert r.returncode == 30


def test_doctor_reports_paths():
    r = _run(["doctor"], cwd=Path(__file__).resolve().parent.parent)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert "python" in data and "sqlite" in data and "home" in data


def test_doctor_includes_target_state(tmp_path: Path):
    r = _run(
        ["doctor", "--target", str(tmp_path / "missing")],
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["target_exists"] is False


def test_sarif_minimum_shape():
    from jgd.contracts.models import Finding

    f = Finding(
        id="JGD-1",
        category="java-deserialization",
        verdict="CHAIN_CONFIRMED",
        severity="high",
        confidence=0.9,
        entry={"class": "A"},
        bridge={},
        sink={},
        evidence=[],
        remediation={},
    )
    sarif = to_sarif([f], "0.2.0")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "jgd/java-deserialization/A"


def test_db_build_creates_database(tmp_path: Path):
    db = tmp_path / "known_chains.db"
    r = _run(["db", "build", "--out", str(db)], cwd=Path(__file__).resolve().parent.parent)
    assert r.returncode == 0, r.stderr
    assert db.exists() and db.stat().st_size > 0
