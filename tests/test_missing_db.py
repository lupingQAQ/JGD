"""Task 7: DB fallback must be explicit, never silently presented as full coverage."""
from pathlib import Path

from jgd.verification import known_chains


def test_missing_db_is_explicit(tmp_path: Path):
    result = known_chains.audit(tmp_path)
    assert result
    assert known_chains.db_status(tmp_path / "absent.db") == "missing"


def test_no_version_gate_is_unverified():
    assert known_chains.version_verdict(["foo.jar"], []).startswith("UNVERIFIED")
